//! K-PKE: the IND-CPA-secure base scheme that ML-KEM wraps with the FO
//! transform. FIPS 203 Alg 12 (KeyGen), Alg 13 (Encrypt), Alg 14 (Decrypt).

use fixed_bigint::Personality;
use modmath::basic::pre_reduced as pr;
use zeroize::Zeroizing;

use crate::blinding;
use crate::encoding::EncodeError;
use crate::field_ext::FieldExt;
use crate::hashing::sha3_512;
use crate::mlkem::encoding::{
    byte_decode, byte_encode, byte_encode_vec, compress_poly, decompress_poly,
};
use crate::mlkem::ntt;
use crate::mlkem::params::{N, Params, Q, Q_N_PRIME, Q_R2_MOD_Q};
use crate::mlkem::sampling::{expand_a, sample_e1_row, sample_ntt, sample_re_y_e2, sample_se};
use crate::poly::Poly;
use crate::polyvec::PolyVec;

/// FIPS 203 encodes NTT-domain polynomials (t_hat, s_hat) in their
/// canonical form on the wire, but we store NTT-domain coefficients in
/// Montgomery form (for fast `mul_mont`). Strip Mont at every
/// byte-encode boundary and re-apply via `FieldExt::reduce` after every
/// byte-decode.
fn polyvec_from_mont<const LEN: usize, P: Personality + FieldExt<P>>(
    v: &PolyVec<u32, LEN>,
) -> PolyVec<u32, LEN> {
    let mut out = PolyVec::<u32, LEN>::zero();
    for i in 0..LEN {
        for j in 0..N {
            out.v[i].coeffs[j] = <P as FieldExt<P>>::into_raw(v.v[i].coeffs[j], Q, Q_N_PRIME);
        }
    }
    out
}

/// K-PKE.KeyGen (Alg 12), generic over personality `P`.
pub fn keygen_impl<const K: usize, P>(
    params: &Params<K>,
    d: &[u8; 32],
    ek_out: &mut [u8],
    dk_out: &mut [u8],
) -> Result<(), EncodeError>
where
    P: Personality + FieldExt<P>,
{
    // sigma seeds CBD sampling and t_hat carries Mont-form secret-mixed
    // values during construction — all wrapped in Zeroizing.
    let g: Zeroizing<[u8; 64]> = Zeroizing::new(sha3_512(&[d, &[K as u8]]));
    let mut rho = [0u8; 32];
    let mut sigma = Zeroizing::new([0u8; 32]);
    let rho_src = g.get(..32).ok_or(EncodeError::BufferTooSmall)?;
    let sigma_src = g.get(32..).ok_or(EncodeError::BufferTooSmall)?;
    rho.copy_from_slice(rho_src);
    sigma.copy_from_slice(sigma_src);

    let a_hat = expand_a::<K>(&rho);
    // Wrap sample_se's secret output directly into Zeroizing so the
    // raw tuple never lives un-zeroized on the stack across the NTT
    // loop. NTT then mutates the secret in place through the wrap.
    let (s_raw, e_raw) = sample_se::<K>(&sigma, params.eta1)?;
    let mut s_hat: Zeroizing<PolyVec<u32, K>> = Zeroizing::new(s_raw);
    let mut e_hat: Zeroizing<PolyVec<u32, K>> = Zeroizing::new(e_raw);
    for i in 0..K {
        ntt::ntt::<P>(&mut s_hat.v[i]);
        ntt::ntt::<P>(&mut e_hat.v[i]);
    }

    // t_hat[i] = sum_j a_hat[i][j] * s_hat[j]  +  e_hat[i]
    let mut t_hat_raw = PolyVec::<u32, K>::zero();
    for i in 0..K {
        ntt::mul_ntt_acc::<K, P>(&mut t_hat_raw.v[i], &a_hat.rows[i].v, &s_hat.v);
        for k in 0..N {
            t_hat_raw.v[i].coeffs[k] =
                pr::add::<u32>(t_hat_raw.v[i].coeffs[k], e_hat.v[i].coeffs[k], Q);
        }
    }
    let t_hat: Zeroizing<PolyVec<u32, K>> = Zeroizing::new(t_hat_raw);

    let t_hat_canon: Zeroizing<PolyVec<u32, K>> = Zeroizing::new(polyvec_from_mont::<_, P>(&t_hat));
    let t_hat_slot = ek_out
        .get_mut(..384 * K)
        .ok_or(EncodeError::BufferTooSmall)?;
    byte_encode_vec(&t_hat_canon, 12, t_hat_slot)?;
    let rho_slot = ek_out
        .get_mut(384 * K..)
        .ok_or(EncodeError::BufferTooSmall)?;
    if rho_slot.len() != 32 {
        return Err(EncodeError::BufferTooSmall);
    }
    rho_slot.copy_from_slice(&rho);

    let s_hat_canon: Zeroizing<PolyVec<u32, K>> = Zeroizing::new(polyvec_from_mont::<_, P>(&s_hat));
    byte_encode_vec(&s_hat_canon, 12, dk_out)?;
    Ok(())
}

/// K-PKE.Encrypt (Alg 13), generic over personality `P`.
pub fn encrypt_impl<const K: usize, P>(
    params: &Params<K>,
    ek: &[u8],
    m: &[u8; 32],
    r: &[u8; 32],
    ct_out: &mut [u8],
) -> Result<(), EncodeError>
where
    P: Personality + FieldExt<P>,
{
    let mut rho = [0u8; 32];
    let rho_src = ek.get(384 * K..).ok_or(EncodeError::BufferTooSmall)?;
    if rho_src.len() != 32 {
        return Err(EncodeError::BufferTooSmall);
    }
    rho.copy_from_slice(rho_src);

    // y and e2 sampled up front; e1 is sampled on demand per u_row to avoid
    // holding K polys of e1 on the stack alongside y and a_row.
    let (y_raw, e2_raw) = sample_re_y_e2::<K>(r, params.eta1, params.eta2)?;
    let mut y: Zeroizing<PolyVec<u32, K>> = Zeroizing::new(y_raw);
    let e2: Zeroizing<Poly<u32>> = Zeroizing::new(e2_raw);
    for i in 0..K {
        ntt::ntt::<P>(&mut y.v[i]);
    }
    // y now holds y_hat.

    // Stream t_hat one column at a time to avoid materializing the full
    // K-poly PolyVec on the stack. Each t_hat[j] is decoded and immediately
    // multiplied into v_ntt, then discarded.
    let mut v_ntt: Zeroizing<Poly<u32>> = Zeroizing::new(Poly::zero());
    for j in 0..K {
        let chunk = ek
            .get(j * 384..(j + 1) * 384)
            .ok_or(EncodeError::BufferTooSmall)?;
        let mut t_hat_j: Zeroizing<Poly<u32>> = Zeroizing::new(byte_decode(chunk, 12)?);
        for k in 0..N {
            t_hat_j.coeffs[k] =
                <P as FieldExt<P>>::reduce(t_hat_j.coeffs[k], Q, Q_N_PRIME, Q_R2_MOD_Q);
        }
        let prod: Zeroizing<Poly<u32>> = Zeroizing::new(ntt::mul_ntt::<P>(&t_hat_j, &y.v[j]));
        for k in 0..N {
            v_ntt.coeffs[k] = pr::add::<u32>(v_ntt.coeffs[k], prod.coeffs[k], Q);
        }
    }
    // inv_NTT v_ntt in place — variable transitions from NTT-domain
    // accumulator to time-domain v without a copy.
    ntt::inv_ntt::<P>(&mut v_ntt);
    let mu: Zeroizing<Poly<u32>> = Zeroizing::new(decompress_poly(&byte_decode(m, 1)?, 1));
    for k in 0..N {
        v_ntt.coeffs[k] = pr::add::<u32>(
            pr::add::<u32>(v_ntt.coeffs[k], e2.coeffs[k], Q),
            mu.coeffs[k],
            Q,
        );
    }
    let v_buf = v_ntt; // v_ntt now holds the time-domain v.

    // u rows streamed straight into ct_out:
    //   u_row[i] = invNTT(sum_j A_hat[j][i] * y_hat[j]) + e1[i]
    let c1_len = 32 * params.du * K;
    let c2_len = 32 * params.dv;
    let u_chunk = 32 * params.du;
    for i in 0..K {
        let mut a_row: PolyVec<u32, K> = PolyVec::zero();
        for j in 0..K {
            a_row.v[j] = sample_ntt(&rho, i as u8, j as u8);
        }
        let mut u_row: Zeroizing<Poly<u32>> = Zeroizing::new(Poly::zero());
        ntt::mul_ntt_acc::<K, P>(&mut u_row, &a_row.v, &y.v);
        ntt::inv_ntt::<P>(&mut u_row);
        let e1_i: Zeroizing<Poly<u32>> = Zeroizing::new(sample_e1_row::<K>(r, i, params.eta2)?);
        for k in 0..N {
            u_row.coeffs[k] = pr::add::<u32>(u_row.coeffs[k], e1_i.coeffs[k], Q);
        }
        let u_row_compressed = compress_poly(&u_row, params.du);
        let slot = ct_out
            .get_mut(i * u_chunk..(i + 1) * u_chunk)
            .ok_or(EncodeError::BufferTooSmall)?;
        byte_encode(&u_row_compressed, params.du, slot)?;
    }

    let v_compressed = compress_poly(&v_buf, params.dv);
    let v_slot = ct_out
        .get_mut(c1_len..c1_len + c2_len)
        .ok_or(EncodeError::BufferTooSmall)?;
    byte_encode(&v_compressed, params.dv, v_slot)?;
    Ok(())
}

/// FO re-encrypt + constant-time compare, without materializing the full ciphertext.
///
/// Identical computation to [`encrypt_impl`] for the `u` rows and `v` poly,
/// but instead of writing to a `ct_out` buffer each row is encoded into a
/// 352-byte scratch buffer, XOR'd against the corresponding slice of `ct_ref`,
/// and discarded. The accumulated `diff` byte is converted to a CT-equality
/// mask (0xFF = equal, 0x00 = different) and returned. This avoids the
/// 768–2048-byte `ct_prime` buffer that the calller would otherwise need.
pub(crate) fn encrypt_compare_impl<const K: usize, P>(
    params: &Params<K>,
    ek: &[u8],
    m: &[u8; 32],
    r: &[u8; 32],
    ct_ref: &[u8],
) -> Result<u8, EncodeError>
where
    P: Personality + FieldExt<P>,
{
    let mut rho = [0u8; 32];
    let rho_src = ek.get(384 * K..).ok_or(EncodeError::BufferTooSmall)?;
    if rho_src.len() != 32 {
        return Err(EncodeError::BufferTooSmall);
    }
    rho.copy_from_slice(rho_src);

    let (y_raw, e2_raw) = sample_re_y_e2::<K>(r, params.eta1, params.eta2)?;
    let mut y: Zeroizing<PolyVec<u32, K>> = Zeroizing::new(y_raw);
    let e2: Zeroizing<Poly<u32>> = Zeroizing::new(e2_raw);
    for i in 0..K {
        ntt::ntt::<P>(&mut y.v[i]);
    }

    let mut v_ntt: Zeroizing<Poly<u32>> = Zeroizing::new(Poly::zero());
    for j in 0..K {
        let chunk = ek
            .get(j * 384..(j + 1) * 384)
            .ok_or(EncodeError::BufferTooSmall)?;
        let mut t_hat_j: Zeroizing<Poly<u32>> = Zeroizing::new(byte_decode(chunk, 12)?);
        for k in 0..N {
            t_hat_j.coeffs[k] =
                <P as FieldExt<P>>::reduce(t_hat_j.coeffs[k], Q, Q_N_PRIME, Q_R2_MOD_Q);
        }
        let prod: Zeroizing<Poly<u32>> = Zeroizing::new(ntt::mul_ntt::<P>(&t_hat_j, &y.v[j]));
        for k in 0..N {
            v_ntt.coeffs[k] = pr::add::<u32>(v_ntt.coeffs[k], prod.coeffs[k], Q);
        }
    }
    ntt::inv_ntt::<P>(&mut v_ntt);
    let mu: Zeroizing<Poly<u32>> = Zeroizing::new(decompress_poly(&byte_decode(m, 1)?, 1));
    for k in 0..N {
        v_ntt.coeffs[k] = pr::add::<u32>(
            pr::add::<u32>(v_ntt.coeffs[k], e2.coeffs[k], Q),
            mu.coeffs[k],
            Q,
        );
    }
    let v_buf = v_ntt;

    let c1_len = 32 * params.du * K;
    let c2_len = 32 * params.dv;
    let u_chunk = 32 * params.du;

    let mut diff = 0u8;
    for i in 0..K {
        let mut a_row: PolyVec<u32, K> = PolyVec::zero();
        for j in 0..K {
            a_row.v[j] = sample_ntt(&rho, i as u8, j as u8);
        }
        let mut u_row: Zeroizing<Poly<u32>> = Zeroizing::new(Poly::zero());
        ntt::mul_ntt_acc::<K, P>(&mut u_row, &a_row.v, &y.v);
        ntt::inv_ntt::<P>(&mut u_row);
        let e1_i: Zeroizing<Poly<u32>> = Zeroizing::new(sample_e1_row::<K>(r, i, params.eta2)?);
        for k in 0..N {
            u_row.coeffs[k] = pr::add::<u32>(u_row.coeffs[k], e1_i.coeffs[k], Q);
        }
        let u_row_compressed = compress_poly(&u_row, params.du);
        // max du = 11 → 32*11 = 352 bytes; sized for worst-case ML-KEM-1024.
        let mut u_tmp = [0u8; 32 * 11];
        let u_tmp_used = u_tmp
            .get_mut(..u_chunk)
            .ok_or(EncodeError::BufferTooSmall)?;
        byte_encode(&u_row_compressed, params.du, u_tmp_used)?;
        let ct_u = ct_ref
            .get(i * u_chunk..(i + 1) * u_chunk)
            .ok_or(EncodeError::BufferTooSmall)?;
        for (a, b) in u_tmp_used.iter().zip(ct_u.iter()) {
            diff |= a ^ b;
        }
    }

    let v_compressed = compress_poly(&v_buf, params.dv);
    // max dv = 5 → 32*5 = 160 bytes; sized for worst-case ML-KEM-1024.
    let mut v_tmp = [0u8; 32 * 5];
    let v_tmp_used = v_tmp.get_mut(..c2_len).ok_or(EncodeError::BufferTooSmall)?;
    byte_encode(&v_compressed, params.dv, v_tmp_used)?;
    let ct_v = ct_ref
        .get(c1_len..c1_len + c2_len)
        .ok_or(EncodeError::BufferTooSmall)?;
    for (a, b) in v_tmp_used.iter().zip(ct_v.iter()) {
        diff |= a ^ b;
    }

    // CT-equality mask: 0xFF if all bytes matched, 0x00 otherwise.
    let nonzero = (diff as u32).wrapping_sub(1) >> 31;
    Ok((nonzero as u8).wrapping_neg())
}

/// K-PKE.Decrypt (Alg 14), generic over personality `P`.
pub fn decrypt_impl<const K: usize, P>(
    params: &Params<K>,
    dk: &[u8],
    ct: &[u8],
    m_out: &mut [u8; 32],
) -> Result<(), EncodeError>
where
    P: Personality + FieldExt<P>,
{
    let c1_len = 32 * params.du * K;
    let u_chunk = 32 * params.du;

    // DPA scalar blinding: scale s_row by r_mont before the dot product,
    // unblind the accumulator by r_inv_mont before inv_ntt. The
    // multiplier hardware never sees raw s.
    let (r_mont, r_inv_mont) = blinding::derive_pair::<P>(
        &[dk, ct, b"krabipqc/decaps-blind"],
        Q,
        Q_N_PRIME,
        Q_R2_MOD_Q,
    );

    let mut w_ntt: Zeroizing<Poly<u32>> = Zeroizing::new(Poly::zero());
    for i in 0..K {
        let u_chunk_slice = ct
            .get(i * u_chunk..(i + 1) * u_chunk)
            .ok_or(EncodeError::BufferTooSmall)?;
        let mut u_row = decompress_poly(&byte_decode(u_chunk_slice, params.du)?, params.du);
        ntt::ntt::<P>(&mut u_row);

        let s_chunk = dk
            .get(i * 384..(i + 1) * 384)
            .ok_or(EncodeError::BufferTooSmall)?;
        let s_row_canon: Zeroizing<Poly<u32>> = Zeroizing::new(byte_decode(s_chunk, 12)?);
        let mut s_row: Zeroizing<Poly<u32>> = Zeroizing::new(Poly::zero());
        for k in 0..N {
            s_row.coeffs[k] =
                <P as FieldExt<P>>::reduce(s_row_canon.coeffs[k], Q, Q_N_PRIME, Q_R2_MOD_Q);
        }
        blinding::scale_mont::<P>(&mut s_row, r_mont, Q, Q_N_PRIME);

        let prod: Zeroizing<Poly<u32>> = Zeroizing::new(ntt::mul_ntt::<P>(&s_row, &u_row));
        for k in 0..N {
            w_ntt.coeffs[k] = pr::add::<u32>(w_ntt.coeffs[k], prod.coeffs[k], Q);
        }
    }

    // Cancel the blinding factor before inv_ntt.
    blinding::scale_mont::<P>(&mut w_ntt, r_inv_mont, Q, Q_N_PRIME);

    // w := v_prime - invNTT(w_ntt), reusing w_ntt in place.
    ntt::inv_ntt::<P>(&mut w_ntt);
    let v_slice = ct.get(c1_len..).ok_or(EncodeError::BufferTooSmall)?;
    let v_prime = decompress_poly(&byte_decode(v_slice, params.dv)?, params.dv);
    for j in 0..N {
        w_ntt.coeffs[j] = pr::sub::<u32>(v_prime.coeffs[j], w_ntt.coeffs[j], Q);
    }

    let w_compressed = compress_poly(&w_ntt, 1);
    byte_encode(&w_compressed, 1, m_out)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mlkem::params::ML_KEM_768;
    use fixed_bigint::Nct;

    #[test]
    fn pke_roundtrip_768() {
        let d = [0x42u8; 32];
        let mut ek = vec![0u8; ML_KEM_768.ek_bytes];
        let mut dk = vec![0u8; 384 * 3];
        keygen_impl::<3, Nct>(&ML_KEM_768, &d, &mut ek, &mut dk).unwrap();

        let m = [0xC3u8; 32];
        let r = [0x77u8; 32];
        let mut ct = vec![0u8; ML_KEM_768.ct_bytes];
        encrypt_impl::<3, Nct>(&ML_KEM_768, &ek, &m, &r, &mut ct).unwrap();

        let mut m_back = [0u8; 32];
        decrypt_impl::<3, Nct>(&ML_KEM_768, &dk, &ct, &mut m_back).unwrap();
        assert_eq!(m_back, m, "K-PKE roundtrip should recover the message");
    }
}
