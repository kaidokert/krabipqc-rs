//! KeyGen_internal / Sign_internal / Verify_internal (FIPS 204 Algs
//! 6, 7, 8), generic over the parameter set `(K, L)` and the
//! personality `P` (`Nct` / `Ct`). The `*_impl` variants carry the
//! generic bodies; the `*_internal` shims pin `P = Nct`.
//!
//! Per-set facades live in [`crate::ml_dsa_44`], [`crate::ml_dsa_65`],
//! [`crate::ml_dsa_87`].

use fixed_bigint::{Nct, Personality};
use zeroize::Zeroizing;

use modmath::basic::pre_reduced as pr;

use crate::blinding;
use crate::encoding;
use crate::field_ext::FieldExt;
use crate::hashing::shake256;
use crate::ntt;
use crate::params::{
    D, MAX_CTILDE_BYTES, MAX_W1_PACKED_BYTES, N, Params, Q, Q_N_PRIME, Q_R2_MOD_Q,
    SEED_EXPAND_BYTES, abs_centered,
};
use crate::poly::Poly;
use crate::polyvec::PolyVec;
use crate::rounding::{high_bits, low_bits, make_hint, power2round_vec};
use crate::sampling::{expand_a, expand_mask, expand_s, rej_ntt_poly, sample_in_ball};

/// KeyGen_internal (FIPS 204 Alg 6), generic over personality `P`.
///
/// `xi` is the secret 32-byte seed. `pk_out` is filled with the
/// canonical pk byte string; `sk_out` with the canonical sk byte
/// string. Lengths must equal `params.pk_bytes` / `params.sk_bytes`.
pub fn keygen_internal_impl<const K: usize, const L: usize, P>(
    params: &Params<K, L>,
    xi: &[u8; 32],
    pk_out: &mut [u8],
    sk_out: &mut [u8],
) where
    P: Personality + FieldExt<P>,
{
    assert_eq!(pk_out.len(), params.pk_bytes, "pk_out length");
    assert_eq!(sk_out.len(), params.sk_bytes, "sk_out length");

    // Everything derived from `xi` is zeroize-on-drop; `rho` is public
    // (it lands in pk).
    let mut seed_out = Zeroizing::new([0u8; SEED_EXPAND_BYTES]);
    shake256(&[xi, &[K as u8], &[L as u8]], &mut *seed_out);
    let mut rho = [0u8; 32];
    let mut rho_prime = Zeroizing::new([0u8; 64]);
    let mut big_k = Zeroizing::new([0u8; 32]);
    rho.copy_from_slice(&seed_out[..32]);
    rho_prime.copy_from_slice(&seed_out[32..96]);
    big_k.copy_from_slice(&seed_out[96..128]);

    let (s1, s2) = expand_s::<K, L>(&rho_prime, params.eta);
    let s1: Zeroizing<PolyVec<u32, L>> = Zeroizing::new(s1);
    let s2: Zeroizing<PolyVec<u32, K>> = Zeroizing::new(s2);

    let mut s1_hat: Zeroizing<PolyVec<u32, L>> = Zeroizing::new(*s1);
    for i in 0..L {
        ntt::ntt::<P>(&mut s1_hat.v[i]);
    }

    // Stream A_hat cells on the fly via rej_ntt_poly; materializing
    // the full K×L matrix would burn up to ~56 KiB stack on ML-DSA-87
    // and keygen visits each cell exactly once anyway.
    let mut t: Zeroizing<PolyVec<u32, K>> = Zeroizing::new(PolyVec::zero());
    for i in 0..K {
        let mut acc = Poly::<u32>::zero();
        for j in 0..L {
            let a_ij = rej_ntt_poly(&rho, j as u8, i as u8);
            let p = ntt::mul_ntt::<P>(&a_ij, &s1_hat.v[j]);
            for n in 0..N {
                acc.coeffs[n] = pr::add::<u32>(acc.coeffs[n], p.coeffs[n], Q);
            }
        }
        ntt::inv_ntt::<P>(&mut acc);
        for n in 0..N {
            acc.coeffs[n] = pr::add::<u32>(acc.coeffs[n], s2.v[i].coeffs[n], Q);
        }
        t.v[i] = acc;
    }
    let (t1, t0) = power2round_vec(&t);
    let t0: Zeroizing<PolyVec<u32, K>> = Zeroizing::new(t0);

    // Buffer sizes are enforced by the caller — facades pass
    // `[u8; PK_BYTES]` / `[u8; SK_BYTES]` arrays sized from `params`.
    encoding::pk_encode(&rho, &t1, pk_out).expect("pk_out sized by caller");
    let mut tr = [0u8; 64];
    shake256(&[pk_out], &mut tr);
    encoding::sk_encode(params, &rho, &big_k, &tr, &s1, &s2, &t0, sk_out)
        .expect("sk_out sized by caller");
}

/// KeyGen_internal (Alg 6), Nct-default shim.
pub fn keygen_internal<const K: usize, const L: usize>(
    params: &Params<K, L>,
    xi: &[u8; 32],
    pk_out: &mut [u8],
    sk_out: &mut [u8],
) {
    keygen_internal_impl::<K, L, Nct>(params, xi, pk_out, sk_out);
}

/// Sign_internal (FIPS 204 Alg 7), generic over personality `P`.
///
/// Single-slice `m_prime` shim around [`sign_internal_impl_pieces`].
/// External callers building `M'` from `(message, ctx)` should use
/// the `sign` / `hash_sign` wrappers on the per-set facade.
pub fn sign_internal_impl<const K: usize, const L: usize, P>(
    params: &Params<K, L>,
    sk: &[u8],
    m_prime: &[u8],
    rnd: &[u8; 32],
    sig_out: &mut [u8],
) where
    P: Personality + FieldExt<P>,
{
    sign_internal_impl_pieces::<K, L, P>(params, sk, &[m_prime], rnd, sig_out);
}

/// Same as [`sign_internal_impl`] but absorbs `M'` from a slice of
/// byte slices, so callers (per-set `sign` / `hash_sign`, TLS
/// transcripts) don't have to materialize a contiguous `M'` on stack.
/// `m_prime_pieces.len()` is capped at 6 because the absorb buffer is
/// a fixed-size array (no_std, no resize); overflow leaves `sig_out`
/// untouched.
pub fn sign_internal_impl_pieces<const K: usize, const L: usize, P>(
    params: &Params<K, L>,
    sk: &[u8],
    m_prime_pieces: &[&[u8]],
    rnd: &[u8; 32],
    sig_out: &mut [u8],
) where
    P: Personality + FieldExt<P>,
{
    const MAX_M_PRIME_PIECES: usize = 6;
    assert_eq!(sk.len(), params.sk_bytes, "sk length");
    assert_eq!(sig_out.len(), params.sig_bytes, "sig_out length");
    assert!(
        m_prime_pieces.len() <= MAX_M_PRIME_PIECES,
        "m_prime_pieces.len() {} exceeds cap {}",
        m_prime_pieces.len(),
        MAX_M_PRIME_PIECES,
    );

    // NTT s1/s2/t0 up front so subsequent c·s_hat / c·t0_hat products
    // across the kappa loop stay in Mont domain. Everything
    // secret-derived is zeroize-on-drop; `rho` is public.
    let (rho, big_k, tr, mut s1_hat, mut s2_hat, mut t0_hat) = {
        let (rho, big_k, tr, mut s1, mut s2, mut t0) =
            encoding::sk_decode(params, sk).expect("malformed sk");
        for i in 0..L {
            ntt::ntt::<P>(&mut s1.v[i]);
        }
        for i in 0..K {
            ntt::ntt::<P>(&mut s2.v[i]);
            ntt::ntt::<P>(&mut t0.v[i]);
        }
        (
            rho,
            Zeroizing::new(big_k),
            Zeroizing::new(tr),
            Zeroizing::new(s1),
            Zeroizing::new(s2),
            Zeroizing::new(t0),
        )
    };

    let a_hat = expand_a::<K, L>(&rho);

    // Multiplicative DPA blinding: blind s_hat / t0_hat by r_mont
    // once up front and c_hat by r_inv_mont inside each kappa retry.
    // `(c · r_inv) · (s · r) ≡ c · s`, so the signature is unchanged;
    // the multiplier sees `s · r` instead of `s`. `r` never leaves
    // the function.
    let (r_mont, r_inv_mont) =
        blinding::derive_pair::<P>(rnd, b"krabipqc/sign-blind", Q, Q_N_PRIME, Q_R2_MOD_Q);
    blinding::scale_polyvec_mont::<P, L>(&mut s1_hat, r_mont, Q, Q_N_PRIME);
    blinding::scale_polyvec_mont::<P, K>(&mut s2_hat, r_mont, Q, Q_N_PRIME);
    blinding::scale_polyvec_mont::<P, K>(&mut t0_hat, r_mont, Q, Q_N_PRIME);

    let mut mu = Zeroizing::new([0u8; 64]);
    let mut absorb: [&[u8]; MAX_M_PRIME_PIECES + 1] = [&[]; MAX_M_PRIME_PIECES + 1];
    absorb[0] = &*tr;
    for (i, p) in m_prime_pieces.iter().enumerate() {
        absorb[i + 1] = p;
    }
    shake256(&absorb[..1 + m_prime_pieces.len()], &mut *mu);

    let mut rho_pp = Zeroizing::new([0u8; 64]);
    shake256(&[&*big_k, rnd, &*mu], &mut *rho_pp);

    let mut kappa: u16 = 0;
    let mut w1_buf = [0u8; MAX_W1_PACKED_BYTES];
    let w1_len = K * 32 * params.w1_bits;
    let w1_packed = &mut w1_buf[..w1_len];

    let mut c_tilde_buf = [0u8; MAX_CTILDE_BYTES];
    let c_tilde = &mut c_tilde_buf[..params.ctilde_bytes];

    // sig_out layout:
    //   [0 .. ctilde_bytes)                       c_tilde (written on accept)
    //   [ctilde_bytes .. + L*z_chunk)              z, row by row
    //   [ctilde_bytes + L*z_chunk .. + omega + K)  hint
    let sig_z_off = params.ctilde_bytes;
    let z_pack_bits = 1 + params.gamma1_bits;
    let z_chunk = 32 * z_pack_bits;
    let z_pack_b = params.gamma1;
    let sig_hint_off = sig_z_off + L * z_chunk;
    let w1_chunk = 32 * params.w1_bits;

    // Reuse scratch across kappa retries so peak stack stays flat.
    let mut y: Zeroizing<PolyVec<u32, L>> = Zeroizing::new(PolyVec::zero());
    let mut tmp_l: Zeroizing<PolyVec<u32, L>> = Zeroizing::new(PolyVec::zero());
    let mut w_buf: Zeroizing<PolyVec<u32, K>> = Zeroizing::new(PolyVec::zero());

    loop {
        *y = expand_mask::<L>(&rho_pp, kappa, params.gamma1, params.gamma1_bits);

        *tmp_l = *y;
        for i in 0..L {
            ntt::ntt::<P>(&mut tmp_l.v[i]);
        }

        for i in 0..K {
            let mut acc = Poly::<u32>::zero();
            for j in 0..L {
                let p = ntt::mul_ntt::<P>(&a_hat.rows[i].v[j], &tmp_l.v[j]);
                acc = acc.add(&p, Q);
            }
            w_buf.v[i] = acc;
        }
        for i in 0..K {
            ntt::inv_ntt::<P>(&mut w_buf.v[i]);
        }

        // Pack w1 rows straight into the challenge-hash input so the
        // loop never materializes a PolyVec<K> worth of scratch.
        let mut w1_row = Poly::<u32>::zero();
        for i in 0..K {
            for j in 0..N {
                w1_row.coeffs[j] = high_bits(w_buf.v[i].coeffs[j], params.gamma2);
            }
            encoding::simple_bit_pack(
                &w1_row,
                params.w1_bits,
                &mut w1_packed[i * w1_chunk..(i + 1) * w1_chunk],
            );
        }
        shake256(&[&*mu, w1_packed], c_tilde);

        // c_tilde is public but c_hat carries secret-mixed Mont-form
        // bytes through s_hat products, so it zeroizes on exit.
        let mut c_hat: Zeroizing<Poly<u32>> = Zeroizing::new(sample_in_ball(c_tilde, params.tau));
        ntt::ntt::<P>(&mut c_hat);
        blinding::scale_mont::<P>(&mut c_hat, r_inv_mont, Q, Q_N_PRIME);

        let mut z_norm = 0u32;
        for i in 0..L {
            let mut row: Zeroizing<Poly<u32>> =
                Zeroizing::new(ntt::mul_ntt::<P>(&s1_hat.v[i], &c_hat));
            ntt::inv_ntt::<P>(&mut row);
            for j in 0..N {
                row.coeffs[j] = pr::add::<u32>(y.v[i].coeffs[j], row.coeffs[j], Q);
            }
            for &c in &row.coeffs {
                let a = abs_centered(c, Q);
                if a > z_norm {
                    z_norm = a;
                }
            }
            encoding::bit_pack(
                &row,
                z_pack_b,
                z_pack_bits,
                &mut sig_out[sig_z_off + i * z_chunk..sig_z_off + (i + 1) * z_chunk],
            );
        }

        for i in 0..K {
            let mut cs2_row: Zeroizing<Poly<u32>> =
                Zeroizing::new(ntt::mul_ntt::<P>(&s2_hat.v[i], &c_hat));
            ntt::inv_ntt::<P>(&mut cs2_row);
            for j in 0..N {
                w_buf.v[i].coeffs[j] = pr::sub::<u32>(w_buf.v[i].coeffs[j], cs2_row.coeffs[j], Q);
            }
        }

        let mut r0_norm = 0u32;
        for v in &w_buf.v {
            for &c in &v.coeffs {
                let a = abs_centered(low_bits(c, params.gamma2), Q);
                if a > r0_norm {
                    r0_norm = a;
                }
            }
        }
        if !(z_norm < params.gamma1 - params.beta && r0_norm < params.gamma2 - params.beta) {
            kappa = kappa.wrapping_add(L as u16);
            continue;
        }

        let hint_section = &mut sig_out[sig_hint_off..sig_hint_off + params.omega + K];
        hint_section.fill(0);
        let mut idx = 0usize;
        let mut weight: u32 = 0;
        let mut ct0_norm = 0u32;
        let mut hint_overflow = false;
        for i in 0..K {
            let mut ct0_row: Zeroizing<Poly<u32>> =
                Zeroizing::new(ntt::mul_ntt::<P>(&t0_hat.v[i], &c_hat));
            ntt::inv_ntt::<P>(&mut ct0_row);
            for j in 0..N {
                let ct0_ij = ct0_row.coeffs[j];
                let a = abs_centered(ct0_ij, Q);
                if a > ct0_norm {
                    ct0_norm = a;
                }
                let w_arg = pr::add::<u32>(w_buf.v[i].coeffs[j], ct0_ij, Q);
                let z_arg = pr::sub::<u32>(0, ct0_ij, Q);
                let b = make_hint(z_arg, w_arg, params.gamma2);
                if b == 1 {
                    if idx < params.omega {
                        hint_section[idx] = j as u8;
                    } else {
                        hint_overflow = true;
                    }
                    idx += 1;
                }
                weight += b as u32;
            }
            let count = core::cmp::min(idx, params.omega);
            hint_section[params.omega + i] = count as u8;
        }
        if !(ct0_norm < params.gamma2 && (weight as usize) <= params.omega && !hint_overflow) {
            kappa = kappa.wrapping_add(L as u16);
            continue;
        }

        sig_out[..params.ctilde_bytes].copy_from_slice(c_tilde);
        return;
    }
}

/// Sign_internal (Alg 7), Nct-default shim.
pub fn sign_internal<const K: usize, const L: usize>(
    params: &Params<K, L>,
    sk: &[u8],
    m_prime: &[u8],
    rnd: &[u8; 32],
    sig_out: &mut [u8],
) {
    sign_internal_impl::<K, L, Nct>(params, sk, m_prime, rnd, sig_out);
}

/// Single-slice `M'` shim around [`verify_internal_impl_pieces`].
pub fn verify_internal_impl<const K: usize, const L: usize, P>(
    params: &Params<K, L>,
    pk: &[u8],
    m_prime: &[u8],
    sig: &[u8],
) -> bool
where
    P: Personality + FieldExt<P>,
{
    verify_internal_impl_pieces::<K, L, P>(params, pk, &[m_prime], sig)
}

/// Same as [`verify_internal_impl`] but absorbs `M'` from a slice of
/// byte slices, so callers (per-set `verify`, TLS transcripts) don't
/// have to materialize a contiguous `M'` on stack.
pub fn verify_internal_impl_pieces<const K: usize, const L: usize, P>(
    params: &Params<K, L>,
    pk: &[u8],
    m_prime_pieces: &[&[u8]],
    sig: &[u8],
) -> bool
where
    P: Personality + FieldExt<P>,
{
    const MAX_M_PRIME_PIECES: usize = 6;
    if m_prime_pieces.len() > MAX_M_PRIME_PIECES
        || pk.len() != params.pk_bytes
        || sig.len() != params.sig_bytes
    {
        return false;
    }

    let mut rho = [0u8; 32];
    rho.copy_from_slice(&pk[..32]);

    let mut c_tilde_buf = [0u8; MAX_CTILDE_BYTES];
    let c_tilde = &mut c_tilde_buf[..params.ctilde_bytes];
    c_tilde.copy_from_slice(&sig[..params.ctilde_bytes]);

    // Validate once so the later `h_bit` / `h_weight` reads can skip
    // bounds checks.
    let hint = encoding::sig_hint_slice::<K, L>(params, sig);
    if !encoding::validate_hint_bytes::<K>(hint, params.omega) {
        return false;
    }

    // `z` is decoded whole because every result row references all L
    // rows in the matrix-vector product below; streaming would
    // multiply the per-row SHAKE cost by K.
    let mut z = PolyVec::<u32, L>::zero();
    for i in 0..L {
        z.v[i] = encoding::sig_z_row::<K, L>(params, sig, i);
    }
    let z_bound = params.gamma1 - params.beta;
    for poly in z.v.iter() {
        for c in poly.coeffs.iter() {
            if abs_centered(*c, Q) >= z_bound {
                return false;
            }
        }
    }

    if encoding::h_weight::<K>(hint, params.omega) as usize > params.omega {
        return false;
    }

    let mut tr = [0u8; 64];
    shake256(&[pk], &mut tr);
    let mut mu = [0u8; 64];
    let mut absorb: [&[u8]; MAX_M_PRIME_PIECES + 1] = [&[]; MAX_M_PRIME_PIECES + 1];
    absorb[0] = &tr;
    for (i, p) in m_prime_pieces.iter().enumerate() {
        absorb[i + 1] = p;
    }
    shake256(&absorb[..1 + m_prime_pieces.len()], &mut mu);

    let mut c_hat = sample_in_ball(c_tilde, params.tau);
    ntt::ntt::<P>(&mut c_hat);

    for i in 0..L {
        ntt::ntt::<P>(&mut z.v[i]);
    }

    let two_d = 1u32 << D;

    // Pack `w1` rows straight into the challenge-hash input so the
    // matrix-vector loop never materializes a `PolyVec<K>` worth
    // (~4 KiB) of scratch.
    let mut w1_buf = [0u8; MAX_W1_PACKED_BYTES];
    let w1_len = K * 32 * params.w1_bits;
    debug_assert!(w1_len <= MAX_W1_PACKED_BYTES);
    let w1_packed = &mut w1_buf[..w1_len];
    let w1_chunk = 32 * params.w1_bits;

    for i in 0..K {
        let mut row = Poly::<u32>::zero();
        for j in 0..L {
            let a_ij = rej_ntt_poly(&rho, j as u8, i as u8);
            let p = ntt::mul_ntt::<P>(&a_ij, &z.v[j]);
            row = row.add(&p, Q);
        }

        let mut t1_row = encoding::pk_t1_row(pk, i);
        for k in 0..N {
            t1_row.coeffs[k] = pr::mul::<u32>(t1_row.coeffs[k], two_d, Q);
        }
        ntt::ntt::<P>(&mut t1_row);
        let ct1 = ntt::mul_ntt::<P>(&c_hat, &t1_row);
        for k in 0..N {
            row.coeffs[k] = pr::sub::<u32>(row.coeffs[k], ct1.coeffs[k], Q);
        }

        ntt::inv_ntt::<P>(&mut row);

        // Walk the row's hint positions once; positions are strictly
        // increasing per validate_hint_bytes, so a peeking pointer
        // tracks h(k) without rescanning the slice for each k.
        let mut hint_iter = encoding::h_row_positions::<K>(hint, params.omega, i).peekable();
        for k in 0..N {
            let h = match hint_iter.peek() {
                Some(&pos) if pos == k => {
                    hint_iter.next();
                    1
                }
                _ => 0,
            };
            row.coeffs[k] = crate::rounding::use_hint(h, row.coeffs[k], params.gamma2);
        }

        encoding::simple_bit_pack(
            &row,
            params.w1_bits,
            &mut w1_packed[i * w1_chunk..(i + 1) * w1_chunk],
        );
    }

    let mut c_tilde_prime_buf = [0u8; MAX_CTILDE_BYTES];
    let c_tilde_prime = &mut c_tilde_prime_buf[..params.ctilde_bytes];
    shake256(&[&mu, w1_packed], c_tilde_prime);

    c_tilde == c_tilde_prime
}

/// Nct shim around [`verify_internal_impl`].
pub fn verify_internal<const K: usize, const L: usize>(
    params: &Params<K, L>,
    pk: &[u8],
    m_prime: &[u8],
    sig: &[u8],
) -> bool {
    verify_internal_impl::<K, L, Nct>(params, pk, m_prime, sig)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::{ML_DSA_44, ML_DSA_65, ML_DSA_87};
    use fixed_bigint::Ct;

    fn message_prime(ctx: &[u8], m: &[u8]) -> Vec<u8> {
        // FIPS 204 §5.2 M': 0x00 || |ctx| || ctx || M.
        assert!(ctx.len() <= 255);
        let mut out = Vec::with_capacity(2 + ctx.len() + m.len());
        out.push(0);
        out.push(ctx.len() as u8);
        out.extend_from_slice(ctx);
        out.extend_from_slice(m);
        out
    }

    fn roundtrip<const K: usize, const L: usize>(params: &Params<K, L>) {
        let xi = [0x42u8; 32];
        let mut pk = vec![0u8; params.pk_bytes];
        let mut sk = vec![0u8; params.sk_bytes];
        keygen_internal(params, &xi, &mut pk, &mut sk);
        let mp = message_prime(b"", b"hello mldsa");
        let mut sig = vec![0u8; params.sig_bytes];
        sign_internal(params, &sk, &mp, &[0xC3u8; 32], &mut sig);
        assert!(verify_internal(params, &pk, &mp, &sig));
        let mp_bad = message_prime(b"", b"different message");
        assert!(!verify_internal(params, &pk, &mp_bad, &sig));
    }

    #[test]
    fn roundtrip_44() {
        roundtrip(&ML_DSA_44);
    }
    #[test]
    fn roundtrip_65() {
        roundtrip(&ML_DSA_65);
    }
    #[test]
    fn roundtrip_87() {
        roundtrip(&ML_DSA_87);
    }

    #[test]
    fn wrong_pk_rejected_44() {
        let mut pk1 = vec![0u8; ML_DSA_44.pk_bytes];
        let mut sk1 = vec![0u8; ML_DSA_44.sk_bytes];
        let mut pk2 = vec![0u8; ML_DSA_44.pk_bytes];
        let mut sk2 = vec![0u8; ML_DSA_44.sk_bytes];
        keygen_internal(&ML_DSA_44, &[1u8; 32], &mut pk1, &mut sk1);
        keygen_internal(&ML_DSA_44, &[2u8; 32], &mut pk2, &mut sk2);
        let mp = message_prime(b"", b"msg");
        let mut sig = vec![0u8; ML_DSA_44.sig_bytes];
        sign_internal(&ML_DSA_44, &sk1, &mp, &[0u8; 32], &mut sig);
        assert!(verify_internal(&ML_DSA_44, &pk1, &mp, &sig));
        assert!(!verify_internal(&ML_DSA_44, &pk2, &mp, &sig));
    }

    /// Same inputs through `Nct` and `Ct` must produce byte-identical
    /// pk/sk/sig — load-bearing claim for the `*_ct` facades.
    fn cross_personality_equiv<const K: usize, const L: usize>(params: &Params<K, L>) {
        let xi = [0x77u8; 32];
        let mut pk_nct = vec![0u8; params.pk_bytes];
        let mut sk_nct = vec![0u8; params.sk_bytes];
        let mut pk_ct = vec![0u8; params.pk_bytes];
        let mut sk_ct = vec![0u8; params.sk_bytes];
        keygen_internal_impl::<K, L, Nct>(params, &xi, &mut pk_nct, &mut sk_nct);
        keygen_internal_impl::<K, L, Ct>(params, &xi, &mut pk_ct, &mut sk_ct);
        assert_eq!(pk_nct, pk_ct, "pk Nct/Ct mismatch");
        assert_eq!(sk_nct, sk_ct, "sk Nct/Ct mismatch");

        let mp = message_prime(b"ctx", b"x-personality msg");
        let rnd = [0x29u8; 32];
        let mut sig_nct = vec![0u8; params.sig_bytes];
        let mut sig_ct = vec![0u8; params.sig_bytes];
        sign_internal_impl::<K, L, Nct>(params, &sk_nct, &mp, &rnd, &mut sig_nct);
        sign_internal_impl::<K, L, Ct>(params, &sk_ct, &mp, &rnd, &mut sig_ct);
        assert_eq!(sig_nct, sig_ct, "signature Nct/Ct mismatch");

        assert!(verify_internal_impl::<K, L, Nct>(
            params, &pk_nct, &mp, &sig_nct
        ));
        assert!(verify_internal_impl::<K, L, Ct>(
            params, &pk_ct, &mp, &sig_ct
        ));
    }

    #[test]
    fn cross_personality_equiv_44() {
        cross_personality_equiv(&ML_DSA_44);
    }
    #[test]
    fn cross_personality_equiv_65() {
        cross_personality_equiv(&ML_DSA_65);
    }
    #[test]
    fn cross_personality_equiv_87() {
        cross_personality_equiv(&ML_DSA_87);
    }
}
