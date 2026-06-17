//! Verify_internal (FIPS 204 Alg 8), generic over the parameter set
//! `(K, L)` and the personality `P` (`Nct` / `Ct`). The `*_impl`
//! variants carry the generic bodies; the `*_internal` shims pin
//! `P = Nct`.
//!
//! Per-set facades live in [`crate::ml_dsa_44`], [`crate::ml_dsa_65`],
//! [`crate::ml_dsa_87`].

use fixed_bigint::{Nct, Personality};

use modmath::basic::pre_reduced as pr;

use crate::encoding;
use crate::field_ext::FieldExt;
use crate::hashing::shake256;
use crate::ntt;
use crate::params::{D, MAX_CTILDE_BYTES, MAX_W1_PACKED_BYTES, N, Params, Q, abs_centered};
use crate::poly::Poly;
use crate::polyvec::PolyVec;
use crate::sampling::{rej_ntt_poly, sample_in_ball};

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

        for k in 0..N {
            let h_bit = encoding::h_bit::<K>(hint, params.omega, i, k);
            row.coeffs[k] = crate::rounding::use_hint(h_bit, row.coeffs[k], params.gamma2);
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
