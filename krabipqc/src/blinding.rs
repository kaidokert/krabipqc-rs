//! Multiplicative scalar blinding for the secret-mixed `c · s_hat`
//! product in ML-DSA sign. Each call picks a random `r ∈ Z_q*`,
//! scales the secret operand by `r`, runs the multiplication, then
//! unblinds by scaling the cofactor by `r^{-1}`. The product collapses
//! to the unblinded value but the multiplier hardware only ever sees
//! `s · r`, so per-coefficient correlation attacks need `r` to
//! interpret the trace — and `r` never leaves the function.

use fixed_bigint::Personality;
use modmath::basic::pre_reduced as pr;

use crate::field_ext::FieldExt;
use crate::hashing::shake256;
use crate::poly::Poly;
use crate::polyvec::PolyVec;

/// Derive a Montgomery-form blinding factor `r ∈ [1, q-1]` and its
/// inverse `r^{-1}` (also in Mont form). The personality dispatch
/// picks the variable-time or constant-time Mont conversion.
///
/// Inputs (`seed_pieces`, `domain_tag`) are absorbed into SHAKE-256;
/// `r` is sampled with a small uniformity bias that's irrelevant
/// for blinding.
pub fn derive_pair<P: Personality + FieldExt<P>>(
    seed_pieces: &[&[u8]],
    domain_tag: &[u8],
    q: u32,
    q_n_prime: u32,
    q_r2_mod_q: u32,
) -> (u32, u32) {
    let r = derive_r(seed_pieces, domain_tag, q);
    // Modular inverse via Fermat: r^(q-2) mod q. pr::exp is bit-by-bit
    // but this runs once per op so it's not perf-critical.
    let r_inv = pr::exp::<u32>(r, q - 2, q);
    (
        <P as FieldExt<P>>::reduce(r, q, q_n_prime, q_r2_mod_q),
        <P as FieldExt<P>>::reduce(r_inv, q, q_n_prime, q_r2_mod_q),
    )
}

fn derive_r(seed_pieces: &[&[u8]], domain_tag: &[u8], q: u32) -> u32 {
    const MAX_PIECES: usize = 7;
    debug_assert!(seed_pieces.len() < MAX_PIECES);
    let mut absorb: [&[u8]; MAX_PIECES] = [&[]; MAX_PIECES];
    for (i, p) in seed_pieces.iter().enumerate() {
        absorb[i] = p;
    }
    absorb[seed_pieces.len()] = domain_tag;

    let mut buf = [0u8; 8];
    shake256(&absorb[..seed_pieces.len() + 1], &mut buf);
    let x = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    (x % (q - 1)) + 1
}

/// Multiply every coefficient of `p` by `r_mont` in-place (Mont ×
/// Mont = Mont).
#[inline]
pub fn scale_mont<P: Personality + FieldExt<P>>(
    p: &mut Poly<u32>,
    r_mont: u32,
    q: u32,
    q_n_prime: u32,
) {
    for c in p.coeffs.iter_mut() {
        *c = <P as FieldExt<P>>::mul_mont(*c, r_mont, q, q_n_prime);
    }
}

/// Multiply every coefficient of every poly in `v` by `r_mont`
/// in-place.
#[inline]
pub fn scale_polyvec_mont<P: Personality + FieldExt<P>, const LEN: usize>(
    v: &mut PolyVec<u32, LEN>,
    r_mont: u32,
    q: u32,
    q_n_prime: u32,
) {
    for p in v.v.iter_mut() {
        scale_mont::<P>(p, r_mont, q, q_n_prime);
    }
}
