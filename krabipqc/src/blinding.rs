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
pub fn derive_pair<P: Personality + FieldExt<P>>(
    seed: &[u8],
    domain_tag: &[u8],
    q: u32,
    q_n_prime: u32,
    q_r2_mod_q: u32,
) -> (u32, u32) {
    let r = derive_r(seed, domain_tag, q);
    // Fermat inverse: r^(q-2) mod q. Once per signature, not hot.
    let r_inv = pr::exp::<u32>(r, q - 2, q);
    (
        <P as FieldExt<P>>::reduce(r, q, q_n_prime, q_r2_mod_q),
        <P as FieldExt<P>>::reduce(r_inv, q, q_n_prime, q_r2_mod_q),
    )
}

fn derive_r(seed: &[u8], domain_tag: &[u8], q: u32) -> u32 {
    let mut buf = [0u8; 8];
    shake256(&[seed, domain_tag], &mut buf);
    let x = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    // Lemire's bounded-random reduction: result is in [0, q-1] with a
    // tiny bias that's irrelevant for blinding. Constant-time on all
    // targets — no `%` on a secret value, which would leak `r` via
    // data-dependent divider timing on x86 and Cortex-M.
    let mapped = ((x as u64 * (q - 1) as u64) >> 32) as u32;
    mapped + 1
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
