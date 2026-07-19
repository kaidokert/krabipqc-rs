//! Multiplicative scalar blinding for the secret-mixed multiplications
//! in ML-DSA sign (`c · s_hat`) and ML-KEM decaps (`s_hat · u_hat`).
//! Each call picks a random `r ∈ Z_q*`, scales the secret operand by
//! `r`, runs the multiplication, then unblinds by scaling the cofactor
//! by `r^{-1}`. The product collapses to the unblinded value but the
//! multiplier hardware only ever sees `s · r`, so per-coefficient
//! correlation attacks need `r` to interpret the trace — and `r`
//! never leaves the function.

use const_num_traits::Personality;

use crate::field_ext::FieldExt;
use crate::hashing::shake256;
use crate::poly::Poly;
#[cfg(not(feature = "lowmem"))]
use crate::polyvec::PolyVec;
/// Derive a Montgomery-form blinding factor `r ∈ [1, q-1]` and its
/// inverse `r^{-1}` (also in Mont form). The personality dispatch
/// picks the variable-time or constant-time Mont conversion.
///
/// `absorb` is the full SHAKE-256 input list — by convention the
/// caller includes the per-op domain tag as the last piece (e.g.
/// `&[rnd, b"krabipqc/sign-blind"]` for sign,
/// `&[dk, ct, b"krabipqc/decaps-blind"]` for decaps) so the same `r`
/// can never be derived across different operations on the same key
/// material.
pub fn derive_pair<P: Personality + FieldExt<P>>(
    absorb: &[&[u8]],
    q: u32,
    q_n_prime: u32,
    q_r2_mod_q: u32,
) -> (u32, u32) {
    let r = derive_r(absorb, q);
    let r_mont = <P as FieldExt<P>>::reduce(r, q, q_n_prime, q_r2_mod_q);
    // Fermat inverse via fixed-exponent square-and-multiply in Montgomery
    // domain. The exponent q-2 is a public constant so the loop iterates
    // its bits in fixed order — no secret-dependent branching. Each
    // multiplication goes through P::mul_mont, which is CT for the Ct
    // personality. The result is already in Montgomery form.
    let r_inv_mont = mont_exp_fixed::<P>(r_mont, q - 2, q, q_n_prime, q_r2_mod_q);
    (r_mont, r_inv_mont)
}

// Square-and-multiply with a public fixed exponent.
// `base_mont` is the secret input in Montgomery form; `exp` must be a
// public value (its bits control the loop, not secret data).
fn mont_exp_fixed<P: Personality + FieldExt<P>>(
    base_mont: u32,
    exp: u32,
    q: u32,
    q_n_prime: u32,
    q_r2_mod_q: u32,
) -> u32 {
    let mut result = <P as FieldExt<P>>::reduce(1, q, q_n_prime, q_r2_mod_q);
    let mut base = base_mont;
    let mut e = exp;
    while e > 0 {
        if e & 1 == 1 {
            result = <P as FieldExt<P>>::mul_mont(result, base, q, q_n_prime);
        }
        base = <P as FieldExt<P>>::mul_mont(base, base, q, q_n_prime);
        e >>= 1;
    }
    result
}

fn derive_r(absorb: &[&[u8]], q: u32) -> u32 {
    let mut buf = [0u8; 8];
    shake256(absorb, &mut buf);
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

/// Only the default sign path blinds whole PolyVecs up front;
/// `lowmem` blinds rows individually via [`scale_mont`].
#[inline]
#[cfg(not(feature = "lowmem"))]
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
