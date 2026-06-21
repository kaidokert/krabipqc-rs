//! Dispatch trait that picks between `wide::mul` (variable-time
//! finalize) and `wide::ct::mul` (CT finalize via `subtle`) on a
//! type-level personality marker, so the scheme code can stay generic
//! over `P: Personality` without naming the two disjoint modmath
//! entry points explicitly.

use fixed_bigint::{Ct, Nct, Personality};
use modmath::basic::montgomery::wide;
use modmath::basic::pre_reduced as pr;

/// Montgomery-domain ops on raw `u32` reps, dispatched by `P`.
/// The modulus constants (`q`, `n_prime = -q^-1 mod 2^32`,
/// `r2_mod_q = R^2 mod q`) are threaded per-call so a single set of
/// impls serves any prime.
pub trait FieldExt<P: Personality> {
    /// Canonical `u32` → Mont-form `u32`.
    fn reduce(canonical: u32, q: u32, n_prime: u32, r2_mod_q: u32) -> u32;

    /// Mont-form `u32` → canonical `u32`. One REDC.
    fn into_raw(mont: u32, q: u32, n_prime: u32) -> u32;

    /// Mont-domain multiplication: `(a·R)(b·R)/R = (a·b)·R`.
    fn mul_mont(a: u32, b: u32, q: u32, n_prime: u32) -> u32;

    /// Caller pairs `N` of these with a single [`Self::redc`] at the end
    /// to get a fused inner product paying one REDC per output coefficient
    /// instead of one per multiply. Safe while `N ≤ R/Q` (R = 2^32).
    fn mul_acc(acc_lo: u32, acc_hi: u32, a: u32, b: u32) -> (u32, u32);

    /// REDC of a double-width `(lo, hi)` Mont-domain accumulator,
    /// folding back to a single-width `u32` in `[0, q)`. Pair with
    /// [`Self::mul_acc`].
    fn redc(acc_lo: u32, acc_hi: u32, q: u32, n_prime: u32) -> u32;

    /// Mont-domain addition (= canonical add mod `q`).
    #[inline]
    fn add_mont(a: u32, b: u32, q: u32) -> u32 {
        pr::add::<u32>(a, b, q)
    }

    /// Mont-domain subtraction.
    #[inline]
    fn sub_mont(a: u32, b: u32, q: u32) -> u32 {
        pr::sub::<u32>(a, b, q)
    }
}

impl FieldExt<Nct> for Nct {
    #[inline]
    fn reduce(canonical: u32, q: u32, n_prime: u32, r2_mod_q: u32) -> u32 {
        wide::mul::<u32>(canonical, r2_mod_q, q, n_prime)
    }
    #[inline]
    fn into_raw(mont: u32, q: u32, n_prime: u32) -> u32 {
        wide::redc::<u32>(mont, 0, q, n_prime)
    }
    #[inline]
    fn mul_mont(a: u32, b: u32, q: u32, n_prime: u32) -> u32 {
        wide::mul::<u32>(a, b, q, n_prime)
    }
    #[inline]
    fn mul_acc(acc_lo: u32, acc_hi: u32, a: u32, b: u32) -> (u32, u32) {
        wide::mul_acc::<u32>(acc_lo, acc_hi, a, b)
    }
    #[inline]
    fn redc(acc_lo: u32, acc_hi: u32, q: u32, n_prime: u32) -> u32 {
        wide::redc::<u32>(acc_lo, acc_hi, q, n_prime)
    }
}

impl FieldExt<Ct> for Ct {
    #[inline]
    fn reduce(canonical: u32, q: u32, n_prime: u32, r2_mod_q: u32) -> u32 {
        wide::ct::mul::<u32>(canonical, r2_mod_q, q, n_prime)
    }
    #[inline]
    fn into_raw(mont: u32, q: u32, n_prime: u32) -> u32 {
        wide::ct::redc::<u32>(mont, 0, q, n_prime)
    }
    #[inline]
    fn mul_mont(a: u32, b: u32, q: u32, n_prime: u32) -> u32 {
        wide::ct::mul::<u32>(a, b, q, n_prime)
    }
    #[inline]
    fn mul_acc(acc_lo: u32, acc_hi: u32, a: u32, b: u32) -> (u32, u32) {
        wide::ct::mul_acc::<u32>(acc_lo, acc_hi, a, b)
    }
    #[inline]
    fn redc(acc_lo: u32, acc_hi: u32, q: u32, n_prime: u32) -> u32 {
        wide::ct::redc::<u32>(acc_lo, acc_hi, q, n_prime)
    }
}
