//! Dispatch trait that picks between `wide::mul` (variable-time
//! finalize) and `wide::ct::mul` (CT finalize via `subtle`) on a
//! type-level personality marker, so the scheme code can stay generic
//! over `P: Personality` without naming the two disjoint modmath
//! entry points explicitly.

use fixed_bigint::{Ct, Nct, Personality};
use modmath::basic::montgomery::wide;
use modmath::basic::pre_reduced as pr;

/// Montgomery-domain ops on raw `u32` reps, dispatched by `P`.
/// Inputs and outputs are u32 in `[0, q)` interpreted as `x · R mod q`;
/// the modulus constants (`q`, `n_prime = -q^-1 mod 2^32`,
/// `r2_mod_q = R^2 mod q`) are threaded per-call so a single set of
/// impls serves any prime.
pub trait FieldExt<P: Personality> {
    /// Canonical `u32` → Mont-form `u32`.
    fn reduce(canonical: u32, q: u32, n_prime: u32, r2_mod_q: u32) -> u32;

    /// Mont-domain multiplication: `(a·R)(b·R)/R = (a·b)·R`.
    fn mul_mont(a: u32, b: u32, q: u32, n_prime: u32) -> u32;

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
    fn mul_mont(a: u32, b: u32, q: u32, n_prime: u32) -> u32 {
        wide::mul::<u32>(a, b, q, n_prime)
    }
}

impl FieldExt<Ct> for Ct {
    #[inline]
    fn reduce(canonical: u32, q: u32, n_prime: u32, r2_mod_q: u32) -> u32 {
        wide::ct::mul::<u32>(canonical, r2_mod_q, q, n_prime)
    }
    #[inline]
    fn mul_mont(a: u32, b: u32, q: u32, n_prime: u32) -> u32 {
        wide::ct::mul::<u32>(a, b, q, n_prime)
    }
}
