//! Generic scalar arithmetic in Z_q via the `modmath` crate.
//!
//! Each lattice scheme picks a [`Modulus`] (its q + precomputed Montgomery
//! constants); the trait's default methods route every +, -, *, exp, neg
//! through `modmath` primitives. With these defaults the per-scheme impls
//! only declare the constants — no arithmetic is duplicated.

use modmath::{
    WideMul,
    basic::{montgomery::wide, pre_reduced},
};

// `add` / `sub` / `neg` below shadow the `modmath::basic::pre_reduced`
// equivalents with branchless versions. The upstream primitives use
// `if sum >= m { sum - m } else { sum }`, which lowers to a conditional
// branch on the value of the operand -- a 1-bit-per-coefficient leak
// over secret-mixed data. The branchless versions below are equivalent
// modulo timing and free us from upstream-dependent CT properties for
// the canonical-domain Z_q arithmetic.

/// Constants for a fixed prime modulus q with R = 2^32.
///
/// Implementors provide:
/// * `Q` — the modulus itself.
/// * `N_PRIME` — `-Q^{-1} mod 2^32`, used by the wide REDC.
/// * `R2_MOD_N` — `R^2 mod Q`, used to convert to Montgomery form.
///
/// Both `N_PRIME` and `R2_MOD_N` can be computed via
/// `modmath::compute_n_prime_newton` / `compute_r2_mod_n`; the per-scheme
/// modules ship them as `const` and assert the values in unit tests so they
/// stay in sync with modmath.
pub trait Modulus: 'static + Copy {
    const MODULUS: u32;
    const N_PRIME: u32;
    const R2_MOD_N: u32;
    /// R mod Q. Equal to `wide::redc(R2_MOD_N, 0, Q, N_PRIME)`. Used to
    /// pre-tabulate NTT zetas in Montgomery form.
    const R_MOD_N: u32;

    /// Reduce an arbitrary u32 into [0, Q).
    #[inline]
    fn reduce(a: u32) -> u32 {
        a % Self::MODULUS
    }

    /// Branchless `a + b mod q`. Inputs assumed `< q`; sum `< 2q < 2^32`
    /// for all moduli the crate handles (q ≤ 2^23), so no u32 wrap.
    #[inline]
    fn add(a: u32, b: u32) -> u32 {
        let sum = a.wrapping_add(b);
        let diff = sum.wrapping_sub(Self::MODULUS);
        // mask = 0xFFFF_FFFF if (sum - q) underflowed (i.e. sum < q), else 0.
        let mask = 0u32.wrapping_sub(diff >> 31);
        (sum & mask) | (diff & !mask)
    }

    /// Branchless `a - b mod q`. Inputs assumed `< q`. Adds q back if the
    /// raw subtract wrapped.
    #[inline]
    fn sub(a: u32, b: u32) -> u32 {
        let diff = a.wrapping_sub(b);
        // mask = 0xFFFF_FFFF if a < b (diff wrapped past 0), else 0.
        let mask = 0u32.wrapping_sub(diff >> 31);
        diff.wrapping_add(Self::MODULUS & mask)
    }

    /// Canonical modular multiplication: a, b, and result are all in [0, Q).
    ///
    /// Implemented via to-Mont → mul-Mont → from-Mont (4 wide REDC steps
    /// plus 1 widening multiply). Used by `Poly::schoolbook_mul` and other
    /// off-hot-path code; the NTT and matrix multiply use [`Modulus::mul_mont`]
    /// directly with pre-converted operands.
    #[inline]
    fn mul(a: u32, b: u32) -> u32 {
        let a_m = Self::to_mont(a);
        let b_m = Self::to_mont(b);
        let c_m = Self::mul_mont(a_m, b_m);
        Self::from_mont(c_m)
    }

    /// Convert canonical [0, Q) → Montgomery form `x * R mod Q`.
    /// One wide multiply + one REDC.
    #[inline]
    fn to_mont(x: u32) -> u32 {
        let x = if x < Self::MODULUS {
            x
        } else {
            x % Self::MODULUS
        };
        let (lo, hi) = WideMul::wide_mul(&x, &Self::R2_MOD_N);
        wide::redc::<u32>(lo, hi, Self::MODULUS, Self::N_PRIME)
    }

    /// Convert Montgomery form `x_mont = x * R mod Q` back to canonical `x`.
    /// One REDC.
    #[inline]
    fn from_mont(x_mont: u32) -> u32 {
        wide::redc::<u32>(x_mont, 0, Self::MODULUS, Self::N_PRIME)
    }

    /// Montgomery-domain multiply: given a, b interpreted as Montgomery
    /// representatives `a_M = a*R mod Q`, returns `(a*b)*R mod Q`.
    ///
    /// One wide multiply + one REDC. This is the hot-path multiply used by
    /// the NTT and all NTT-domain pointwise/dot products; everything in
    /// the NTT domain carries Montgomery-form coefficients.
    #[inline]
    fn mul_mont(a_mont: u32, b_mont: u32) -> u32 {
        wide::mul::<u32>(a_mont, b_mont, Self::MODULUS, Self::N_PRIME)
    }

    #[inline]
    fn pow(a: u32, e: u32) -> u32 {
        pre_reduced::exp::<u32>(a, e, Self::MODULUS)
    }

    /// Modular inverse `x^{-1} mod q` via Fermat's little theorem
    /// (`x^{q-2}`), in Montgomery domain for speed.
    ///
    /// The exponent is the public `q - 2`, so the square-and-multiply
    /// loop's iteration count is independent of `x`. Each per-step
    /// `mul_mont` is CT on the operand value via `modmath::wide::mul`.
    /// Used by the per-call scalar-blinding setup; assumes `x != 0`
    /// (caller filters), since `0^{q-2} = 0` would silently produce
    /// a non-inverse.
    #[inline]
    fn inv(x: u32) -> u32 {
        debug_assert!(x != 0);
        let x_mont = Self::to_mont(x);
        let one_mont = Self::R_MOD_N;
        let mut acc = one_mont;
        let mut base = x_mont;
        let mut e = Self::MODULUS - 2;
        while e > 0 {
            if e & 1 == 1 {
                acc = Self::mul_mont(acc, base);
            }
            e >>= 1;
            if e > 0 {
                base = Self::mul_mont(base, base);
            }
        }
        Self::from_mont(acc)
    }

    /// Branchless `-a mod q` via `Self::sub(0, a)`. The `Self::sub`
    /// branchless mask handles the `a == 0` edge case (returns 0
    /// instead of `q`).
    #[inline]
    fn neg(a: u32) -> u32 {
        Self::sub(0, a)
    }

    /// Convert a centered representative in (-Q/2, Q/2] to canonical [0, Q).
    ///
    /// Branchless: selects between `x as u32` (non-negative) and
    /// `Q - |x| mod Q` (negative) via an MSB-derived mask. Constant-time
    /// in the value of `x` provided `|x| < Q` (the typical centered input).
    /// For large out-of-range magnitudes the reduction `% Q` is still
    /// applied per-branch; values that come from inside the crate are
    /// always already in range.
    #[inline]
    fn from_signed(x: i32) -> u32 {
        // 0xFFFF_FFFF if x is negative, 0 otherwise.
        let neg_mask = (x >> 31) as u32;
        // |x| as unsigned. `wrapping_abs` of i32::MIN wraps to itself; we
        // never call from_signed with i32::MIN.
        let abs = x.wrapping_abs() as u32;
        // Reduce |x| into [0, Q). Branchless: subtract Q iff abs >= Q.
        let geq_q = (((abs.wrapping_sub(Self::MODULUS) >> 31) ^ 1) & 1).wrapping_neg();
        let abs_red = abs.wrapping_sub(Self::MODULUS & geq_q);
        // Non-negative branch result.
        let pos = abs_red;
        // Negative branch result: Q - abs_red, with the Q-Q = 0 case folded in.
        let zero_mask = ((abs_red | abs_red.wrapping_neg()) >> 31).wrapping_sub(1); // 0xFF if abs_red == 0, else 0
        let neg = Self::MODULUS.wrapping_sub(abs_red) & !zero_mask;
        (pos & !neg_mask) | (neg & neg_mask)
    }

    /// Convert canonical [0, Q) to centered representative in (-Q/2, Q/2].
    ///
    /// Branchless: returns `x - Q` (as i32) when `x > Q/2`, else `x`.
    /// Assumes `x < Q`; values outside that range produce undefined output
    /// (all internal call sites maintain the invariant).
    #[inline]
    fn to_signed(x: u32) -> i32 {
        // 1 if x > Q/2 (i.e. (Q/2 - x) underflows), 0 otherwise.
        let in_high = ((Self::MODULUS / 2).wrapping_sub(x) >> 31) & 1;
        let mask = 0u32.wrapping_sub(in_high); // 0xFF... if high half
        // x - Q reinterpreted as the negative i32 in the high half;
        // x in the low half.
        let x_minus_q = x.wrapping_sub(Self::MODULUS);
        ((x & !mask) | (x_minus_q & mask)) as i32
    }

    /// Absolute value of the centered representative.
    ///
    /// Branchless: returns `min(x, Q - x)`, assuming `x < Q`.
    #[inline]
    fn abs_centered(x: u32) -> u32 {
        let q_minus_x = Self::MODULUS.wrapping_sub(x);
        // 1 if x > q_minus_x, 0 otherwise.
        let take_q_minus_x = (q_minus_x.wrapping_sub(x) >> 31) & 1;
        let mask = 0u32.wrapping_sub(take_q_minus_x); // 0xFF if x > Q-x
        (x & !mask) | (q_minus_x & mask)
    }

    /// Unit-test helper: assert the published Montgomery constants match
    /// what `modmath` would compute. Called by each Modulus impl's tests.
    #[cfg(test)]
    fn assert_mont_params_match() {
        let n_prime = modmath::compute_n_prime_newton::<u32>(Self::MODULUS, 32);
        let r_mod_q = modmath::compute_r_mod_n::<u32>(Self::MODULUS, 32);
        let r2_mod_q = modmath::compute_r2_mod_n::<u32>(r_mod_q, Self::MODULUS, 32);
        assert_eq!(n_prime, Self::N_PRIME, "N_PRIME mismatch");
        assert_eq!(r_mod_q, Self::R_MOD_N, "R_MOD_N mismatch");
        assert_eq!(r2_mod_q, Self::R2_MOD_N, "R2_MOD_N mismatch");
    }

    /// Unit-test helper: to_mont / from_mont round-trip on a wide sample.
    #[cfg(test)]
    fn assert_mont_roundtrip(samples: usize, seed: u64) {
        let mut state = seed;
        for _ in 0..samples {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let x = (state as u32) % Self::MODULUS;
            assert_eq!(Self::from_mont(Self::to_mont(x)), x);
        }
    }

    /// Unit-test helper: `mul_mont(to_mont(a), to_mont(b))` equals
    /// `to_mont(a*b mod Q)`.
    #[cfg(test)]
    fn assert_mul_mont_consistent(samples: usize, seed: u64) {
        let mut state = seed;
        for _ in 0..samples {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let a = (state as u32) % Self::MODULUS;
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let b = (state as u32) % Self::MODULUS;
            let m = Self::mul_mont(Self::to_mont(a), Self::to_mont(b));
            assert_eq!(
                Self::from_mont(m),
                pre_reduced::mul::<u32>(a, b, Self::MODULUS)
            );
        }
    }

    /// Unit-test helper: cross-check `inv` against trial-and-error.
    #[cfg(test)]
    fn assert_inv_roundtrip(samples: usize, seed: u64) {
        let mut state = seed;
        for _ in 0..samples {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let x = ((state as u32) % (Self::MODULUS - 1)) + 1; // x in [1, q-1]
            let inv = Self::inv(x);
            assert_eq!(
                Self::mul(x, inv),
                1,
                "x * x^{{-1}} should be 1 mod q (x={x}, inv={inv})"
            );
        }
    }

    /// Unit-test helper: cross-check `mul` against `pre_reduced::mul`.
    #[cfg(test)]
    fn assert_mul_matches_basic(samples: usize, seed: u64) {
        let mut state = seed;
        for _ in 0..samples {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let a = (state as u32) % Self::MODULUS;
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let b = (state as u32) % Self::MODULUS;
            assert_eq!(
                Self::mul(a, b),
                pre_reduced::mul::<u32>(a, b, Self::MODULUS)
            );
        }
    }
}
