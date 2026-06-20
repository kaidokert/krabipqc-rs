//! Polynomial ring `R_q = Z_q[X]/(X^N + 1)` for `N = 256`.
//!
//! `Poly<T>` is the storage type — a fixed-size array of `N`
//! coefficients of element type `T` (typically `u32`). The
//! arithmetic methods (`add` / `sub` / `schoolbook_mul`) take the
//! modulus as a runtime value of type `T` and delegate to the
//! [`modmath::basic::pre_reduced`] surface, which assumes its inputs
//! are already canonical (`< modulus`). Callers are responsible for
//! upholding that precondition; passing out-of-range coefficients
//! produces undefined-but-deterministic output.

use modmath::basic::pre_reduced as pr;
use zeroize::Zeroize;

use crate::params::N;

/// A polynomial in `R_q`: `N = 256` coefficients of element type `T`.
///
/// `T` is the storage type of one coefficient. For the FIPS 203 / 204
/// moduli (`q ≤ 2^23`) `T = u32` is the natural choice. The arithmetic
/// methods on `Poly<u32>` route through
/// `modmath::basic::pre_reduced::{add, sub, mul}`; the per-call
/// `modulus` argument is the scheme's `q`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Poly<T> {
    pub coeffs: [T; N],
}

impl<T: Copy + Default> Default for Poly<T> {
    fn default() -> Self {
        Self::zero()
    }
}

impl<T: Copy + Default> Poly<T> {
    /// Zero polynomial.
    pub fn zero() -> Self {
        Self {
            coeffs: [T::default(); N],
        }
    }
}

impl<T: Zeroize> Zeroize for Poly<T> {
    fn zeroize(&mut self) {
        self.coeffs.zeroize();
    }
}

// ---------------------------------------------------------------------------
// Arithmetic specialized to u32. PQC moduli all fit comfortably (q ≤ 2^23
// for ML-DSA, q = 3329 for ML-KEM), so u32 is the only storage type the
// scheme code uses. If we later need a different element type the bound
// is straightforward to generalize.
// ---------------------------------------------------------------------------

impl Poly<u32> {
    /// Coefficient-wise addition modulo `modulus`. Inputs assumed
    /// canonical (`< modulus`).
    pub fn add(&self, other: &Self, modulus: u32) -> Self {
        let mut out = Self::zero();
        for i in 0..N {
            out.coeffs[i] = pr::add::<u32>(self.coeffs[i], other.coeffs[i], modulus);
        }
        out
    }

    /// Coefficient-wise subtraction modulo `modulus`.
    pub fn sub(&self, other: &Self, modulus: u32) -> Self {
        let mut out = Self::zero();
        for i in 0..N {
            out.coeffs[i] = pr::sub::<u32>(self.coeffs[i], other.coeffs[i], modulus);
        }
        out
    }

    /// Schoolbook (O(N²)) multiplication in `R_q = Z_q[X]/(X^N + 1)`.
    /// The anticyclic reduction is performed inline: terms that would
    /// overflow degree `N` are subtracted from the low half (`X^N = -1`).
    pub fn schoolbook_mul(&self, other: &Self, modulus: u32) -> Self {
        let mut out = Self::zero();
        for i in 0..N {
            for j in 0..N {
                let prod = pr::mul::<u32>(self.coeffs[i], other.coeffs[j], modulus);
                let k = i + j;
                if k < N {
                    out.coeffs[k] = pr::add::<u32>(out.coeffs[k], prod, modulus);
                } else {
                    // X^N = -1: contribution lands at index (k - N) with
                    // a sign flip.
                    out.coeffs[k - N] = pr::sub::<u32>(out.coeffs[k - N], prod, modulus);
                }
            }
        }
        out
    }

    /// Coefficient-wise (Hadamard) multiplication modulo `modulus`.
    ///
    /// Not the right operation for NTT-domain polynomials (which need
    /// the scheme-specific `mul_ntt` arriving with PR2); kept here for
    /// the time-domain pointwise multiply that some helpers want.
    pub fn elementwise_mul(&self, other: &Self, modulus: u32) -> Self {
        let mut out = Self::zero();
        for i in 0..N {
            out.coeffs[i] = pr::mul::<u32>(self.coeffs[i], other.coeffs[i], modulus);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Small test prime. Real moduli (q = 3329 for ML-KEM, q ≈ 2^23 for
    // ML-DSA) land with the per-scheme params in later PRs.
    const Q: u32 = 17;

    #[test]
    fn add_sub_roundtrip() {
        let mut a = Poly::<u32>::zero();
        let mut b = Poly::<u32>::zero();
        for i in 0..N {
            a.coeffs[i] = (i as u32 * 5) % Q;
            b.coeffs[i] = (i as u32 * 3 + 1) % Q;
        }
        let s = a.add(&b, Q);
        let r = s.sub(&b, Q);
        assert_eq!(r, a);
    }

    #[test]
    fn schoolbook_constant_mul() {
        let mut a = Poly::<u32>::zero();
        a.coeffs[0] = 2;
        a.coeffs[1] = 3;
        let mut b = Poly::<u32>::zero();
        b.coeffs[0] = 5;
        let p = a.schoolbook_mul(&b, Q);
        assert_eq!(p.coeffs[0], 10);
        assert_eq!(p.coeffs[1], 15);
        for i in 2..N {
            assert_eq!(p.coeffs[i], 0);
        }
    }

    #[test]
    fn schoolbook_anticyclic() {
        // X^{N-1} * X = X^N = -1 in R_q. Result is the constant
        // polynomial (modulus - 1).
        let mut a = Poly::<u32>::zero();
        a.coeffs[N - 1] = 1;
        let mut b = Poly::<u32>::zero();
        b.coeffs[1] = 1;
        let p = a.schoolbook_mul(&b, Q);
        assert_eq!(p.coeffs[0], Q - 1);
        for i in 1..N {
            assert_eq!(p.coeffs[i], 0);
        }
    }

    #[test]
    fn zeroize_clears_all_coeffs() {
        let mut a = Poly::<u32>::zero();
        for i in 0..N {
            a.coeffs[i] = (i as u32 + 1) % Q;
        }
        a.zeroize();
        for i in 0..N {
            assert_eq!(a.coeffs[i], 0);
        }
    }

    #[test]
    fn default_yields_zero() {
        let p: Poly<u32> = Poly::default();
        assert!(p.coeffs.iter().all(|&c| c == 0));
    }

    #[test]
    fn elementwise_mul_pointwise() {
        let mut a = Poly::<u32>::zero();
        let mut b = Poly::<u32>::zero();
        for i in 0..N {
            a.coeffs[i] = (i as u32 + 1) % Q;
            b.coeffs[i] = 2;
        }
        let c = a.elementwise_mul(&b, Q);
        for i in 0..N {
            assert_eq!(c.coeffs[i], (a.coeffs[i] * 2) % Q);
        }
    }
}
