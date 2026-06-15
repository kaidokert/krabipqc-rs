//! Polynomial ring `R_q = Z_q[X]/(X^N + 1)` for N = 256, generic over
//! the modulus `M`.
//!
//! Coefficients are stored as raw u32 in [0, Q); the meaning (canonical
//! vs Montgomery form) is a function-level convention. Personality choice
//! (Nct / Ct) is carried by the NTT trait `NttScheme<P>`, not by `Poly`
//! itself — keeping `Poly<M>` ungeneric over `P` avoids forcing every
//! call site through turbofish around the const-generic `LEN` on
//! `PolyVec`.

use core::marker::PhantomData;

use zeroize::Zeroize;

use crate::field::Modulus;
use crate::params::N;

/// A polynomial in R_q (or its NTT image): 256 u32 coefficients tagged by
/// the modulus `M`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Poly<M: Modulus> {
    pub coeffs: [u32; N],
    _m: PhantomData<fn() -> M>,
}

impl<M: Modulus> Zeroize for Poly<M> {
    fn zeroize(&mut self) {
        self.coeffs.zeroize();
    }
}

impl<M: Modulus> Poly<M> {
    /// Zero polynomial.
    pub const fn zero() -> Self {
        Self {
            coeffs: [0u32; N],
            _m: PhantomData,
        }
    }

    /// Coefficient-wise addition.
    pub fn add(&self, other: &Self) -> Self {
        let mut out = Self::zero();
        for i in 0..N {
            out.coeffs[i] = M::add(self.coeffs[i], other.coeffs[i]);
        }
        out
    }

    /// Coefficient-wise subtraction.
    pub fn sub(&self, other: &Self) -> Self {
        let mut out = Self::zero();
        for i in 0..N {
            out.coeffs[i] = M::sub(self.coeffs[i], other.coeffs[i]);
        }
        out
    }

    /// Schoolbook multiplication in R_q (mod X^N + 1). O(N^2); used for testing.
    pub fn schoolbook_mul(&self, other: &Self) -> Self {
        let mut out = Self::zero();
        for i in 0..N {
            for j in 0..N {
                let prod = M::mul(self.coeffs[i], other.coeffs[j]);
                let k = i + j;
                if k < N {
                    out.coeffs[k] = M::add(out.coeffs[k], prod);
                } else {
                    // X^N = -1
                    out.coeffs[k - N] = M::sub(out.coeffs[k - N], prod);
                }
            }
        }
        out
    }

    /// Canonical element-wise multiplication. Both inputs interpreted as
    /// canonical Z_q values; output is canonical.
    ///
    /// Note: this is **not** the right operation for NTT-domain polynomials.
    /// Use [`crate::polyvec::NttScheme::mul_ntt`] — those know about the
    /// Montgomery-form convention used in the NTT domain.
    pub fn elementwise_mul(&self, other: &Self) -> Self {
        let mut out = Self::zero();
        for i in 0..N {
            out.coeffs[i] = M::mul(self.coeffs[i], other.coeffs[i]);
        }
        out
    }
}
