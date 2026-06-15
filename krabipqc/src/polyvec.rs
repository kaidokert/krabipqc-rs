//! Fixed-length vectors and matrices of polynomials in `R_q`.
//!
//! `PolyVec<T, LEN>` and `PolyMatrix<T, K, L>` are storage shells over
//! [`Poly<T>`]. Element-wise arithmetic (`add` / `sub`) takes the
//! modulus as a runtime value and delegates to the per-coefficient
//! `Poly` methods, which themselves route through
//! [`modmath::basic::pre_reduced`].

use zeroize::Zeroize;

use crate::poly::Poly;

/// A vector of `LEN` polynomials with coefficient type `T`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolyVec<T, const LEN: usize> {
    pub v: [Poly<T>; LEN],
}

impl<T: Copy + Default, const LEN: usize> Default for PolyVec<T, LEN> {
    fn default() -> Self {
        Self::zero()
    }
}

impl<T: Copy + Default, const LEN: usize> PolyVec<T, LEN> {
    pub fn zero() -> Self {
        Self {
            v: [Poly::<T>::zero(); LEN],
        }
    }
}

impl<T: Zeroize, const LEN: usize> Zeroize for PolyVec<T, LEN> {
    fn zeroize(&mut self) {
        for p in &mut self.v {
            p.zeroize();
        }
    }
}

impl<const LEN: usize> PolyVec<u32, LEN> {
    /// Element-wise vector addition.
    pub fn add(&self, other: &Self, modulus: u32) -> Self {
        let mut out = Self::zero();
        for i in 0..LEN {
            out.v[i] = self.v[i].add(&other.v[i], modulus);
        }
        out
    }

    /// Element-wise vector subtraction.
    pub fn sub(&self, other: &Self, modulus: u32) -> Self {
        let mut out = Self::zero();
        for i in 0..LEN {
            out.v[i] = self.v[i].sub(&other.v[i], modulus);
        }
        out
    }
}

/// A `K × L` matrix of polynomials.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolyMatrix<T, const K: usize, const L: usize> {
    pub rows: [PolyVec<T, L>; K],
}

impl<T: Copy + Default, const K: usize, const L: usize> Default for PolyMatrix<T, K, L> {
    fn default() -> Self {
        Self::zero()
    }
}

impl<T: Copy + Default, const K: usize, const L: usize> PolyMatrix<T, K, L> {
    pub fn zero() -> Self {
        Self {
            rows: [PolyVec::<T, L>::zero(); K],
        }
    }
}

impl<T: Zeroize, const K: usize, const L: usize> Zeroize for PolyMatrix<T, K, L> {
    fn zeroize(&mut self) {
        for row in &mut self.rows {
            row.zeroize();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::N;

    const Q: u32 = 17;

    #[test]
    fn vec_add_sub_roundtrip() {
        let mut a = PolyVec::<u32, 4>::zero();
        let mut b = PolyVec::<u32, 4>::zero();
        for i in 0..4 {
            for j in 0..N {
                a.v[i].coeffs[j] = ((i * 100 + j) as u32) % Q;
                b.v[i].coeffs[j] = ((j * 3 + i) as u32) % Q;
            }
        }
        let s = a.add(&b, Q);
        let r = s.sub(&b, Q);
        assert_eq!(r, a);
    }

    #[test]
    fn vec_zeroize_clears_everything() {
        let mut a = PolyVec::<u32, 4>::zero();
        for i in 0..4 {
            for j in 0..N {
                a.v[i].coeffs[j] = (j as u32 + 1) % Q;
            }
        }
        a.zeroize();
        for i in 0..4 {
            for j in 0..N {
                assert_eq!(a.v[i].coeffs[j], 0);
            }
        }
    }

    #[test]
    fn matrix_zeroize_clears_everything() {
        let mut m = PolyMatrix::<u32, 2, 3>::zero();
        for i in 0..2 {
            for j in 0..3 {
                for k in 0..N {
                    m.rows[i].v[j].coeffs[k] = ((i + j + k) as u32) % Q;
                }
            }
        }
        m.zeroize();
        for i in 0..2 {
            for j in 0..3 {
                for k in 0..N {
                    assert_eq!(m.rows[i].v[j].coeffs[k], 0);
                }
            }
        }
    }
}
