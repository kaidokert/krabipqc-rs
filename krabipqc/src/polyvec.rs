//! Fixed-length vectors and matrices of polynomials in R_q.
//!
//! Generic over the modulus `M`. The NTT-domain helpers (`.ntt()`,
//! `.inv_ntt()`, `PolyMatrix::mul_vec_ntt`) are only available when `M`
//! implements [`NttScheme`] — ML-DSA and ML-KEM each plug in their own.

use core::marker::PhantomData;

use fixed_bigint::{Nct, Personality};
use zeroize::Zeroize;

use crate::field::Modulus;
use crate::params::N;
use crate::poly::Poly;

/// A vector of `LEN` polynomials over Z_q (Q determined by `M`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolyVec<M: Modulus, const LEN: usize> {
    pub v: [Poly<M>; LEN],
    _m: PhantomData<fn() -> M>,
}

impl<M: Modulus, const LEN: usize> Zeroize for PolyVec<M, LEN> {
    fn zeroize(&mut self) {
        for p in &mut self.v {
            p.zeroize();
        }
    }
}

impl<M: Modulus, const LEN: usize> PolyVec<M, LEN> {
    pub const fn zero() -> Self {
        Self {
            v: [Poly::<M>::zero(); LEN],
            _m: PhantomData,
        }
    }

    pub fn add(&self, other: &Self) -> Self {
        let mut out = Self::zero();
        for i in 0..LEN {
            out.v[i] = self.v[i].add(&other.v[i]);
        }
        out
    }

    pub fn sub(&self, other: &Self) -> Self {
        let mut out = Self::zero();
        for i in 0..LEN {
            out.v[i] = self.v[i].sub(&other.v[i]);
        }
        out
    }

    /// Max absolute centered coefficient across the whole vector.
    pub fn inf_norm(&self) -> u32 {
        let mut m = 0u32;
        for poly in &self.v {
            for &c in &poly.coeffs {
                let a = M::abs_centered(c);
                if a > m {
                    m = a;
                }
            }
        }
        m
    }
}

/// NTT-domain scheme parameterized by the personality `P`.
///
/// Each `(modulus, personality)` pair gets its own impl — the NTT
/// butterflies and the `mul_ntt` body are identical algorithmically,
/// but the underlying `Mont<M, P>::mul` they call routes to either
/// `wide::mul` (Nct) or `wide::ct::mul` (Ct).
///
/// (For ML-DSA's complete NTT `mul_ntt` is the trivial elementwise product;
/// for ML-KEM's incomplete NTT it's BaseCaseMultiply applied to 128 pairs.)
pub trait NttScheme<P: Personality = Nct>: Modulus {
    fn ntt(p: &mut Poly<Self>);
    fn inv_ntt(p: &mut Poly<Self>);
    fn mul_ntt(a: &Poly<Self>, b: &Poly<Self>) -> Poly<Self>;
}

// ---------------------------------------------------------------------------
// NTT-domain methods on PolyVec / PolyMatrix.
//
// `vec.ntt()` etc. resolve to the Nct variant (matches the original
// signature and keeps every existing call site working unchanged).
// `vec.ntt_with::<P>()` is the personality-explicit form, used by
// generic-over-P code
// ---------------------------------------------------------------------------

impl<M: Modulus, const LEN: usize> PolyVec<M, LEN> {
    /// Forward NTT under the given personality.
    pub fn ntt_with<P: Personality>(&self) -> Self
    where
        M: NttScheme<P>,
    {
        let mut out = *self;
        for i in 0..LEN {
            <M as NttScheme<P>>::ntt(&mut out.v[i]);
        }
        out
    }

    /// Inverse NTT under the given personality.
    pub fn inv_ntt_with<P: Personality>(&self) -> Self
    where
        M: NttScheme<P>,
    {
        let mut out = *self;
        for i in 0..LEN {
            <M as NttScheme<P>>::inv_ntt(&mut out.v[i]);
        }
        out
    }

    /// `scale_pointwise` under the given personality.
    pub fn scale_pointwise_with<P: Personality>(&self, c: &Poly<M>) -> Self
    where
        M: NttScheme<P>,
    {
        let mut out = Self::zero();
        for i in 0..LEN {
            out.v[i] = <M as NttScheme<P>>::mul_ntt(c, &self.v[i]);
        }
        out
    }
}

impl<M: NttScheme<Nct>, const LEN: usize> PolyVec<M, LEN> {
    /// Default-personality (Nct) forward NTT.
    pub fn ntt(&self) -> Self {
        self.ntt_with::<Nct>()
    }

    /// Default-personality (Nct) inverse NTT.
    pub fn inv_ntt(&self) -> Self {
        self.inv_ntt_with::<Nct>()
    }

    /// Default-personality (Nct) pointwise scale.
    pub fn scale_pointwise(&self, c: &Poly<M>) -> Self {
        self.scale_pointwise_with::<Nct>(c)
    }
}

/// A K x L matrix of polynomials (k rows, l columns).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolyMatrix<M: Modulus, const K: usize, const L: usize> {
    pub rows: [PolyVec<M, L>; K],
    _m: PhantomData<fn() -> M>,
}

impl<M: Modulus, const K: usize, const L: usize> PolyMatrix<M, K, L> {
    pub const fn zero() -> Self {
        Self {
            rows: [PolyVec::<M, L>::zero(); K],
            _m: PhantomData,
        }
    }
}

impl<M: Modulus, const K: usize, const L: usize> PolyMatrix<M, K, L> {
    /// Matrix–vector multiplication in the NTT domain under personality `P`:
    /// out_i = sum_j a_ij * v_j. All inputs and outputs are NTT-domain.
    pub fn mul_vec_ntt_with<P: Personality>(&self, v: &PolyVec<M, L>) -> PolyVec<M, K>
    where
        M: NttScheme<P>,
    {
        let mut out = PolyVec::<M, K>::zero();
        for i in 0..K {
            let mut acc = Poly::<M>::zero();
            for j in 0..L {
                let p = <M as NttScheme<P>>::mul_ntt(&self.rows[i].v[j], &v.v[j]);
                acc = acc.add(&p);
            }
            out.v[i] = acc;
        }
        out
    }
}

impl<M: NttScheme<Nct>, const K: usize, const L: usize> PolyMatrix<M, K, L> {
    /// Default-personality (Nct) matrix-vector multiply.
    pub fn mul_vec_ntt(&self, v: &PolyVec<M, L>) -> PolyVec<M, K> {
        self.mul_vec_ntt_with::<Nct>(v)
    }
}

impl<M: Modulus, const K: usize> PolyMatrix<M, K, K> {
    /// Transposed matrix–vector multiplication under personality `P`:
    /// out_i = sum_j a_ji * v_j. Only defined for square matrices.
    pub fn transposed_mul_vec_ntt_with<P: Personality>(&self, v: &PolyVec<M, K>) -> PolyVec<M, K>
    where
        M: NttScheme<P>,
    {
        let mut out = PolyVec::<M, K>::zero();
        for i in 0..K {
            let mut acc = Poly::<M>::zero();
            for j in 0..K {
                let p = <M as NttScheme<P>>::mul_ntt(&self.rows[j].v[i], &v.v[j]);
                acc = acc.add(&p);
            }
            out.v[i] = acc;
        }
        out
    }
}

impl<M: NttScheme<Nct>, const K: usize> PolyMatrix<M, K, K> {
    /// Default-personality transposed matrix-vector multiply.
    pub fn transposed_mul_vec_ntt(&self, v: &PolyVec<M, K>) -> PolyVec<M, K> {
        self.transposed_mul_vec_ntt_with::<Nct>(v)
    }
}

impl<M: Modulus, const LEN: usize> PolyVec<M, LEN> {
    /// NTT-domain dot product under personality `P`: `sum_i self[i] * other[i]`.
    pub fn dot_ntt_with<P: Personality>(&self, other: &PolyVec<M, LEN>) -> Poly<M>
    where
        M: NttScheme<P>,
    {
        let mut acc = Poly::<M>::zero();
        for i in 0..LEN {
            let p = <M as NttScheme<P>>::mul_ntt(&self.v[i], &other.v[i]);
            acc = acc.add(&p);
        }
        acc
    }
}

impl<M: NttScheme<Nct>, const LEN: usize> PolyVec<M, LEN> {
    /// Default-personality (Nct) dot product.
    pub fn dot_ntt(&self, other: &PolyVec<M, LEN>) -> Poly<M> {
        self.dot_ntt_with::<Nct>(other)
    }
}

/// Helper to map a scalar function over every coefficient of a PolyVec.
pub fn map_coeffs<M: Modulus, const LEN: usize, F: Fn(u32) -> u32>(
    v: &PolyVec<M, LEN>,
    f: F,
) -> PolyVec<M, LEN> {
    let mut out = PolyVec::<M, LEN>::zero();
    for i in 0..LEN {
        for j in 0..N {
            out.v[i].coeffs[j] = f(v.v[i].coeffs[j]);
        }
    }
    out
}
