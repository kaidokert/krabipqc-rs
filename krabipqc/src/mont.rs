//! `Mont<M, P>` — a `#[repr(transparent)]` newtype around `u32`, tagged by
//! its modulus `M` and by its [`Personality`] `P`.
//!
//! `Nct` (default) selects the variable-time finalize; `Ct` selects the
//! constant-time finalize via `subtle::ConditionallySelectable`. The Nct
//! and Ct method bodies live in separate `impl` blocks rather than
//! dispatching at runtime, so the optimizer can specialize.

use core::marker::PhantomData;

use fixed_bigint::{Ct, Nct, Personality};
use modmath::basic::montgomery::wide;
use subtle::{Choice, ConditionallySelectable, ConstantTimeLess};

use crate::field::Modulus;

/// A u32 value in Montgomery form, tagged with its modulus `M` and the
/// personality `P` (which picks branched- vs CT-finalize).
///
/// `#[repr(transparent)]` so `[Mont<M, P>; 256]` has the same memory
/// layout as `[u32; 256]` — important for ABI compatibility with any
/// existing raw-u32 code path and for the optimizer.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct Mont<M: Modulus, P: Personality = Nct> {
    inner: u32,
    _m: PhantomData<fn() -> (M, P)>,
}

// ---------------------------------------------------------------------------
// Personality-agnostic accessors / constants
// ---------------------------------------------------------------------------

impl<M: Modulus, P: Personality> Mont<M, P> {
    /// Wrap a raw u32 already in Montgomery form. **Escape hatch:** caller
    /// guarantees `inner ≡ x · R mod M::MODULUS` for some `x` in `[0, M::MODULUS)`.
    pub const fn from_mont_raw(inner: u32) -> Self {
        Self {
            inner,
            _m: PhantomData,
        }
    }

    /// Unwrap to the raw Montgomery-form u32.
    pub const fn to_mont_raw(self) -> u32 {
        self.inner
    }

    /// Additive identity (0 in Mont form is 0).
    pub const fn zero() -> Self {
        Self::from_mont_raw(0)
    }

    /// Multiplicative identity (1 in Mont form is `R mod M::MODULUS`).
    pub const fn one() -> Self {
        Self::from_mont_raw(M::R_MOD_N)
    }
}

// ---------------------------------------------------------------------------
// Nct variant — variable-time finalize (verify, Encaps)
// ---------------------------------------------------------------------------

// Inherent `add`/`sub`/`mul` are intentional and match modmath's `Field`
// surface + ed25519's `Curve25519Field`. We're not implementing the
// std::ops traits because we want by-value semantics + a name that says
// "Mont domain" rather than overloading `+`/`-`/`*`.
#[allow(clippy::should_implement_trait)]
impl<M: Modulus> Mont<M, Nct> {
    /// Convert a canonical `[0, M::MODULUS)` value to Montgomery form.
    /// One wide mul + one wide REDC. Variable-time finalize.
    pub fn from_raw(raw: u32) -> Self {
        let raw = if raw < M::MODULUS {
            raw
        } else {
            raw % M::MODULUS
        };
        Self::from_mont_raw(wide::mul::<u32>(raw, M::R2_MOD_N, M::MODULUS, M::N_PRIME))
    }

    /// Convert back to canonical form. One wide REDC.
    pub fn to_raw(self) -> u32 {
        wide::redc::<u32>(self.inner, 0, M::MODULUS, M::N_PRIME)
    }

    /// Montgomery-domain modular multiplication. Branched final-sub.
    #[inline]
    pub fn mul(self, other: Self) -> Self {
        Self::from_mont_raw(wide::mul::<u32>(
            self.inner,
            other.inner,
            M::MODULUS,
            M::N_PRIME,
        ))
    }

    /// Modular addition. Branched conditional-subtract.
    pub fn add(self, other: Self) -> Self {
        let sum = self.inner.wrapping_add(other.inner);
        let needs_sub = sum < self.inner || sum >= M::MODULUS;
        let result = if needs_sub {
            sum.wrapping_sub(M::MODULUS)
        } else {
            sum
        };
        Self::from_mont_raw(result)
    }

    /// Modular subtraction. Branched borrow correction.
    pub fn sub(self, other: Self) -> Self {
        let (diff, borrow) = self.inner.overflowing_sub(other.inner);
        let result = if borrow {
            diff.wrapping_add(M::MODULUS)
        } else {
            diff
        };
        Self::from_mont_raw(result)
    }
}

// ---------------------------------------------------------------------------
// Ct variant — constant-time finalize (sign, Decaps)
// ---------------------------------------------------------------------------

#[allow(clippy::should_implement_trait)]
impl<M: Modulus> Mont<M, Ct> {
    /// Convert a canonical value to Mont form. CT finalize.
    pub fn from_raw(raw: u32) -> Self {
        let raw = if raw < M::MODULUS {
            raw
        } else {
            raw % M::MODULUS
        };
        Self::from_mont_raw(wide::ct::mul::<u32>(
            raw,
            M::R2_MOD_N,
            M::MODULUS,
            M::N_PRIME,
        ))
    }

    /// Convert back to canonical form. CT REDC.
    pub fn to_raw(self) -> u32 {
        wide::ct::redc::<u32>(self.inner, 0, M::MODULUS, M::N_PRIME)
    }

    /// Mont-domain modular multiplication. CT finalize via
    /// `subtle::ConditionallySelectable`.
    #[inline]
    pub fn mul(self, other: Self) -> Self {
        Self::from_mont_raw(wide::ct::mul::<u32>(
            self.inner,
            other.inner,
            M::MODULUS,
            M::N_PRIME,
        ))
    }

    /// Modular addition with CT conditional-subtract. Mirrors
    /// `modmath::Field<_, Ct>::add`.
    pub fn add(self, other: Self) -> Self {
        let sum = self.inner.wrapping_add(other.inner);
        let sub = sum.wrapping_sub(M::MODULUS);
        let carry = sum.ct_lt(&self.inner); // wraparound bit
        let ge_m = !sum.ct_lt(&M::MODULUS);
        let needs_sub = carry | ge_m;
        Self::from_mont_raw(u32::conditional_select(&sum, &sub, needs_sub))
    }

    /// Modular subtraction with CT borrow correction.
    pub fn sub(self, other: Self) -> Self {
        let diff = self.inner.wrapping_sub(other.inner);
        let corrected = diff.wrapping_add(M::MODULUS);
        let borrow = self.inner.ct_lt(&other.inner);
        Self::from_mont_raw(u32::conditional_select(&diff, &corrected, borrow))
    }
}

// CT-only ConditionallySelectable. Selecting on Nct values silently is a
// category error (the caller is mixing public and secret data), and we
// catch it at compile time by limiting the impl to the Ct variant —
// matches fixed-bigint's choice to only impl it for FixedUInt<_, _, Ct>.
impl<M: Modulus> ConditionallySelectable for Mont<M, Ct> {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self::from_mont_raw(u32::conditional_select(&a.inner, &b.inner, choice))
    }
}

// ---------------------------------------------------------------------------
// MontMath<M> — abstraction over Mont<M, Nct> and Mont<M, Ct>
// ---------------------------------------------------------------------------

/// A common surface over `Mont<M, Nct>` and `Mont<M, Ct>` so callers (the
/// NTT, matrix multiply, samplers) can be generic over the personality.
///
/// Inherent methods on `Mont<M, Nct>` and `Mont<M, Ct>` are defined on
/// *disjoint* types, so a generic function `fn f<P>(m: Mont<M, P>)` can't
/// call `m.mul(...)` directly. This trait wraps the per-personality
/// bodies so a single generic NTT body can dispatch correctly at
/// compile time.
pub trait MontMath<M: Modulus>: Sized + Copy {
    fn from_raw(raw: u32) -> Self;
    fn to_raw(self) -> u32;
    fn from_mont_raw(inner: u32) -> Self;
    fn to_mont_raw(self) -> u32;
    fn zero() -> Self;
    fn one() -> Self;
    fn mul(self, other: Self) -> Self;
    fn add(self, other: Self) -> Self;
    fn sub(self, other: Self) -> Self;
    /// Negate: `0 - self` in Mont form.
    fn neg(self) -> Self {
        Self::zero().sub(self)
    }
}

impl<M: Modulus> MontMath<M> for Mont<M, Nct> {
    fn from_raw(raw: u32) -> Self {
        Mont::<M, Nct>::from_raw(raw)
    }
    fn to_raw(self) -> u32 {
        Mont::<M, Nct>::to_raw(self)
    }
    fn from_mont_raw(inner: u32) -> Self {
        Mont::<M, Nct>::from_mont_raw(inner)
    }
    fn to_mont_raw(self) -> u32 {
        Mont::<M, Nct>::to_mont_raw(self)
    }
    fn zero() -> Self {
        Mont::<M, Nct>::zero()
    }
    fn one() -> Self {
        Mont::<M, Nct>::one()
    }
    fn mul(self, other: Self) -> Self {
        Mont::<M, Nct>::mul(self, other)
    }
    fn add(self, other: Self) -> Self {
        Mont::<M, Nct>::add(self, other)
    }
    fn sub(self, other: Self) -> Self {
        Mont::<M, Nct>::sub(self, other)
    }
}

impl<M: Modulus> MontMath<M> for Mont<M, Ct> {
    fn from_raw(raw: u32) -> Self {
        Mont::<M, Ct>::from_raw(raw)
    }
    fn to_raw(self) -> u32 {
        Mont::<M, Ct>::to_raw(self)
    }
    fn from_mont_raw(inner: u32) -> Self {
        Mont::<M, Ct>::from_mont_raw(inner)
    }
    fn to_mont_raw(self) -> u32 {
        Mont::<M, Ct>::to_mont_raw(self)
    }
    fn zero() -> Self {
        Mont::<M, Ct>::zero()
    }
    fn one() -> Self {
        Mont::<M, Ct>::one()
    }
    fn mul(self, other: Self) -> Self {
        Mont::<M, Ct>::mul(self, other)
    }
    fn add(self, other: Self) -> Self {
        Mont::<M, Ct>::add(self, other)
    }
    fn sub(self, other: Self) -> Self {
        Mont::<M, Ct>::sub(self, other)
    }
}
