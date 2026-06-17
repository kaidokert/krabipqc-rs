#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

//! `no_std` ML-DSA (FIPS 204) keygen / sign / verify for all three
//! parameter sets — [`ml_dsa_44`], [`ml_dsa_65`], [`ml_dsa_87`].
//! Byte-for-byte ACVP-conformant on the `keyGen`, `sigGen`, and
//! `sigVer` test vectors.
//!
//! # Quick start
//!
//! ```ignore
//! use krabipqc::ml_dsa_44;
//!
//! let xi = [0x42u8; 32];
//! let (pk, sk) = ml_dsa_44::keygen_internal(&xi);
//!
//! let rnd = [0xC3u8; 32];
//! let sig = ml_dsa_44::sign(&sk, b"hello mldsa", b"app-ctx", &rnd).unwrap();
//!
//! assert!(ml_dsa_44::verify(&pk, b"hello mldsa", b"app-ctx", &sig));
//! ```
//!
//! For protocols that pre-hash the message (TLS 1.3 CertificateVerify
//! per `draft-ietf-tls-mldsa`), use `hash_sign` / `hash_verify` with a
//! [`ml_dsa_44::PreHash`] selector. For low-level control over `M'`,
//! the `*_internal` variants take the already-constructed `M'` as
//! `&[u8]`.
//!
//! RNG-driven entry points ([`ml_dsa_44::keygen`],
//! [`ml_dsa_44::sign_random`], [`ml_dsa_44::hash_sign_random`]) take
//! a [`rand_core::TryCryptoRng`] so fallible embedded HW RNGs
//! propagate their error type via [`SignError::Rng`].
//!
//! Each per-set facade exposes `*_ct` siblings that route NTT-domain
//! Mont arithmetic through `wide_montgomery_mul_ct` and use
//! [`subtle::ConditionallySelectable`] for conditional subtractions,
//! producing byte-identical pk/sk/sig and accept/reject decisions to
//! the default path. Time-domain post-processing (rejection samplers,
//! the `% gamma2` operations) is not yet constant-time — the `_ct`
//! suffix is a partial guarantee.

pub(crate) mod blinding;
pub(crate) mod encoding;
pub(crate) mod field_ext;
pub mod hashing;
pub(crate) mod internal;
mod ml_dsa;
pub(crate) mod ntt;
pub mod params;
pub mod poly;
pub mod polyvec;
pub(crate) mod rounding;
pub(crate) mod sampling;

pub use ml_dsa::{ml_dsa_44, ml_dsa_65, ml_dsa_87};

pub use fixed_bigint::{Ct, Nct, Personality};
pub use modmath::{Field, FieldCt, FieldNct, MontStorage, Residue, ResidueCt, ResidueNct};

/// Error returned by the RNG-wrapped `sign_random` /
/// `hash_sign_random` entry points on each per-set facade.
///
/// * [`SignError::CtxTooLong`] — caller-supplied `ctx` exceeded the
///   FIPS 204 §5.2 limit of 255 bytes.
/// * [`SignError::Rng`] — the RNG returned an error while sampling
///   the per-signature 32-byte randomness input. `E` is the RNG's own
///   error type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignError<E> {
    CtxTooLong,
    Rng(E),
}
