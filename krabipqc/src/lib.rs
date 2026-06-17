#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

//! `no_std` ML-DSA verifier (FIPS 204, all three parameter sets).
//!
//! Parameter sets: [`ml_dsa_44`], [`ml_dsa_65`], [`ml_dsa_87`].
//! Byte-for-byte ACVP-conformant on the `sigVer` test vectors.
//!
//! # Quick start
//!
//! ```ignore
//! use krabipqc::ml_dsa_44;
//!
//! assert!(ml_dsa_44::verify(&pk, b"hello mldsa", b"app-ctx", &sig));
//! ```
//!
//! [`ml_dsa_44::verify_internal`] takes the FIPS 204 §5.2 message
//! representative `M'` directly, for callers that build `M'` outside
//! the crate (e.g. TLS 1.3 pre-hashed signatures).
//!
//! Each per-set facade exposes a `verify_ct` sibling that routes
//! NTT-domain Mont arithmetic through `wide_montgomery_mul_ct` and
//! uses [`subtle::ConditionallySelectable`] for conditional
//! subtractions, producing byte-identical accept/reject decisions to
//! the default `verify`.

pub mod encoding;
pub mod field_ext;
pub mod hashing;
pub mod internal;
mod ml_dsa;
pub mod ntt;
pub mod params;
pub mod poly;
pub mod polyvec;
pub mod rounding;
pub mod sampling;

pub use ml_dsa::{ml_dsa_44, ml_dsa_65, ml_dsa_87};

pub use fixed_bigint::{Ct, Nct, Personality};
pub use modmath::{Field, FieldCt, FieldNct, MontStorage, Residue, ResidueCt, ResidueNct};
