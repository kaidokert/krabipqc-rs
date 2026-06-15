#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

//! `no_std` math foundation for post-quantum cryptography.
//!
//! This crate is the substrate for the NIST PQC standards published in
//! FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA).
//!
//! # Layer responsibilities
//!
//! Modular arithmetic and Montgomery-domain operations are owned by
//! `modmath`; we re-export its [`Field`] / [`Residue`] typestate so
//! consumers can name them through `krabipqc::*`. The [`Personality`]
//! marker (`Nct` variable-time vs `Ct` constant-time via `subtle`) is
//! owned by `fixed_bigint`; we re-export the marker types as well so
//! the entire surface name-resolves under `krabipqc`.

pub mod hashing;
pub mod params;
pub mod poly;
pub mod polyvec;

pub use fixed_bigint::{Ct, Nct, Personality};
pub use modmath::{Field, FieldCt, FieldNct, MontStorage, Residue, ResidueCt, ResidueNct};
