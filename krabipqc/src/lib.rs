#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

//! `no_std` ML-DSA (FIPS 204) and ML-KEM (FIPS 203) for microcontrollers.
//! Byte-for-byte ACVP-conformant on all six parameter sets.
//!
//! # Quick start
//!
//! ```ignore
//! use krabipqc::{MlDsaSigner, MlDsaVerifier, MlDsa44};
//! use kem::common::Generate;
//! use signature::{RandomizedSigner, Verifier};
//!
//! // Key generation (RNG-driven; fixed seed via ml_dsa_44::keygen_from_seed).
//! let mut rng = /* your TryCryptoRng */;
//! let signer: MlDsaSigner<MlDsa44> = MlDsaSigner::try_generate_from_rng(&mut rng).unwrap();
//! let verifier: MlDsaVerifier<MlDsa44> = signer.verifying_key();
//!
//! let sig = signer.try_sign_with_rng(&mut rng, b"hello mldsa").unwrap();
//! verifier.verify(b"hello mldsa", &sig).unwrap();
//! ```
//!
//! Swap `MlDsa44` for [`MlDsa65`] or [`MlDsa87`] to change the parameter set;
//! the rest of the code is identical.
//!
//! For ML-KEM use [`Dk<MlKem512>`][`Dk`] / [`Ek<MlKem512>`][`Ek`] via the
//! [`kem`] trait family (`Generate`, `Encapsulate`, `TryDecapsulate`).
//!
//! For protocols that pre-hash the message (TLS 1.3 CertificateVerify
//! per `draft-ietf-tls-mldsa`), use `hash_sign` / `hash_verify` on the
//! per-set facades ([`ml_dsa_44`] etc.) with a [`PreHash`] selector.
//!
//! RNG-driven entry points ([`ml_dsa_44::keygen`],
//! [`ml_dsa_44::sign_random`], [`ml_dsa_44::hash_sign_random`]) take
//! a [`rand_core::TryCryptoRng`] so fallible embedded HW RNGs
//! propagate their error type via [`SignError::Rng`].

pub(crate) mod blinding;
pub(crate) mod encoding;
pub(crate) mod field_ext;
pub(crate) mod hashing;
pub(crate) mod internal;
mod ml_dsa;
mod ml_kem;
pub(crate) mod mlkem;
pub(crate) mod ntt;
pub(crate) mod params;
pub(crate) mod poly;
pub(crate) mod polyvec;
pub(crate) mod rounding;
mod rustcrypto;
pub(crate) mod sampling;

pub use ml_dsa::{ml_dsa_44, ml_dsa_65, ml_dsa_87};
pub use ml_kem::{ml_kem_512, ml_kem_768, ml_kem_1024};

#[doc(inline)]
pub use encoding::EncodeError;

pub use rustcrypto::{Dk, Ek, MlKem, MlKem512, MlKem768, MlKem1024, MlKemParams};
pub use rustcrypto::{
    MlDsa44, MlDsa65, MlDsa87, MlDsaParams, MlDsaSignature, MlDsaSigner, MlDsaVerifier,
};

/// Pre-hash selector for HashML-DSA ([`ml_dsa_44::hash_sign`] /
/// [`ml_dsa_44::hash_verify`] and their `-65` / `-87` equivalents).
/// Carries the externally-computed digest and the OID family the
/// verifier binds it to.
///
/// SHA-256 and SHA-512 cover the digests used by TLS 1.3 + ML-DSA
/// CertificateVerify (draft-ietf-tls-mldsa). FIPS 204 §5.4 Table 3
/// also approves SHA3-{256,384,512}, SHA-384, and SHAKE-128/256
/// pre-hashes; signatures produced with those algorithms cannot be
/// verified through this API.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum PreHash {
    /// SHA-256 pre-hash, OID 2.16.840.1.101.3.4.2.1.
    Sha256([u8; 32]),
    /// SHA-512 pre-hash, OID 2.16.840.1.101.3.4.2.3.
    Sha512([u8; 64]),
}

/// Error returned by the RNG-wrapped `sign_random` /
/// `hash_sign_random` entry points on each per-set facade.
///
/// * [`SignError::CtxTooLong`] — caller-supplied `ctx` exceeded the
///   FIPS 204 §5.2 limit of 255 bytes.
/// * [`SignError::Rng`] — the RNG returned an error while sampling
///   the per-signature 32-byte randomness input. `E` is the RNG's own
///   error type.
/// * [`SignError::Encode`] — a structural buffer / codec mismatch.
///   Unreachable in practice once the per-set facade has pinned sk /
///   sig sizes via const generics; surfaced rather than panicked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SignError<E> {
    CtxTooLong,
    Rng(E),
    Encode(encoding::EncodeError),
}

impl<E> From<encoding::EncodeError> for SignError<E> {
    fn from(e: encoding::EncodeError) -> Self {
        SignError::Encode(e)
    }
}

/// Error returned by the RNG-driven entry points on each per-set facade:
/// [`ml_dsa_44::keygen`], [`ml_kem_512::keygen`], [`ml_kem_512::encaps`],
/// and their `-65` / `-87` / `-768` / `-1024` equivalents.
///
/// * [`RandError::Rng`] — the RNG returned an error while sampling the
///   random input. `E` is the RNG's own error type.
/// * [`RandError::Encode`] — a structural buffer / codec mismatch.
///   Unreachable in practice once the per-set facade has pinned all
///   buffer sizes via const generics; surfaced rather than panicked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RandError<E> {
    Rng(E),
    Encode(encoding::EncodeError),
}

impl<E> From<encoding::EncodeError> for RandError<E> {
    fn from(e: encoding::EncodeError) -> Self {
        RandError::Encode(e)
    }
}
