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
//! Deterministic entry points use [`KeyGenSeed`] and [`SigningRandomness`]
//! newtypes to prevent buffer transposition at the call site.

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

/// 32-byte seed `ξ` for ML-DSA deterministic key generation.
///
/// Zero-cost newtype over `[u8; 32]` that prevents accidental substitution
/// of a key-derivation output, symmetric key, or hash digest for the keygen seed.
pub struct KeyGenSeed(pub [u8; 32]);

impl zeroize::Zeroize for KeyGenSeed {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl From<[u8; 32]> for KeyGenSeed {
    fn from(b: [u8; 32]) -> Self {
        Self(b)
    }
}

/// 32-byte per-signature randomness `rnd` for ML-DSA sign.
///
/// Zero-cost newtype over `[u8; 32]` that prevents accidental use of a
/// keygen seed or hash output in the signing randomness slot.
pub struct SigningRandomness(pub [u8; 32]);

impl zeroize::Zeroize for SigningRandomness {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl From<[u8; 32]> for SigningRandomness {
    fn from(b: [u8; 32]) -> Self {
        Self(b)
    }
}

/// FIPS 204 §5.2 / §5.4 domain-separation header for the message representative M'.
///
/// Bundles `flag || |ctx| || ctx` (and `oid || PHM(M)` for [`PreHashed`][DomainSeparator::PreHashed])
/// so the per-set facades never scatter 1-byte stack arrays across call sites and ctx-length
/// validation happens in one place.
pub(crate) enum DomainSeparator<'a> {
    /// Pure ML-DSA domain: flag byte `0x00`.
    Pure { header: [u8; 2], ctx: &'a [u8] },
    /// HashML-DSA domain: flag byte `0x01`, with DER OID and pre-hash digest.
    PreHashed {
        header: [u8; 2],
        ctx: &'a [u8],
        oid: &'static [u8],
        digest: &'a [u8],
    },
}

impl<'a> DomainSeparator<'a> {
    /// Returns `None` if `ctx.len() > 255`.
    pub fn pure(ctx: &'a [u8]) -> Option<Self> {
        if ctx.len() > 255 {
            return None;
        }
        Some(Self::Pure {
            header: [0x00, ctx.len() as u8],
            ctx,
        })
    }

    /// Returns `None` if `ctx.len() > 255`.
    pub fn pre_hashed(ctx: &'a [u8], oid: &'static [u8], digest: &'a [u8]) -> Option<Self> {
        if ctx.len() > 255 {
            return None;
        }
        Some(Self::PreHashed {
            header: [0x01, ctx.len() as u8],
            ctx,
            oid,
            digest,
        })
    }

    /// M' piece list for [`internal::sign_internal_impl_pieces`][crate::internal::sign_internal_impl_pieces]
    /// and the verify counterpart.
    ///
    /// For `Pure`, `m` is the caller message. For `PreHashed`, `m` is unused
    /// (the digest is already carried in the variant). Returns the piece array and valid count.
    pub fn pieces<'b>(&'b self, m: &'b [u8]) -> ([&'b [u8]; 4], usize) {
        match self {
            Self::Pure { header, ctx } => ([header, ctx, m, &[]], 3),
            Self::PreHashed {
                header,
                ctx,
                oid,
                digest,
            } => ([header, ctx, oid, digest], 4),
        }
    }
}

#[doc(inline)]
pub use encoding::EncodeError;

pub use rustcrypto::{Dk, Ek, MlKem, MlKem512, MlKem768, MlKem1024, MlKemParams};
pub use rustcrypto::{
    MlDsa44, MlDsa65, MlDsa87, MlDsaParams, MlDsaSignature, MlDsaSigner, MlDsaVerifier,
};

/// Pre-hash selector for HashML-DSA ([`ml_dsa_44::hash_sign`] /
/// [`ml_dsa_44::hash_verify`] and their `-65` / `-87` equivalents).
///
/// Pairs the externally-computed digest with its FIPS 204 §5.4 Table 3
/// DER-encoded OID. Named constructors cover the six most common algorithms;
/// `PreHash::new` accepts any OID for the remaining FIPS-approved pre-hashes.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PreHash<'a> {
    oid: &'static [u8],
    digest: &'a [u8],
}

// Converts a const-oid `ObjectIdentifier` whose arc encoding is exactly 9 bytes
// (all FIPS 204 §5.4 Table 3 SHA-2/SHA-3 OIDs) into a DER-encoded `[u8; 11]`
// (tag 0x06, length 0x09, then the 9 arc bytes).  The assert fires at compile
// time if the OID has a different arc-byte length.
const fn oid_der<const N: usize>(oid: &const_oid::ObjectIdentifier) -> [u8; N] {
    let arc = oid.as_bytes();
    assert!(
        arc.len() + 2 == N,
        "OID arc length does not match expected DER size"
    );
    let mut out = [0u8; N];
    out[0] = 0x06;
    out[1] = arc.len() as u8;
    let mut i = 0;
    while i < arc.len() {
        out[i + 2] = arc[i];
        i += 1;
    }
    out
}

impl<'a> PreHash<'a> {
    // FIPS 204 §5.4 Table 3 — DER-encoded OIDs derived from human-readable arc strings.
    // Arc strings are cross-checkable against the NIST / IANA OID registry.
    const DER_SHA256: [u8; 11] = oid_der(&const_oid::ObjectIdentifier::new_unwrap(
        "2.16.840.1.101.3.4.2.1",
    ));
    const DER_SHA384: [u8; 11] = oid_der(&const_oid::ObjectIdentifier::new_unwrap(
        "2.16.840.1.101.3.4.2.2",
    ));
    const DER_SHA512: [u8; 11] = oid_der(&const_oid::ObjectIdentifier::new_unwrap(
        "2.16.840.1.101.3.4.2.3",
    ));
    const DER_SHA512_256: [u8; 11] = oid_der(&const_oid::ObjectIdentifier::new_unwrap(
        "2.16.840.1.101.3.4.2.6",
    ));
    const DER_SHA3_256: [u8; 11] = oid_der(&const_oid::ObjectIdentifier::new_unwrap(
        "2.16.840.1.101.3.4.2.8",
    ));
    const DER_SHA3_384: [u8; 11] = oid_der(&const_oid::ObjectIdentifier::new_unwrap(
        "2.16.840.1.101.3.4.2.9",
    ));
    const DER_SHA3_512: [u8; 11] = oid_der(&const_oid::ObjectIdentifier::new_unwrap(
        "2.16.840.1.101.3.4.2.10",
    ));
    const DER_SHAKE128: [u8; 11] = oid_der(&const_oid::ObjectIdentifier::new_unwrap(
        "2.16.840.1.101.3.4.2.11",
    ));
    const DER_SHAKE256: [u8; 11] = oid_der(&const_oid::ObjectIdentifier::new_unwrap(
        "2.16.840.1.101.3.4.2.12",
    ));

    pub const OID_SHA256: &'static [u8] = &Self::DER_SHA256;
    pub const OID_SHA384: &'static [u8] = &Self::DER_SHA384;
    pub const OID_SHA512: &'static [u8] = &Self::DER_SHA512;
    pub const OID_SHA512_256: &'static [u8] = &Self::DER_SHA512_256;
    pub const OID_SHA3_256: &'static [u8] = &Self::DER_SHA3_256;
    pub const OID_SHA3_384: &'static [u8] = &Self::DER_SHA3_384;
    pub const OID_SHA3_512: &'static [u8] = &Self::DER_SHA3_512;
    pub const OID_SHAKE128: &'static [u8] = &Self::DER_SHAKE128;
    pub const OID_SHAKE256: &'static [u8] = &Self::DER_SHAKE256;

    /// Generic constructor for any FIPS 204-approved OID.
    pub const fn new(oid: &'static [u8], digest: &'a [u8]) -> Self {
        Self { oid, digest }
    }

    pub const fn sha256(digest: &'a [u8; 32]) -> Self {
        Self {
            oid: Self::OID_SHA256,
            digest,
        }
    }
    pub const fn sha384(digest: &'a [u8; 48]) -> Self {
        Self {
            oid: Self::OID_SHA384,
            digest,
        }
    }
    pub const fn sha512(digest: &'a [u8; 64]) -> Self {
        Self {
            oid: Self::OID_SHA512,
            digest,
        }
    }
    pub const fn sha3_256(digest: &'a [u8; 32]) -> Self {
        Self {
            oid: Self::OID_SHA3_256,
            digest,
        }
    }
    pub const fn sha3_384(digest: &'a [u8; 48]) -> Self {
        Self {
            oid: Self::OID_SHA3_384,
            digest,
        }
    }
    pub const fn sha3_512(digest: &'a [u8; 64]) -> Self {
        Self {
            oid: Self::OID_SHA3_512,
            digest,
        }
    }

    pub fn oid(&self) -> &'static [u8] {
        self.oid
    }
    pub fn digest(&self) -> &[u8] {
        self.digest
    }
}

/// Error from the deterministic sign path: [`ml_dsa_44::sign`] /
/// [`ml_dsa_44::hash_sign`] and their `-65` / `-87` equivalents.
///
/// * [`MessageError::CtxTooLong`] — `ctx` exceeds the FIPS 204 §5.2 limit of 255 bytes.
/// * [`MessageError::Encode`] — structural buffer / codec mismatch; unreachable in practice
///   for in-tree const-sized inputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MessageError {
    CtxTooLong,
    Encode(encoding::EncodeError),
}

impl From<encoding::EncodeError> for MessageError {
    fn from(e: encoding::EncodeError) -> Self {
        MessageError::Encode(e)
    }
}

/// Error returned by the RNG-driven [`ml_dsa_44::sign_random`] /
/// [`ml_dsa_44::hash_sign_random`] entry points on each per-set facade.
///
/// * [`SignError::Message`] — a message-level failure; see [`MessageError`].
/// * [`SignError::Rng`] — the RNG returned an error while sampling the
///   per-signature 32-byte randomness input. `E` is the RNG's own error type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SignError<E> {
    Message(MessageError),
    Rng(E),
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
