//! RustCrypto trait impls for ML-KEM and ML-DSA.
//!
//! * ML-KEM-{512, 768, 1024} implement [`kem::Kem`] via per-set
//!   [`MlKem512`] / [`MlKem768`] / [`MlKem1024`] marker types with
//!   `Dk*` / `Ek*` byte-array wrappers around the FIPS 203 dk / ek
//!   encodings.
//! * ML-DSA-{44, 65, 87} implement [`signature::Signer`] /
//!   [`signature::Verifier`] / [`signature::RandomizedSigner`] /
//!   [`signature::Keypair`] via per-set `MlDsaN{Signer,Verifier,
//!   Signature}` wrappers around the FIPS 204 sk / pk / sig
//!   encodings.
//!
//! Trait methods route through the corresponding [`crate::ml_kem_512`] /
//! [`crate::ml_dsa_44`] / etc. facades. Some kem / signature trait
//! signatures are infallible (`Decapsulate::decapsulate`,
//! `Encapsulate::encapsulate_with_rng`, `Generate::try_generate_from_rng`
//! whose error type is the RNG's, etc.) while the facade returns
//! `Result<_, EncodeError>` — those crossings document the
//! structurally-unreachable Encode arm and use `.expect` so a
//! mismatched const-generic pinning would surface loudly in debug
//! rather than corrupt silently.

use core::fmt;

use kem::common::array::{Array, sizes};
use kem::common::typenum::{Unsigned, consts::U32};
use kem::{
    Decapsulator, Encapsulate, Generate, Kem, KeyExport, KeyInit, KeySizeUser, TryDecapsulate,
    TryKeyInit,
};
use rand_core::{CryptoRng, TryCryptoRng};
use zeroize::Zeroizing;

// ============================================================================
// ML-KEM
// ============================================================================

/// Glue from the kem::Kem family of traits to a per-set ML-KEM facade.
/// Bodies are identical across sets modulo sizes / facade path.
macro_rules! impl_mlkem_kem {
    (
        $kem_marker:ident, $dk_struct:ident, $ek_struct:ident,
        $ek_size:ident, $dk_size:ident, $ct_size:ident,
        $facade:ident, $k:literal,
    ) => {
        /// Marker type for ML-KEM-N's `kem::Kem` impl. Sk / ek / ct sizes
        /// live in the associated types.
        #[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
        pub struct $kem_marker;

        /// Decapsulation key (the secret-side ML-KEM byte-encoded `dk`).
        /// Caches the embedded ek so `Decapsulator::encapsulation_key`
        /// returns `&Self::EncapsulationKey` without re-parsing.
        #[derive(Clone)]
        pub struct $dk_struct {
            sk: Zeroizing<Array<u8, sizes::$dk_size>>,
            ek: $ek_struct,
        }

        impl $dk_struct {
            const SK_LEN: usize = <sizes::$dk_size as Unsigned>::USIZE;
            const EK_LEN: usize = <sizes::$ek_size as Unsigned>::USIZE;
            const DK_PKE_LEN: usize = Self::SK_LEN - Self::EK_LEN - 32 - 32;
        }

        impl fmt::Debug for $dk_struct {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_struct(stringify!($dk_struct))
                    .field("sk", &"<secret>")
                    .field("ek", &self.ek)
                    .finish()
            }
        }

        /// Encapsulation key (the public-side ML-KEM byte-encoded `ek`).
        #[derive(Clone, Debug, PartialEq, Eq)]
        pub struct $ek_struct {
            ek: Array<u8, sizes::$ek_size>,
        }

        impl Kem for $kem_marker {
            type DecapsulationKey = $dk_struct;
            type EncapsulationKey = $ek_struct;
            type SharedKeySize = U32;
            type CiphertextSize = sizes::$ct_size;
        }

        impl KeySizeUser for $ek_struct {
            type KeySize = sizes::$ek_size;
        }

        // No infallible `KeyInit` for the public-side ek: peer-supplied
        // bytes have to pass the FIPS 203 §7.2 modulus check, so the
        // only construction path from a `Key` is fallible.
        impl TryKeyInit for $ek_struct {
            fn new(key: &Array<u8, sizes::$ek_size>) -> Result<Self, kem::InvalidKey> {
                let ek_pke = &key[..384 * $k];
                crate::mlkem::encoding::ek_modulus_check::<$k>(ek_pke)
                    .map_err(|_| kem::InvalidKey)?;
                Ok(Self { ek: key.clone() })
            }
        }

        impl KeyExport for $ek_struct {
            fn to_bytes(&self) -> Array<u8, sizes::$ek_size> {
                self.ek.clone()
            }
        }

        impl KeySizeUser for $dk_struct {
            type KeySize = sizes::$dk_size;
        }

        // Symmetric with `Ek*::TryKeyInit`: peer-supplied dk bytes embed
        // an ek that must satisfy the FIPS 203 §7.2 modulus check, else
        // `Dk::encapsulation_key()` would silently hand out a
        // non-canonical Ek that the corresponding `Ek::new` would reject.
        // No infallible `KeyInit` for the same reason — drops the auto
        // `kem::FromSeed` blanket; deterministic-seed construction goes
        // through `try_generate_from_rng` or the facade keygen instead.
        impl TryKeyInit for $dk_struct {
            fn new(key: &Array<u8, sizes::$dk_size>) -> Result<Self, kem::InvalidKey> {
                let mut ek_bytes = Array::<u8, sizes::$ek_size>::default();
                let ek_start = Self::DK_PKE_LEN;
                let ek_end = ek_start + Self::EK_LEN;
                ek_bytes.copy_from_slice(&key[ek_start..ek_end]);
                let ek = <$ek_struct as TryKeyInit>::new(&ek_bytes)?;
                Ok(Self {
                    sk: Zeroizing::new(key.clone()),
                    ek,
                })
            }
        }

        impl Generate for $dk_struct {
            fn try_generate_from_rng<R: TryCryptoRng + ?Sized>(
                rng: &mut R,
            ) -> Result<Self, R::Error> {
                // The trait error type is fixed to R::Error, but our
                // facade keygen returns KemError<R::Error>. Draw the
                // seeds locally so any structurally-unreachable Encode
                // arm from keygen_internal stays out of the trait's
                // error channel.
                let mut d = Zeroizing::new([0u8; 32]);
                let mut z = Zeroizing::new([0u8; 32]);
                rng.try_fill_bytes(&mut *d)?;
                rng.try_fill_bytes(&mut *z)?;
                // TODO: drop .expect — trait's R::Error can't carry EncodeError without a breaking where bound.
                let (ek_bytes, sk_bytes) = crate::$facade::keygen_internal(&d, &z)
                    .expect("keygen_internal infallible on facade-pinned buffer sizes");
                let ek = $ek_struct {
                    ek: Array::from(ek_bytes),
                };
                let sk = Zeroizing::new(Array::from(sk_bytes));
                Ok(Self { sk, ek })
            }
        }

        impl Decapsulator for $dk_struct {
            type Kem = $kem_marker;

            fn encapsulation_key(&self) -> &$ek_struct {
                &self.ek
            }
        }

        // Only `TryDecapsulate` (not the infallible `Decapsulate`) so the
        // facade's structural EncodeError surfaces as an Err instead of
        // panicking. Callers reach for `try_decapsulate` directly.
        impl TryDecapsulate for $dk_struct {
            type Error = crate::EncodeError;

            fn try_decapsulate(
                &self,
                ct: &Array<u8, sizes::$ct_size>,
            ) -> Result<Array<u8, U32>, Self::Error> {
                let sk_arr: &[u8; crate::$facade::DK_BYTES] = (&*self.sk).into();
                let ct_arr: &[u8; crate::$facade::CT_BYTES] = ct.into();
                let ss = crate::$facade::decaps_internal(sk_arr, ct_arr)?;
                Ok(Array::from(ss))
            }
        }

        impl Encapsulate for $ek_struct {
            type Kem = $kem_marker;

            fn encapsulate_with_rng<R>(
                &self,
                rng: &mut R,
            ) -> (Array<u8, sizes::$ct_size>, Array<u8, U32>)
            where
                R: CryptoRng + ?Sized,
            {
                let ek_arr: &[u8; crate::$facade::EK_BYTES] = (&self.ek).into();
                let mut m = Zeroizing::new([0u8; 32]);
                rand_core::Rng::fill_bytes(rng, &mut *m);
                // TODO: drop .expect — needs const-generic Params buffer sizes + CanonicalEk typestate.
                let (ss_bytes, ct_bytes) = crate::$facade::encaps_internal(ek_arr, &m)
                    .expect("encaps_internal infallible: ek validated, buffers pinned");
                (Array::from(ct_bytes), Array::from(ss_bytes))
            }
        }
    };
}

impl_mlkem_kem!(MlKem512, Dk512, Ek512, U800, U1632, U768, ml_kem_512, 2,);
impl_mlkem_kem!(MlKem768, Dk768, Ek768, U1184, U2400, U1088, ml_kem_768, 3,);
impl_mlkem_kem!(
    MlKem1024,
    Dk1024,
    Ek1024,
    U1568,
    U3168,
    U1568,
    ml_kem_1024,
    4,
);

// ============================================================================
// ML-DSA
// ============================================================================

use signature::{Error as SigError, Keypair, RandomizedSigner, Signer, Verifier};

/// Glue from the signature::{Signer, Verifier, RandomizedSigner,
/// Keypair} family to a per-set ML-DSA facade. The RustCrypto traits
/// don't model ctx-string signing, so the impls below always pass
/// `ctx = []`. Callers needing non-empty ctx or HashML-DSA should
/// reach the facade fns directly.
macro_rules! impl_mldsa_sig {
    (
        $signer:ident, $verifier:ident, $sig:ident,
        $pk_size:ident, $sk_size:ident, $sig_size:ident,
        $facade:ident,
    ) => {
        /// Byte-encoded ML-DSA signature wrapper.
        #[derive(Clone, Debug, PartialEq, Eq)]
        pub struct $sig(Array<u8, sizes::$sig_size>);

        impl AsRef<[u8]> for $sig {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }

        impl From<Array<u8, sizes::$sig_size>> for $sig {
            fn from(a: Array<u8, sizes::$sig_size>) -> Self {
                Self(a)
            }
        }

        impl TryFrom<&[u8]> for $sig {
            type Error = SigError;
            fn try_from(bytes: &[u8]) -> Result<Self, SigError> {
                Array::try_from(bytes)
                    .map(Self)
                    .map_err(|_| SigError::new())
            }
        }

        /// Verifier (public key holder) for ML-DSA-N.
        #[derive(Clone, Debug, PartialEq, Eq)]
        pub struct $verifier {
            pk: Array<u8, sizes::$pk_size>,
        }

        impl KeySizeUser for $verifier {
            type KeySize = sizes::$pk_size;
        }

        impl KeyInit for $verifier {
            fn new(key: &Array<u8, sizes::$pk_size>) -> Self {
                Self { pk: key.clone() }
            }
        }

        impl KeyExport for $verifier {
            fn to_bytes(&self) -> Array<u8, sizes::$pk_size> {
                self.pk.clone()
            }
        }

        impl Verifier<$sig> for $verifier {
            fn verify(&self, msg: &[u8], signature: &$sig) -> Result<(), SigError> {
                let pk_arr: &[u8; crate::$facade::PK_BYTES] = (&self.pk).into();
                let sig_arr: &[u8; crate::$facade::SIG_BYTES] = (&signature.0).into();
                if crate::$facade::verify(pk_arr, msg, &[], sig_arr) {
                    Ok(())
                } else {
                    Err(SigError::new())
                }
            }
        }

        /// Signer (secret key holder) for ML-DSA-N. Caches the
        /// verifying key alongside the sk so `Keypair::verifying_key`
        /// doesn't have to re-derive it.
        #[derive(Clone)]
        pub struct $signer {
            sk: Zeroizing<Array<u8, sizes::$sk_size>>,
            vk: $verifier,
        }

        impl fmt::Debug for $signer {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_struct(stringify!($signer))
                    .field("sk", &"<secret>")
                    .field("vk", &self.vk)
                    .finish()
            }
        }

        impl $signer {
            /// Build a Signer from the byte-encoded (sk, pk) pair.
            /// FIPS 204 sk does not contain the literal pk bytes, so
            /// the caller has to supply both halves; this is the
            /// natural counterpart to `keygen` which returns them
            /// together.
            pub fn from_keypair(
                sk: &Array<u8, sizes::$sk_size>,
                pk: &Array<u8, sizes::$pk_size>,
            ) -> Self {
                Self {
                    sk: Zeroizing::new(sk.clone()),
                    vk: $verifier { pk: pk.clone() },
                }
            }
        }

        impl Keypair for $signer {
            type VerifyingKey = $verifier;
            fn verifying_key(&self) -> Self::VerifyingKey {
                self.vk.clone()
            }
        }

        impl Signer<$sig> for $signer {
            fn try_sign(&self, msg: &[u8]) -> Result<$sig, SigError> {
                let sk_arr: &[u8; crate::$facade::SK_BYTES] = (&*self.sk).into();
                let rnd = [0u8; 32]; // deterministic; ctx = empty
                let bytes =
                    crate::$facade::sign(sk_arr, msg, &[], &rnd).map_err(|_| SigError::new())?;
                Ok($sig(Array::from(bytes)))
            }
        }

        impl RandomizedSigner<$sig> for $signer {
            fn try_sign_with_rng<R: TryCryptoRng + ?Sized>(
                &self,
                rng: &mut R,
                msg: &[u8],
            ) -> Result<$sig, SigError> {
                let sk_arr: &[u8; crate::$facade::SK_BYTES] = (&*self.sk).into();
                let bytes = crate::$facade::sign_random(sk_arr, msg, &[], rng)
                    .map_err(|_| SigError::new())?;
                Ok($sig(Array::from(bytes)))
            }
        }

        impl Generate for $signer {
            fn try_generate_from_rng<R: TryCryptoRng + ?Sized>(
                rng: &mut R,
            ) -> Result<Self, R::Error> {
                // Same shape as the ML-KEM Dk Generate impl: bypass
                // the facade's KeyGenError-returning keygen so the
                // structurally-unreachable Encode arm doesn't have to
                // squeeze through R::Error.
                let mut xi = Zeroizing::new([0u8; 32]);
                rng.try_fill_bytes(&mut *xi)?;
                // TODO: drop .expect — trait's R::Error can't carry EncodeError without a breaking where bound.
                let (pk_bytes, sk_bytes) = crate::$facade::keygen_internal(&xi)
                    .expect("keygen_internal infallible on facade-pinned buffer sizes");
                Ok(Self {
                    sk: Zeroizing::new(Array::from(sk_bytes)),
                    vk: $verifier {
                        pk: Array::from(pk_bytes),
                    },
                })
            }
        }
    };
}

impl_mldsa_sig!(
    MlDsa44Signer,
    MlDsa44Verifier,
    MlDsa44Signature,
    U1312,
    U2560,
    U2420,
    ml_dsa_44,
);

impl_mldsa_sig!(
    MlDsa65Signer,
    MlDsa65Verifier,
    MlDsa65Signature,
    U1952,
    U4032,
    U3309,
    ml_dsa_65,
);

impl_mldsa_sig!(
    MlDsa87Signer,
    MlDsa87Verifier,
    MlDsa87Signature,
    U2592,
    U4896,
    U4627,
    ml_dsa_87,
);

#[cfg(test)]
mod tests {
    use super::*;
    use core::convert::Infallible;

    /// Deterministic fixed RNG so tests stay reproducible. Implements
    /// `TryCryptoRng<Error = Infallible>`, which rand_core's blanket
    /// impls lift to `CryptoRng` for the trait methods bounded on the
    /// infallible variant.
    struct FixedRng(u8);
    impl rand_core::TryRng for FixedRng {
        type Error = Infallible;
        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Ok(u32::from_le_bytes([self.0; 4]))
        }
        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            Ok(u64::from_le_bytes([self.0; 8]))
        }
        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
            dst.fill(self.0);
            Ok(())
        }
    }
    impl rand_core::TryCryptoRng for FixedRng {}

    /// ML-KEM-512 round-trip via the Kem trait family.
    #[test]
    fn mlkem512_roundtrip_via_traits() {
        let mut rng = FixedRng(0x42);
        let dk = Dk512::try_generate_from_rng(&mut rng).unwrap();
        let ek = dk.encapsulation_key().clone();

        let mut crng = FixedRng(0x77);
        let (ct, ss_send) = ek.encapsulate_with_rng(&mut crng);
        let ss_recv = dk.try_decapsulate(&ct).unwrap();
        assert_eq!(ss_send, ss_recv);
    }

    /// ML-DSA-44 round-trip via the signature trait family.
    #[test]
    fn mldsa44_roundtrip_via_traits() {
        let mut rng = FixedRng(0x42);
        let signer = MlDsa44Signer::try_generate_from_rng(&mut rng).unwrap();
        let verifier = signer.verifying_key();

        let msg = b"hello pqc traits";
        let sig: MlDsa44Signature = signer.sign(msg);
        verifier.verify(msg, &sig).expect("verify should pass");

        let wrong = b"hello rust crypto";
        verifier
            .verify(wrong, &sig)
            .expect_err("verify should fail on wrong msg");
    }

    /// Randomized signing path produces a verifiable signature.
    #[test]
    fn mldsa65_randomized_roundtrip_via_traits() {
        let mut rng = FixedRng(0x99);
        let signer = MlDsa65Signer::try_generate_from_rng(&mut rng).unwrap();
        let verifier = signer.verifying_key();

        let mut crng = FixedRng(0x55);
        let msg = b"randomized";
        let sig: MlDsa65Signature = signer.sign_with_rng(&mut crng, msg);
        verifier.verify(msg, &sig).expect("verify should pass");
    }

    /// Non-canonical ek (first t_hat coefficient forged to 0xFFF > q)
    /// must be rejected at TryKeyInit so the infallible Encapsulate
    /// trait can't be reached with an invalid key.
    #[test]
    fn mlkem512_trykeyinit_rejects_non_canonical_ek() {
        let mut rng = FixedRng(0x42);
        let dk = Dk512::try_generate_from_rng(&mut rng).unwrap();
        let mut bytes: Array<u8, sizes::U800> = dk.ek.ek;
        // Pack the first 12-bit coefficient as 0xFFF (4095, > q = 3329).
        bytes[0] = 0xFF;
        bytes[1] = (bytes[1] & 0xF0) | 0x0F;
        assert!(<Ek512 as TryKeyInit>::new(&bytes).is_err());
    }

    /// Symmetric with the Ek test: a Dk byte blob with a non-canonical
    /// embedded ek must be rejected at TryKeyInit; otherwise Dk's
    /// `encapsulation_key()` would silently surface an invalid Ek.
    #[test]
    fn mlkem512_trykeyinit_dk_rejects_non_canonical_embedded_ek() {
        let mut rng = FixedRng(0x42);
        let dk_good = Dk512::try_generate_from_rng(&mut rng).unwrap();
        let mut bytes: Array<u8, sizes::U1632> = *dk_good.sk;
        // ek_pke starts at offset 384 * K = 768; first 12-bit coeff
        // sits at bytes 768..770.
        let ek_off = Dk512::DK_PKE_LEN;
        bytes[ek_off] = 0xFF;
        bytes[ek_off + 1] = (bytes[ek_off + 1] & 0xF0) | 0x0F;
        assert!(<Dk512 as TryKeyInit>::new(&bytes).is_err());
    }
}
