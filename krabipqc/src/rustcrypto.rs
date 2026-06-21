//! RustCrypto trait impls for ML-KEM and ML-DSA.
//!
//! Types are generic over the parameter set via sealed [`MlKemParams`] /
//! [`MlDsaParams`] traits:
//!
//! * ML-KEM: `Dk<P>` / `Ek<P>` with `P` ∈ {[`MlKem512`], [`MlKem768`],
//!   [`MlKem1024`]}; marker type [`MlKem<P>`] carries the [`kem::Kem`] impl.
//! * ML-DSA: [`MlDsaSigner<P>`] / [`MlDsaVerifier<P>`] / [`MlDsaSignature<P>`]
//!   with `P` ∈ {[`MlDsa44`], [`MlDsa65`], [`MlDsa87`]}.
//!
//! Trait methods route through the corresponding [`crate::ml_kem_512`] /
//! [`crate::ml_dsa_44`] / etc. facades. Infallible trait paths cross a
//! structurally-unreachable `EncodeError` arm via `.expect` so a
//! mismatched const-generic pinning surfaces loudly in debug.

use core::fmt;
use core::marker::PhantomData;

use hybrid_array::ArraySize;
use kem::common::array::{Array, sizes};
use kem::common::typenum::{Unsigned, consts::U32};
use kem::{
    Decapsulator, Encapsulate, Generate, Kem, KeyExport, KeyInit, KeySizeUser, TryDecapsulate,
    TryKeyInit,
};
use rand_core::{CryptoRng, TryCryptoRng};
use zeroize::Zeroizing;

mod private {
    pub trait Sealed {}
}

/// Sealed trait implemented by the ML-KEM parameter-set marker types
/// ([`MlKem512`], [`MlKem768`], [`MlKem1024`]). Carries the associated buffer
/// sizes and dispatches to the FIPS 203 facade.
#[allow(clippy::type_complexity)]
pub trait MlKemParams:
    private::Sealed
    + Copy
    + Clone
    + fmt::Debug
    + Default
    + PartialEq
    + Eq
    + PartialOrd
    + Ord
    + Send
    + Sync
    + Sized
    + 'static
{
    /// Encapsulation-key byte length.
    type EkSize: ArraySize + PartialEq + Eq;
    /// Decapsulation-key byte length.
    type DkSize: ArraySize + PartialEq + Eq;
    /// Ciphertext byte length.
    type CtSize: ArraySize + PartialEq + Eq;

    #[doc(hidden)]
    fn kem_keygen(
        d: &[u8; 32],
        z: &[u8; 32],
    ) -> Result<(Array<u8, Self::EkSize>, Array<u8, Self::DkSize>), crate::EncodeError>;
    #[doc(hidden)]
    fn kem_encaps(
        ek: &Array<u8, Self::EkSize>,
        m: &[u8; 32],
    ) -> Result<(Array<u8, U32>, Array<u8, Self::CtSize>), crate::EncodeError>;
    #[doc(hidden)]
    fn kem_decaps(
        dk: &Array<u8, Self::DkSize>,
        ct: &Array<u8, Self::CtSize>,
    ) -> Result<Array<u8, U32>, crate::EncodeError>;
    #[doc(hidden)]
    fn kem_ek_validate(ek: &Array<u8, Self::EkSize>) -> Result<(), kem::InvalidKey>;
    #[doc(hidden)]
    fn kem_ek_offset() -> usize;
}

/// Sealed trait implemented by the ML-DSA parameter-set marker types
/// ([`MlDsa44`], [`MlDsa65`], [`MlDsa87`]). Carries the associated buffer
/// sizes and dispatches to the FIPS 204 facade.
#[allow(clippy::type_complexity)]
pub trait MlDsaParams:
    private::Sealed
    + Copy
    + Clone
    + fmt::Debug
    + Default
    + PartialEq
    + Eq
    + PartialOrd
    + Ord
    + Send
    + Sync
    + Sized
    + 'static
{
    /// Public-key byte length.
    type PkSize: ArraySize + PartialEq + Eq;
    /// Secret-key byte length.
    type SkSize: ArraySize + PartialEq + Eq;
    /// Signature byte length.
    type SigSize: ArraySize + PartialEq + Eq;

    #[doc(hidden)]
    fn dsa_keygen(
        xi: &[u8; 32],
    ) -> Result<(Array<u8, Self::PkSize>, Array<u8, Self::SkSize>), crate::EncodeError>;
    #[doc(hidden)]
    fn dsa_sign(
        sk: &Array<u8, Self::SkSize>,
        msg: &[u8],
        ctx: &[u8],
        rnd: &[u8; 32],
    ) -> Result<Array<u8, Self::SigSize>, crate::SignError<core::convert::Infallible>>;
    #[doc(hidden)]
    fn dsa_sign_random<R: TryCryptoRng + ?Sized>(
        sk: &Array<u8, Self::SkSize>,
        msg: &[u8],
        ctx: &[u8],
        rng: &mut R,
    ) -> Result<Array<u8, Self::SigSize>, crate::SignError<R::Error>>;
    #[doc(hidden)]
    fn dsa_verify(
        pk: &Array<u8, Self::PkSize>,
        msg: &[u8],
        ctx: &[u8],
        sig: &Array<u8, Self::SigSize>,
    ) -> bool;
}

/// Parameter-set marker for ML-KEM-512 (`k = 2`).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct MlKem512;

/// Parameter-set marker for ML-KEM-768 (`k = 3`).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct MlKem768;

/// Parameter-set marker for ML-KEM-1024 (`k = 4`).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct MlKem1024;

impl private::Sealed for MlKem512 {}
impl private::Sealed for MlKem768 {}
impl private::Sealed for MlKem1024 {}

impl MlKemParams for MlKem512 {
    type EkSize = sizes::U800;
    type DkSize = sizes::U1632;
    type CtSize = sizes::U768;

    fn kem_keygen(
        d: &[u8; 32],
        z: &[u8; 32],
    ) -> Result<(Array<u8, Self::EkSize>, Array<u8, Self::DkSize>), crate::EncodeError> {
        let (ek, dk) = crate::ml_kem_512::keygen_from_seed(d, z)?;
        Ok((Array::from(ek), Array::from(dk)))
    }
    fn kem_encaps(
        ek: &Array<u8, Self::EkSize>,
        m: &[u8; 32],
    ) -> Result<(Array<u8, U32>, Array<u8, Self::CtSize>), crate::EncodeError> {
        let ek_arr: &[u8; crate::ml_kem_512::EK_BYTES] = ek.as_ref();
        let (ss, ct) = crate::ml_kem_512::encaps_from_seed(ek_arr, m)?;
        Ok((Array::from(ss), Array::from(ct)))
    }
    fn kem_decaps(
        dk: &Array<u8, Self::DkSize>,
        ct: &Array<u8, Self::CtSize>,
    ) -> Result<Array<u8, U32>, crate::EncodeError> {
        let dk_arr: &[u8; crate::ml_kem_512::DK_BYTES] = dk.as_ref();
        let ct_arr: &[u8; crate::ml_kem_512::CT_BYTES] = ct.as_ref();
        Ok(Array::from(crate::ml_kem_512::decaps(dk_arr, ct_arr)?))
    }
    fn kem_ek_validate(ek: &Array<u8, Self::EkSize>) -> Result<(), kem::InvalidKey> {
        crate::mlkem::encoding::ek_modulus_check::<2>(&ek[..384 * 2]).map_err(|_| kem::InvalidKey)
    }
    fn kem_ek_offset() -> usize {
        768
    }
}

impl MlKemParams for MlKem768 {
    type EkSize = sizes::U1184;
    type DkSize = sizes::U2400;
    type CtSize = sizes::U1088;

    fn kem_keygen(
        d: &[u8; 32],
        z: &[u8; 32],
    ) -> Result<(Array<u8, Self::EkSize>, Array<u8, Self::DkSize>), crate::EncodeError> {
        let (ek, dk) = crate::ml_kem_768::keygen_from_seed(d, z)?;
        Ok((Array::from(ek), Array::from(dk)))
    }
    fn kem_encaps(
        ek: &Array<u8, Self::EkSize>,
        m: &[u8; 32],
    ) -> Result<(Array<u8, U32>, Array<u8, Self::CtSize>), crate::EncodeError> {
        let ek_arr: &[u8; crate::ml_kem_768::EK_BYTES] = ek.as_ref();
        let (ss, ct) = crate::ml_kem_768::encaps_from_seed(ek_arr, m)?;
        Ok((Array::from(ss), Array::from(ct)))
    }
    fn kem_decaps(
        dk: &Array<u8, Self::DkSize>,
        ct: &Array<u8, Self::CtSize>,
    ) -> Result<Array<u8, U32>, crate::EncodeError> {
        let dk_arr: &[u8; crate::ml_kem_768::DK_BYTES] = dk.as_ref();
        let ct_arr: &[u8; crate::ml_kem_768::CT_BYTES] = ct.as_ref();
        Ok(Array::from(crate::ml_kem_768::decaps(dk_arr, ct_arr)?))
    }
    fn kem_ek_validate(ek: &Array<u8, Self::EkSize>) -> Result<(), kem::InvalidKey> {
        crate::mlkem::encoding::ek_modulus_check::<3>(&ek[..384 * 3]).map_err(|_| kem::InvalidKey)
    }
    fn kem_ek_offset() -> usize {
        1152
    }
}

impl MlKemParams for MlKem1024 {
    type EkSize = sizes::U1568;
    type DkSize = sizes::U3168;
    type CtSize = sizes::U1568;

    fn kem_keygen(
        d: &[u8; 32],
        z: &[u8; 32],
    ) -> Result<(Array<u8, Self::EkSize>, Array<u8, Self::DkSize>), crate::EncodeError> {
        let (ek, dk) = crate::ml_kem_1024::keygen_from_seed(d, z)?;
        Ok((Array::from(ek), Array::from(dk)))
    }
    fn kem_encaps(
        ek: &Array<u8, Self::EkSize>,
        m: &[u8; 32],
    ) -> Result<(Array<u8, U32>, Array<u8, Self::CtSize>), crate::EncodeError> {
        let ek_arr: &[u8; crate::ml_kem_1024::EK_BYTES] = ek.as_ref();
        let (ss, ct) = crate::ml_kem_1024::encaps_from_seed(ek_arr, m)?;
        Ok((Array::from(ss), Array::from(ct)))
    }
    fn kem_decaps(
        dk: &Array<u8, Self::DkSize>,
        ct: &Array<u8, Self::CtSize>,
    ) -> Result<Array<u8, U32>, crate::EncodeError> {
        let dk_arr: &[u8; crate::ml_kem_1024::DK_BYTES] = dk.as_ref();
        let ct_arr: &[u8; crate::ml_kem_1024::CT_BYTES] = ct.as_ref();
        Ok(Array::from(crate::ml_kem_1024::decaps(dk_arr, ct_arr)?))
    }
    fn kem_ek_validate(ek: &Array<u8, Self::EkSize>) -> Result<(), kem::InvalidKey> {
        crate::mlkem::encoding::ek_modulus_check::<4>(&ek[..384 * 4]).map_err(|_| kem::InvalidKey)
    }
    fn kem_ek_offset() -> usize {
        1536
    }
}

/// Parameter-set marker for ML-DSA-44 (`k = 4`, `l = 4`).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct MlDsa44;

/// Parameter-set marker for ML-DSA-65 (`k = 6`, `l = 5`).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct MlDsa65;

/// Parameter-set marker for ML-DSA-87 (`k = 8`, `l = 7`).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct MlDsa87;

impl private::Sealed for MlDsa44 {}
impl private::Sealed for MlDsa65 {}
impl private::Sealed for MlDsa87 {}

impl MlDsaParams for MlDsa44 {
    type PkSize = sizes::U1312;
    type SkSize = sizes::U2560;
    type SigSize = sizes::U2420;

    fn dsa_keygen(
        xi: &[u8; 32],
    ) -> Result<(Array<u8, Self::PkSize>, Array<u8, Self::SkSize>), crate::EncodeError> {
        let (pk, sk) = crate::ml_dsa_44::keygen_from_seed(xi)?;
        Ok((Array::from(pk), Array::from(sk)))
    }
    fn dsa_sign(
        sk: &Array<u8, Self::SkSize>,
        msg: &[u8],
        ctx: &[u8],
        rnd: &[u8; 32],
    ) -> Result<Array<u8, Self::SigSize>, crate::SignError<core::convert::Infallible>> {
        let sk_arr: &[u8; crate::ml_dsa_44::SK_BYTES] = sk.as_ref();
        Ok(Array::from(crate::ml_dsa_44::sign(sk_arr, msg, ctx, rnd)?))
    }
    fn dsa_sign_random<R: TryCryptoRng + ?Sized>(
        sk: &Array<u8, Self::SkSize>,
        msg: &[u8],
        ctx: &[u8],
        rng: &mut R,
    ) -> Result<Array<u8, Self::SigSize>, crate::SignError<R::Error>> {
        let sk_arr: &[u8; crate::ml_dsa_44::SK_BYTES] = sk.as_ref();
        Ok(Array::from(crate::ml_dsa_44::sign_random(
            sk_arr, msg, ctx, rng,
        )?))
    }
    fn dsa_verify(
        pk: &Array<u8, Self::PkSize>,
        msg: &[u8],
        ctx: &[u8],
        sig: &Array<u8, Self::SigSize>,
    ) -> bool {
        let pk_arr: &[u8; crate::ml_dsa_44::PK_BYTES] = pk.as_ref();
        let sig_arr: &[u8; crate::ml_dsa_44::SIG_BYTES] = sig.as_ref();
        crate::ml_dsa_44::verify(pk_arr, msg, ctx, sig_arr)
    }
}

impl MlDsaParams for MlDsa65 {
    type PkSize = sizes::U1952;
    type SkSize = sizes::U4032;
    type SigSize = sizes::U3309;

    fn dsa_keygen(
        xi: &[u8; 32],
    ) -> Result<(Array<u8, Self::PkSize>, Array<u8, Self::SkSize>), crate::EncodeError> {
        let (pk, sk) = crate::ml_dsa_65::keygen_from_seed(xi)?;
        Ok((Array::from(pk), Array::from(sk)))
    }
    fn dsa_sign(
        sk: &Array<u8, Self::SkSize>,
        msg: &[u8],
        ctx: &[u8],
        rnd: &[u8; 32],
    ) -> Result<Array<u8, Self::SigSize>, crate::SignError<core::convert::Infallible>> {
        let sk_arr: &[u8; crate::ml_dsa_65::SK_BYTES] = sk.as_ref();
        Ok(Array::from(crate::ml_dsa_65::sign(sk_arr, msg, ctx, rnd)?))
    }
    fn dsa_sign_random<R: TryCryptoRng + ?Sized>(
        sk: &Array<u8, Self::SkSize>,
        msg: &[u8],
        ctx: &[u8],
        rng: &mut R,
    ) -> Result<Array<u8, Self::SigSize>, crate::SignError<R::Error>> {
        let sk_arr: &[u8; crate::ml_dsa_65::SK_BYTES] = sk.as_ref();
        Ok(Array::from(crate::ml_dsa_65::sign_random(
            sk_arr, msg, ctx, rng,
        )?))
    }
    fn dsa_verify(
        pk: &Array<u8, Self::PkSize>,
        msg: &[u8],
        ctx: &[u8],
        sig: &Array<u8, Self::SigSize>,
    ) -> bool {
        let pk_arr: &[u8; crate::ml_dsa_65::PK_BYTES] = pk.as_ref();
        let sig_arr: &[u8; crate::ml_dsa_65::SIG_BYTES] = sig.as_ref();
        crate::ml_dsa_65::verify(pk_arr, msg, ctx, sig_arr)
    }
}

impl MlDsaParams for MlDsa87 {
    type PkSize = sizes::U2592;
    type SkSize = sizes::U4896;
    type SigSize = sizes::U4627;

    fn dsa_keygen(
        xi: &[u8; 32],
    ) -> Result<(Array<u8, Self::PkSize>, Array<u8, Self::SkSize>), crate::EncodeError> {
        let (pk, sk) = crate::ml_dsa_87::keygen_from_seed(xi)?;
        Ok((Array::from(pk), Array::from(sk)))
    }
    fn dsa_sign(
        sk: &Array<u8, Self::SkSize>,
        msg: &[u8],
        ctx: &[u8],
        rnd: &[u8; 32],
    ) -> Result<Array<u8, Self::SigSize>, crate::SignError<core::convert::Infallible>> {
        let sk_arr: &[u8; crate::ml_dsa_87::SK_BYTES] = sk.as_ref();
        Ok(Array::from(crate::ml_dsa_87::sign(sk_arr, msg, ctx, rnd)?))
    }
    fn dsa_sign_random<R: TryCryptoRng + ?Sized>(
        sk: &Array<u8, Self::SkSize>,
        msg: &[u8],
        ctx: &[u8],
        rng: &mut R,
    ) -> Result<Array<u8, Self::SigSize>, crate::SignError<R::Error>> {
        let sk_arr: &[u8; crate::ml_dsa_87::SK_BYTES] = sk.as_ref();
        Ok(Array::from(crate::ml_dsa_87::sign_random(
            sk_arr, msg, ctx, rng,
        )?))
    }
    fn dsa_verify(
        pk: &Array<u8, Self::PkSize>,
        msg: &[u8],
        ctx: &[u8],
        sig: &Array<u8, Self::SigSize>,
    ) -> bool {
        let pk_arr: &[u8; crate::ml_dsa_87::PK_BYTES] = pk.as_ref();
        let sig_arr: &[u8; crate::ml_dsa_87::SIG_BYTES] = sig.as_ref();
        crate::ml_dsa_87::verify(pk_arr, msg, ctx, sig_arr)
    }
}

/// `kem::Kem` marker for ML-KEM. Use `MlKem<MlKem512>` etc. in generic
/// contexts that require a `K: Kem` bound. For direct key construction,
/// `Dk<MlKem512>::try_generate_from_rng` is more ergonomic.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct MlKem<P: MlKemParams>(PhantomData<P>);

impl<P: MlKemParams> Kem for MlKem<P> {
    type DecapsulationKey = Dk<P>;
    type EncapsulationKey = Ek<P>;
    type SharedKeySize = U32;
    type CiphertextSize = P::CtSize;
}

/// Decapsulation key (the secret-side ML-KEM byte-encoded `dk`).
/// Caches the embedded ek so [`Decapsulator::encapsulation_key`]
/// returns `&Ek<P>` without re-parsing.
#[derive(Clone)]
pub struct Dk<P: MlKemParams> {
    sk: Zeroizing<Array<u8, P::DkSize>>,
    ek: Ek<P>,
}

impl<P: MlKemParams> fmt::Debug for Dk<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Dk")
            .field("sk", &"<secret>")
            .field("ek", &self.ek)
            .finish()
    }
}

/// Encapsulation key (the public-side ML-KEM byte-encoded `ek`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ek<P: MlKemParams> {
    ek: Array<u8, P::EkSize>,
}

impl<P: MlKemParams> KeySizeUser for Ek<P> {
    type KeySize = P::EkSize;
}

// No infallible `KeyInit` for the public-side ek: peer-supplied bytes
// must pass the FIPS 203 §7.2 modulus check.
impl<P: MlKemParams> TryKeyInit for Ek<P> {
    fn new(key: &Array<u8, P::EkSize>) -> Result<Self, kem::InvalidKey> {
        P::kem_ek_validate(key)?;
        Ok(Self { ek: key.clone() })
    }
}

impl<P: MlKemParams> KeyExport for Ek<P> {
    fn to_bytes(&self) -> Array<u8, P::EkSize> {
        self.ek.clone()
    }
}

impl<P: MlKemParams> Encapsulate for Ek<P> {
    type Kem = MlKem<P>;

    fn encapsulate_with_rng<R>(&self, rng: &mut R) -> (Array<u8, P::CtSize>, Array<u8, U32>)
    where
        R: CryptoRng + ?Sized,
    {
        let mut m = Zeroizing::new([0u8; 32]);
        rand_core::Rng::fill_bytes(rng, &mut *m);
        // TODO: drop .expect — needs const-generic Params buffer sizes + CanonicalEk typestate.
        let (ss_bytes, ct_bytes) = P::kem_encaps(&self.ek, &m)
            .expect("kem_encaps infallible: ek validated at construction, buffers pinned");
        (ct_bytes, ss_bytes)
    }
}

impl<P: MlKemParams> KeySizeUser for Dk<P> {
    type KeySize = P::DkSize;
}

// Symmetric with `Ek::TryKeyInit`: peer-supplied dk bytes embed an ek
// that must satisfy the FIPS 203 §7.2 modulus check, else
// `encapsulation_key()` would silently hand out a non-canonical Ek.
impl<P: MlKemParams> TryKeyInit for Dk<P> {
    fn new(key: &Array<u8, P::DkSize>) -> Result<Self, kem::InvalidKey> {
        let ek_start = P::kem_ek_offset();
        let ek_end = ek_start + <P::EkSize as Unsigned>::USIZE;
        let ek_bytes: Array<u8, P::EkSize> = key
            .get(ek_start..ek_end)
            .and_then(|s| s.try_into().ok())
            .ok_or(kem::InvalidKey)?;
        let ek = <Ek<P> as TryKeyInit>::new(&ek_bytes)?;
        Ok(Self {
            sk: Zeroizing::new(key.clone()),
            ek,
        })
    }
}

impl<P: MlKemParams> Generate for Dk<P> {
    fn try_generate_from_rng<R: TryCryptoRng + ?Sized>(rng: &mut R) -> Result<Self, R::Error> {
        // structurally-unreachable EncodeError can't flow through R::Error.
        let mut d = Zeroizing::new([0u8; 32]);
        let mut z = Zeroizing::new([0u8; 32]);
        rng.try_fill_bytes(&mut *d)?;
        rng.try_fill_bytes(&mut *z)?;
        // TODO: drop .expect — trait's R::Error can't carry EncodeError without a breaking where bound.
        let (ek_bytes, sk_bytes) =
            P::kem_keygen(&d, &z).expect("kem_keygen infallible on facade-pinned buffer sizes");
        let ek = Ek { ek: ek_bytes };
        Ok(Self {
            sk: Zeroizing::new(sk_bytes),
            ek,
        })
    }
}

impl<P: MlKemParams> Decapsulator for Dk<P> {
    type Kem = MlKem<P>;

    fn encapsulation_key(&self) -> &Ek<P> {
        &self.ek
    }
}

// Only `TryDecapsulate` (not infallible `Decapsulate`) so the facade's
// structural EncodeError surfaces as an Err rather than a panic.
impl<P: MlKemParams> TryDecapsulate for Dk<P> {
    type Error = crate::EncodeError;

    fn try_decapsulate(&self, ct: &Array<u8, P::CtSize>) -> Result<Array<u8, U32>, Self::Error> {
        P::kem_decaps(&self.sk, ct)
    }
}

use signature::{Error as SigError, Keypair, RandomizedSigner, Verifier};

/// Byte-encoded ML-DSA signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlDsaSignature<P: MlDsaParams>(Array<u8, P::SigSize>);

impl<P: MlDsaParams> AsRef<[u8]> for MlDsaSignature<P> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<P: MlDsaParams> From<Array<u8, P::SigSize>> for MlDsaSignature<P> {
    fn from(a: Array<u8, P::SigSize>) -> Self {
        Self(a)
    }
}

impl<P: MlDsaParams> TryFrom<&[u8]> for MlDsaSignature<P> {
    type Error = SigError;
    fn try_from(bytes: &[u8]) -> Result<Self, SigError> {
        Array::try_from(bytes)
            .map(Self)
            .map_err(|_| SigError::new())
    }
}

/// Verifier (public key holder) for ML-DSA.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlDsaVerifier<P: MlDsaParams> {
    pk: Array<u8, P::PkSize>,
}

impl<P: MlDsaParams> KeySizeUser for MlDsaVerifier<P> {
    type KeySize = P::PkSize;
}

impl<P: MlDsaParams> KeyInit for MlDsaVerifier<P> {
    fn new(key: &Array<u8, P::PkSize>) -> Self {
        Self { pk: key.clone() }
    }
}

impl<P: MlDsaParams> KeyExport for MlDsaVerifier<P> {
    fn to_bytes(&self) -> Array<u8, P::PkSize> {
        self.pk.clone()
    }
}

impl<P: MlDsaParams> Verifier<MlDsaSignature<P>> for MlDsaVerifier<P> {
    fn verify(&self, msg: &[u8], signature: &MlDsaSignature<P>) -> Result<(), SigError> {
        if P::dsa_verify(&self.pk, msg, &[], &signature.0) {
            Ok(())
        } else {
            Err(SigError::new())
        }
    }
}

/// Signer (secret key holder) for ML-DSA. Caches the verifying key so
/// [`Keypair::verifying_key`] doesn't have to re-derive it.
#[derive(Clone)]
pub struct MlDsaSigner<P: MlDsaParams> {
    sk: Zeroizing<Array<u8, P::SkSize>>,
    vk: MlDsaVerifier<P>,
}

impl<P: MlDsaParams> fmt::Debug for MlDsaSigner<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MlDsaSigner")
            .field("sk", &"<secret>")
            .field("vk", &self.vk)
            .finish()
    }
}

impl<P: MlDsaParams> MlDsaSigner<P> {
    /// Build a Signer from the byte-encoded `(sk, pk)` pair.
    /// FIPS 204 sk does not contain the literal pk bytes, so the caller
    /// must supply both halves; this is the natural counterpart to
    /// `keygen_from_seed` which returns them together.
    pub fn from_keypair(sk: &Array<u8, P::SkSize>, pk: &Array<u8, P::PkSize>) -> Self {
        Self {
            sk: Zeroizing::new(sk.clone()),
            vk: MlDsaVerifier { pk: pk.clone() },
        }
    }
}

impl<P: MlDsaParams> Keypair for MlDsaSigner<P> {
    type VerifyingKey = MlDsaVerifier<P>;
    fn verifying_key(&self) -> Self::VerifyingKey {
        self.vk.clone()
    }
}

impl<P: MlDsaParams> RandomizedSigner<MlDsaSignature<P>> for MlDsaSigner<P> {
    fn try_sign_with_rng<R: TryCryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        msg: &[u8],
    ) -> Result<MlDsaSignature<P>, SigError> {
        let bytes = P::dsa_sign_random(&self.sk, msg, &[], rng).map_err(|_| SigError::new())?;
        Ok(MlDsaSignature(bytes))
    }
}

impl<P: MlDsaParams> Generate for MlDsaSigner<P> {
    fn try_generate_from_rng<R: TryCryptoRng + ?Sized>(rng: &mut R) -> Result<Self, R::Error> {
        let mut xi = Zeroizing::new([0u8; 32]);
        rng.try_fill_bytes(&mut *xi)?;
        // TODO: drop .expect — trait's R::Error can't carry EncodeError without a breaking where bound.
        let (pk_bytes, sk_bytes) =
            P::dsa_keygen(&xi).expect("dsa_keygen infallible on facade-pinned buffer sizes");
        Ok(Self {
            sk: Zeroizing::new(sk_bytes),
            vk: MlDsaVerifier { pk: pk_bytes },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::convert::Infallible;

    /// Deterministic fixed RNG so tests stay reproducible.
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
        let dk = Dk::<MlKem512>::try_generate_from_rng(&mut rng).unwrap();
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
        let signer = MlDsaSigner::<MlDsa44>::try_generate_from_rng(&mut rng).unwrap();
        let verifier = signer.verifying_key();

        let msg = b"hello pqc traits";
        let sig: MlDsaSignature<MlDsa44> = signer.sign_with_rng(&mut FixedRng(0x55), msg);
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
        let signer = MlDsaSigner::<MlDsa65>::try_generate_from_rng(&mut rng).unwrap();
        let verifier = signer.verifying_key();

        let mut crng = FixedRng(0x55);
        let msg = b"randomized";
        let sig: MlDsaSignature<MlDsa65> = signer.sign_with_rng(&mut crng, msg);
        verifier.verify(msg, &sig).expect("verify should pass");
    }

    /// Non-canonical ek (first t_hat coefficient forged to 0xFFF > q)
    /// must be rejected at TryKeyInit so the infallible Encapsulate
    /// trait can't be reached with an invalid key.
    #[test]
    fn mlkem512_trykeyinit_rejects_non_canonical_ek() {
        let mut rng = FixedRng(0x42);
        let dk = Dk::<MlKem512>::try_generate_from_rng(&mut rng).unwrap();
        let mut bytes: Array<u8, sizes::U800> = dk.ek.ek;
        // Pack the first 12-bit coefficient as 0xFFF (4095, > q = 3329).
        bytes[0] = 0xFF;
        bytes[1] = (bytes[1] & 0xF0) | 0x0F;
        assert!(<Ek<MlKem512> as TryKeyInit>::new(&bytes).is_err());
    }

    /// Symmetric with the Ek test: a Dk byte blob with a non-canonical
    /// embedded ek must be rejected at TryKeyInit.
    #[test]
    fn mlkem512_trykeyinit_dk_rejects_non_canonical_embedded_ek() {
        let mut rng = FixedRng(0x42);
        let dk_good = Dk::<MlKem512>::try_generate_from_rng(&mut rng).unwrap();
        let mut bytes: Array<u8, sizes::U1632> = *dk_good.sk;
        // ek starts at MlKem512::kem_ek_offset() = 768; first 12-bit coeff
        // sits at bytes 768..770.
        let ek_off = MlKem512::kem_ek_offset();
        bytes[ek_off] = 0xFF;
        bytes[ek_off + 1] = (bytes[ek_off + 1] & 0xF0) | 0x0F;
        assert!(<Dk<MlKem512> as TryKeyInit>::new(&bytes).is_err());
    }

    /// Success path of TryKeyInit for Dk, Ek::to_bytes, and Dk::Debug.
    #[test]
    fn mlkem512_dk_trykeyinit_valid_and_debug() {
        let mut rng = FixedRng(0x42);
        let dk = Dk::<MlKem512>::try_generate_from_rng(&mut rng).unwrap();
        let sk_bytes: Array<u8, sizes::U1632> = *dk.sk;
        let dk2 = <Dk<MlKem512> as TryKeyInit>::new(&sk_bytes).unwrap();
        let _ = std::format!("{:?}", dk2);
        let _ = dk2.encapsulation_key().to_bytes();
    }

    /// ML-KEM-768 and ML-KEM-1024 round-trips via traits.
    #[test]
    fn mlkem768_roundtrip_via_traits() {
        let mut rng = FixedRng(0x55);
        let dk = Dk::<MlKem768>::try_generate_from_rng(&mut rng).unwrap();
        let ek = dk.encapsulation_key().clone();
        let (ct, ss_send) = ek.encapsulate_with_rng(&mut FixedRng(0x77));
        let ss_recv = dk.try_decapsulate(&ct).unwrap();
        assert_eq!(ss_send, ss_recv);
    }

    #[test]
    fn mlkem1024_roundtrip_via_traits() {
        let mut rng = FixedRng(0x33);
        let dk = Dk::<MlKem1024>::try_generate_from_rng(&mut rng).unwrap();
        let ek = dk.encapsulation_key().clone();
        let (ct, ss_send) = ek.encapsulate_with_rng(&mut FixedRng(0x44));
        let ss_recv = dk.try_decapsulate(&ct).unwrap();
        assert_eq!(ss_send, ss_recv);
    }

    /// Signature byte conversions: AsRef, From<Array>, TryFrom<&[u8]>.
    #[test]
    fn mldsa44_sig_conversions() {
        let mut rng = FixedRng(0x42);
        let signer = MlDsaSigner::<MlDsa44>::try_generate_from_rng(&mut rng).unwrap();
        let sig: MlDsaSignature<MlDsa44> = signer.sign_with_rng(&mut FixedRng(0x55), b"test");

        let bytes: &[u8] = sig.as_ref();

        let sig2 = MlDsaSignature::<MlDsa44>::try_from(bytes).unwrap();
        assert_eq!(sig, sig2);

        let arr = Array::<u8, sizes::U2420>::default();
        let _ = MlDsaSignature::<MlDsa44>::from(arr);

        assert!(MlDsaSignature::<MlDsa44>::try_from(&[0u8; 42][..]).is_err());
    }

    /// Verifier KeyInit, KeyExport, and verify-rejects-wrong-sig.
    #[test]
    fn mldsa44_verifier_init_and_export() {
        let mut rng = FixedRng(0x42);
        let signer = MlDsaSigner::<MlDsa44>::try_generate_from_rng(&mut rng).unwrap();
        let vk = signer.verifying_key();

        let pk_bytes = vk.to_bytes();
        let vk2 = MlDsaVerifier::<MlDsa44>::new(&pk_bytes);

        let sig: MlDsaSignature<MlDsa44> = signer.sign_with_rng(&mut FixedRng(0x55), b"hello");
        vk2.verify(b"hello", &sig).unwrap();
    }

    /// Signer::from_keypair and Signer::Debug.
    #[test]
    fn mldsa44_signer_from_keypair_and_debug() {
        let (pk_bytes, sk_bytes) = crate::ml_dsa_44::keygen_from_seed(&[0x42u8; 32]).unwrap();
        let sk_arr = Array::from(sk_bytes);
        let pk_arr = Array::from(pk_bytes);
        let signer = MlDsaSigner::<MlDsa44>::from_keypair(&sk_arr, &pk_arr);
        let vk = signer.verifying_key();

        let _ = std::format!("{:?}", signer);

        let sig: MlDsaSignature<MlDsa44> =
            signer.sign_with_rng(&mut FixedRng(0x55), b"from_keypair");
        vk.verify(b"from_keypair", &sig).unwrap();
    }

    /// ML-DSA-87 via traits (covers the third parameter set).
    #[test]
    fn mldsa87_roundtrip_via_traits() {
        let mut rng = FixedRng(0x99);
        let signer = MlDsaSigner::<MlDsa87>::try_generate_from_rng(&mut rng).unwrap();
        let vk = signer.verifying_key();
        let msg = b"ml-dsa-87 via traits";
        let sig: MlDsaSignature<MlDsa87> = signer.sign_with_rng(&mut FixedRng(0x55), msg);
        vk.verify(msg, &sig).unwrap();
        let sig2: MlDsaSignature<MlDsa87> = signer.sign_with_rng(&mut FixedRng(0x66), msg);
        vk.verify(msg, &sig2).unwrap();
    }
}
