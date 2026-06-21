//! Per-parameter-set facades (ML-DSA-44 / 65 / 87) over the generic
//! [`crate::internal`] keygen / sign / verify functions.
//!
//! KeyGen and Sign run NTT-domain Mont arithmetic through
//! `wide::ct::mul` (the `Ct` personality); Verify uses `wide::mul`
//! because its inputs (pk, sig, M) are public and the variable-time
//! REDC finalize has nothing to leak. Time-domain post-processing
//! (the `sample_in_ball` rejection loop and the rounding helpers) is
//! not yet constant-time, so the Ct path is a partial guarantee.

macro_rules! per_set {
    ($mod:ident, $params:ident, $doc:expr) => {
        #[doc = $doc]
        pub mod $mod {
            use fixed_bigint::{Ct, Nct};

            use crate::internal;
            use crate::params::$params;
            use crate::{
                DomainSeparator, EncodeError, KeyGenSeed, MessageError, PreHash, RandError,
                SignError, SigningRandomness,
            };

            pub const PK_BYTES: usize = $params.pk_bytes;
            pub const SK_BYTES: usize = $params.sk_bytes;
            pub const SIG_BYTES: usize = $params.sig_bytes;

            /// Deterministic ML-DSA KeyGen (FIPS 204 §6 Alg 1). Takes
            /// the 32-byte seed `ξ` as a [`KeyGenSeed`]; returns `(pk, sk)`.
            /// Use [`keygen`] when the seed should come from an RNG.
            pub fn keygen_from_seed(
                xi: &KeyGenSeed,
            ) -> Result<([u8; PK_BYTES], [u8; SK_BYTES]), EncodeError> {
                let mut pk = [0u8; PK_BYTES];
                let mut sk = [0u8; SK_BYTES];
                internal::keygen_internal_impl::<_, _, Ct>(&$params, &xi.0, &mut pk, &mut sk)?;
                Ok((pk, sk))
            }

            /// Low-level ML-DSA Sign (FIPS 204 §6 Alg 2). Takes the
            /// pre-constructed message representative `M'` directly.
            /// Most callers want [`sign`] (which builds `M'` from
            /// `(sk, M, ctx)`) or [`hash_sign`] for HashML-DSA.
            ///
            /// Requires the `acvp` crate feature.
            #[cfg(feature = "acvp")]
            pub fn sign_msg_repr(
                sk: &[u8; SK_BYTES],
                m_prime: &[u8],
                rnd: &SigningRandomness,
            ) -> Result<[u8; SIG_BYTES], EncodeError> {
                let mut sig = [0u8; SIG_BYTES];
                internal::sign_internal_impl::<_, _, Ct>(&$params, sk, m_prime, &rnd.0, &mut sig)?;
                Ok(sig)
            }

            /// Low-level ML-DSA Verify (FIPS 204 §6 Alg 3). Takes the
            /// pre-constructed message representative `M'` directly.
            /// Most callers want [`verify`] (which builds `M'` from
            /// `(pk, M, ctx)`) or [`hash_verify`] for HashML-DSA.
            ///
            /// Requires the `acvp` crate feature.
            #[cfg(feature = "acvp")]
            pub fn verify_msg_repr(
                pk: &[u8; PK_BYTES],
                m_prime: &[u8],
                sig: &[u8; SIG_BYTES],
            ) -> bool {
                internal::verify_internal_impl::<_, _, Nct>(&$params, pk, m_prime, sig)
            }

            /// Pure ML-DSA Sign (FIPS 204 §5.2). Builds the message
            /// representative `M' = 0x00 || |ctx| || ctx || M`, absorbing
            /// the pieces directly into SHAKE-256. Returns
            /// `CtxTooLong` if `ctx.len() > u8::MAX as usize`.
            pub fn sign(
                sk: &[u8; SK_BYTES],
                m: &[u8],
                ctx: &[u8],
                rnd: &SigningRandomness,
            ) -> Result<[u8; SIG_BYTES], MessageError> {
                let ds = DomainSeparator::pure(ctx).ok_or(MessageError::CtxTooLong)?;
                let (pieces, n) = ds.pieces(m);
                let mut sig = [0u8; SIG_BYTES];
                internal::sign_internal_impl_pieces::<_, _, Ct>(
                    &$params,
                    sk,
                    &pieces[..n],
                    &rnd.0,
                    &mut sig,
                )?;
                Ok(sig)
            }

            /// Pure ML-DSA Verify (FIPS 204 §5.2). Builds the message
            /// representative `M' = 0x00 || |ctx| || ctx || M`, absorbing
            /// the pieces directly into SHAKE-256 without materializing a
            /// contiguous `M'` buffer. Returns `false` on any failure.
            pub fn verify(
                pk: &[u8; PK_BYTES],
                m: &[u8],
                ctx: &[u8],
                sig: &[u8; SIG_BYTES],
            ) -> bool {
                let Some(ds) = DomainSeparator::pure(ctx) else {
                    return false;
                };
                let (pieces, n) = ds.pieces(m);
                internal::verify_internal_impl_pieces::<_, _, Nct>(&$params, pk, &pieces[..n], sig)
            }

            /// HashML-DSA Sign (FIPS 204 §5.4). Caller hashes the message
            /// externally and passes the digest via [`PreHash`].
            /// Returns `CtxTooLong` if `ctx.len() > u8::MAX as usize`.
            pub fn hash_sign(
                sk: &[u8; SK_BYTES],
                ph: PreHash<'_>,
                ctx: &[u8],
                rnd: &SigningRandomness,
            ) -> Result<[u8; SIG_BYTES], MessageError> {
                let ds = DomainSeparator::pre_hashed(ctx, ph.oid(), ph.digest())
                    .ok_or(MessageError::CtxTooLong)?;
                let (pieces, n) = ds.pieces(&[]);
                let mut sig = [0u8; SIG_BYTES];
                internal::sign_internal_impl_pieces::<_, _, Ct>(
                    &$params,
                    sk,
                    &pieces[..n],
                    &rnd.0,
                    &mut sig,
                )?;
                Ok(sig)
            }

            /// HashML-DSA Verify (FIPS 204 §5.4): pre-hashed message
            /// representative `M' = 0x01 || |ctx| || ctx || OID || PHM(M)`.
            /// Used by TLS 1.3 + ML-DSA CertificateVerify.
            pub fn hash_verify(
                pk: &[u8; PK_BYTES],
                ph: PreHash<'_>,
                ctx: &[u8],
                sig: &[u8; SIG_BYTES],
            ) -> bool {
                let Some(ds) = DomainSeparator::pre_hashed(ctx, ph.oid(), ph.digest()) else {
                    return false;
                };
                let (pieces, n) = ds.pieces(&[]);
                internal::verify_internal_impl_pieces::<_, _, Nct>(&$params, pk, &pieces[..n], sig)
            }

            /// RNG-driven ML-DSA KeyGen. Draws the 32-byte seed `ξ`
            /// from `rng`; returns `(pk, sk)`.
            pub fn keygen<R: rand_core::TryCryptoRng + ?Sized>(
                rng: &mut R,
            ) -> Result<([u8; PK_BYTES], [u8; SK_BYTES]), RandError<R::Error>> {
                let mut xi = zeroize::Zeroizing::new(KeyGenSeed([0u8; 32]));
                rng.try_fill_bytes(&mut xi.0).map_err(RandError::Rng)?;
                Ok(keygen_from_seed(&xi)?)
            }

            /// RNG-driven pure ML-DSA Sign. Draws the 32-byte `rnd`
            /// from `rng` and builds the FIPS 204 §5.2 `M'` from
            /// `(m, ctx)`. Returns `Message(CtxTooLong)` if `ctx.len() > u8::MAX as usize`
            /// and `Rng(R::Error)` on RNG failure.
            pub fn sign_random<R: rand_core::TryCryptoRng + ?Sized>(
                sk: &[u8; SK_BYTES],
                m: &[u8],
                ctx: &[u8],
                rng: &mut R,
            ) -> Result<[u8; SIG_BYTES], SignError<R::Error>> {
                if ctx.len() > u8::MAX as usize {
                    return Err(SignError::Message(MessageError::CtxTooLong));
                }
                let mut rnd = zeroize::Zeroizing::new(SigningRandomness([0u8; 32]));
                rng.try_fill_bytes(&mut rnd.0).map_err(SignError::Rng)?;
                sign(sk, m, ctx, &rnd).map_err(SignError::Message)
            }

            /// RNG-driven HashML-DSA Sign.
            pub fn hash_sign_random<R: rand_core::TryCryptoRng + ?Sized>(
                sk: &[u8; SK_BYTES],
                ph: PreHash<'_>,
                ctx: &[u8],
                rng: &mut R,
            ) -> Result<[u8; SIG_BYTES], SignError<R::Error>> {
                if ctx.len() > u8::MAX as usize {
                    return Err(SignError::Message(MessageError::CtxTooLong));
                }
                let mut rnd = zeroize::Zeroizing::new(SigningRandomness([0u8; 32]));
                rng.try_fill_bytes(&mut rnd.0).map_err(SignError::Rng)?;
                hash_sign(sk, ph, ctx, &rnd).map_err(SignError::Message)
            }

            #[cfg(test)]
            mod tests {
                use super::*;
                use crate::{KeyGenSeed, MessageError, PreHash, SignError, SigningRandomness};
                use core::convert::Infallible;

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

                #[test]
                fn keygen_via_rng() {
                    keygen(&mut FixedRng(0x42)).unwrap();
                }

                #[test]
                fn hash_sign_verify_sha256() {
                    let (pk, sk) = keygen_from_seed(&KeyGenSeed([0x42u8; 32])).unwrap();
                    let ph = PreHash::sha256(&[0x11u8; 32]);
                    let sig = hash_sign(&sk, ph, b"ctx", &SigningRandomness([0xC3u8; 32])).unwrap();
                    assert!(hash_verify(&pk, ph, b"ctx", &sig));
                    let ph_wrong = PreHash::sha256(&[0x22u8; 32]);
                    assert!(!hash_verify(&pk, ph_wrong, b"ctx", &sig));
                }

                #[test]
                fn hash_sign_verify_sha512() {
                    let (pk, sk) = keygen_from_seed(&KeyGenSeed([0x55u8; 32])).unwrap();
                    let ph = PreHash::sha512(&[0x77u8; 64]);
                    let sig = hash_sign(&sk, ph, b"", &SigningRandomness([0xC3u8; 32])).unwrap();
                    assert!(hash_verify(&pk, ph, b"", &sig));
                }

                #[test]
                fn sign_random_roundtrip() {
                    let (pk, sk) = keygen_from_seed(&KeyGenSeed([0x42u8; 32])).unwrap();
                    let sig = sign_random(&sk, b"msg", b"", &mut FixedRng(0x77)).unwrap();
                    assert!(verify(&pk, b"msg", b"", &sig));
                }

                #[test]
                fn hash_sign_random_roundtrip() {
                    let (pk, sk) = keygen_from_seed(&KeyGenSeed([0x42u8; 32])).unwrap();
                    let ph = PreHash::sha256(&[0xABu8; 32]);
                    let sig = hash_sign_random(&sk, ph, b"", &mut FixedRng(0x77)).unwrap();
                    assert!(hash_verify(&pk, ph, b"", &sig));
                }

                #[test]
                fn ctx_too_long_rejected() {
                    let (pk, sk) = keygen_from_seed(&KeyGenSeed([0x42u8; 32])).unwrap();
                    let long = [0u8; 256];
                    let ph = PreHash::sha256(&[0u8; 32]);
                    let rnd = SigningRandomness([0u8; 32]);
                    assert!(matches!(
                        sign(&sk, b"m", &long, &rnd),
                        Err(MessageError::CtxTooLong)
                    ));
                    assert!(!verify(&pk, b"m", &long, &[0u8; SIG_BYTES]));
                    assert!(matches!(
                        hash_sign(&sk, ph, &long, &rnd),
                        Err(MessageError::CtxTooLong)
                    ));
                    assert!(!hash_verify(&pk, ph, &long, &[0u8; SIG_BYTES]));
                    assert!(matches!(
                        sign_random(&sk, b"m", &long, &mut FixedRng(0x42)),
                        Err(SignError::Message(MessageError::CtxTooLong))
                    ));
                    assert!(matches!(
                        hash_sign_random(&sk, ph, &long, &mut FixedRng(0x42)),
                        Err(SignError::Message(MessageError::CtxTooLong))
                    ));
                }
            }
        }
    };
}

per_set!(
    ml_dsa_44,
    ML_DSA_44,
    "ML-DSA-44 (FIPS 204, parameter set 1): K=4, L=4, η=2, τ=39, λ=128.\n\nPublic key: 1312 B. Signature: 2420 B."
);
per_set!(
    ml_dsa_65,
    ML_DSA_65,
    "ML-DSA-65 (FIPS 204, parameter set 2): K=6, L=5, η=4, τ=49, λ=192.\n\nPublic key: 1952 B. Signature: 3309 B."
);
per_set!(
    ml_dsa_87,
    ML_DSA_87,
    "ML-DSA-87 (FIPS 204, parameter set 3): K=8, L=7, η=2, τ=60, λ=256.\n\nPublic key: 2592 B. Signature: 4627 B."
);
