//! Per-parameter-set facades (ML-DSA-44 / 65 / 87) over the generic
//! [`crate::internal`] keygen / sign / verify functions.
//!
//! Each `*_ct` sibling routes NTT-domain Mont arithmetic through
//! `wide::ct::mul` and yields byte-identical pk/sk/sig and
//! accept/reject decisions; time-domain post-processing (the
//! `sample_in_ball` rejection loop and the rounding helpers) is not
//! yet constant-time, so the `_ct` suffix is a partial guarantee.

macro_rules! per_set {
    ($mod:ident, $params:ident, $doc:expr) => {
        #[doc = $doc]
        pub mod $mod {
            use fixed_bigint::Ct;

            use crate::internal;
            use crate::params::$params;

            pub const PK_BYTES: usize = $params.pk_bytes;
            pub const SK_BYTES: usize = $params.sk_bytes;
            pub const SIG_BYTES: usize = $params.sig_bytes;

            pub fn keygen_internal(xi: &[u8; 32]) -> ([u8; PK_BYTES], [u8; SK_BYTES]) {
                let mut pk = [0u8; PK_BYTES];
                let mut sk = [0u8; SK_BYTES];
                internal::keygen_internal(&$params, xi, &mut pk, &mut sk);
                (pk, sk)
            }

            pub fn sign_internal(
                sk: &[u8; SK_BYTES],
                m_prime: &[u8],
                rnd: &[u8; 32],
            ) -> [u8; SIG_BYTES] {
                let mut sig = [0u8; SIG_BYTES];
                internal::sign_internal(&$params, sk, m_prime, rnd, &mut sig);
                sig
            }

            pub fn verify_internal(
                pk: &[u8; PK_BYTES],
                m_prime: &[u8],
                sig: &[u8; SIG_BYTES],
            ) -> bool {
                internal::verify_internal(&$params, pk, m_prime, sig)
            }

            /// CT-flavored sibling of [`keygen_internal`].
            pub fn keygen_internal_ct(xi: &[u8; 32]) -> ([u8; PK_BYTES], [u8; SK_BYTES]) {
                let mut pk = [0u8; PK_BYTES];
                let mut sk = [0u8; SK_BYTES];
                internal::keygen_internal_impl::<_, _, Ct>(&$params, xi, &mut pk, &mut sk);
                (pk, sk)
            }

            /// CT-flavored sibling of [`sign_internal`].
            pub fn sign_internal_ct(
                sk: &[u8; SK_BYTES],
                m_prime: &[u8],
                rnd: &[u8; 32],
            ) -> [u8; SIG_BYTES] {
                let mut sig = [0u8; SIG_BYTES];
                internal::sign_internal_impl::<_, _, Ct>(&$params, sk, m_prime, rnd, &mut sig);
                sig
            }

            /// CT-flavored sibling of [`verify_internal`].
            pub fn verify_internal_ct(
                pk: &[u8; PK_BYTES],
                m_prime: &[u8],
                sig: &[u8; SIG_BYTES],
            ) -> bool {
                internal::verify_internal_impl::<_, _, Ct>(&$params, pk, m_prime, sig)
            }

            /// Pure ML-DSA Sign (FIPS 204 §5.2). Builds the message
            /// representative `M' = 0x00 || |ctx| || ctx || M` from
            /// the four input pieces, absorbing them directly into
            /// SHAKE-256 without a contiguous `M'` buffer. Returns
            /// `None` if `ctx.len() > 255` (the only failure mode for
            /// pure-mode signing).
            pub fn sign(
                sk: &[u8; SK_BYTES],
                m: &[u8],
                ctx: &[u8],
                rnd: &[u8; 32],
            ) -> Option<[u8; SIG_BYTES]> {
                if ctx.len() > 255 {
                    return None;
                }
                let prefix = [0x00u8];
                let ctx_len = [ctx.len() as u8];
                let pieces: &[&[u8]] = &[&prefix, &ctx_len, ctx, m];
                let mut sig = [0u8; SIG_BYTES];
                internal::sign_internal_impl_pieces::<_, _, fixed_bigint::Nct>(
                    &$params, sk, pieces, rnd, &mut sig,
                );
                Some(sig)
            }

            /// CT-flavored sibling of [`sign`].
            pub fn sign_ct(
                sk: &[u8; SK_BYTES],
                m: &[u8],
                ctx: &[u8],
                rnd: &[u8; 32],
            ) -> Option<[u8; SIG_BYTES]> {
                if ctx.len() > 255 {
                    return None;
                }
                let prefix = [0x00u8];
                let ctx_len = [ctx.len() as u8];
                let pieces: &[&[u8]] = &[&prefix, &ctx_len, ctx, m];
                let mut sig = [0u8; SIG_BYTES];
                internal::sign_internal_impl_pieces::<_, _, Ct>(
                    &$params, sk, pieces, rnd, &mut sig,
                );
                Some(sig)
            }

            /// Pure ML-DSA Verify (FIPS 204 §5.2). Builds the message
            /// representative `M' = 0x00 || |ctx| || ctx || M` from
            /// the four input pieces, absorbing them directly into
            /// SHAKE-256 without materializing a contiguous `M'`
            /// buffer. Returns `false` on any failure (oversize `ctx`,
            /// malformed `sig`, or hash mismatch).
            pub fn verify(
                pk: &[u8; PK_BYTES],
                m: &[u8],
                ctx: &[u8],
                sig: &[u8; SIG_BYTES],
            ) -> bool {
                if ctx.len() > 255 {
                    return false;
                }
                let prefix = [0x00u8];
                let ctx_len = [ctx.len() as u8];
                let pieces: &[&[u8]] = &[&prefix, &ctx_len, ctx, m];
                internal::verify_internal_impl_pieces::<_, _, fixed_bigint::Nct>(
                    &$params, pk, pieces, sig,
                )
            }

            /// CT-flavored pure ML-DSA Verify.
            pub fn verify_ct(
                pk: &[u8; PK_BYTES],
                m: &[u8],
                ctx: &[u8],
                sig: &[u8; SIG_BYTES],
            ) -> bool {
                if ctx.len() > 255 {
                    return false;
                }
                let prefix = [0x00u8];
                let ctx_len = [ctx.len() as u8];
                let pieces: &[&[u8]] = &[&prefix, &ctx_len, ctx, m];
                internal::verify_internal_impl_pieces::<_, _, Ct>(&$params, pk, pieces, sig)
            }

            /// Pre-hash selector for [`hash_verify`]. Carries the
            /// externally-computed digest plus the OID family the
            /// verifier binds it to.
            ///
            /// SHA-256 and SHA-512 cover the digests used by current
            /// TLS 1.3 + ML-DSA CertificateVerify codepoints. FIPS 204
            /// §5.4 Algorithm 5 also approves SHA3-{256,384,512},
            /// SHA-384, and SHAKE-128/256 pre-hashes; signatures
            /// produced with those cannot be verified through this
            /// API.
            #[derive(Clone, Copy, Debug, PartialEq, Eq)]
            pub enum PreHash {
                /// SHA-256, OID 2.16.840.1.101.3.4.2.1.
                Sha256([u8; 32]),
                /// SHA-512, OID 2.16.840.1.101.3.4.2.3.
                Sha512([u8; 64]),
            }

            // FIPS 204 §5.4 Table 3, DER-encoded.
            const OID_SHA256: [u8; 11] = [
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
            ];
            const OID_SHA512: [u8; 11] = [
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
            ];

            #[inline]
            fn ph_pieces(ph: &PreHash) -> (&'static [u8], &[u8]) {
                match ph {
                    PreHash::Sha256(d) => (&OID_SHA256, d.as_slice()),
                    PreHash::Sha512(d) => (&OID_SHA512, d.as_slice()),
                }
            }

            /// HashML-DSA Sign (FIPS 204 §5.4). Caller hashes the
            /// message externally and passes the digest via [`PreHash`].
            /// Returns `None` if `ctx.len() > 255`.
            pub fn hash_sign(
                sk: &[u8; SK_BYTES],
                ph: &PreHash,
                ctx: &[u8],
                rnd: &[u8; 32],
            ) -> Option<[u8; SIG_BYTES]> {
                if ctx.len() > 255 {
                    return None;
                }
                let prefix = [0x01u8];
                let ctx_len = [ctx.len() as u8];
                let (oid, digest) = ph_pieces(ph);
                let pieces: &[&[u8]] = &[&prefix, &ctx_len, ctx, oid, digest];
                let mut sig = [0u8; SIG_BYTES];
                internal::sign_internal_impl_pieces::<_, _, fixed_bigint::Nct>(
                    &$params, sk, pieces, rnd, &mut sig,
                );
                Some(sig)
            }

            /// CT-flavored sibling of [`hash_sign`].
            pub fn hash_sign_ct(
                sk: &[u8; SK_BYTES],
                ph: &PreHash,
                ctx: &[u8],
                rnd: &[u8; 32],
            ) -> Option<[u8; SIG_BYTES]> {
                if ctx.len() > 255 {
                    return None;
                }
                let prefix = [0x01u8];
                let ctx_len = [ctx.len() as u8];
                let (oid, digest) = ph_pieces(ph);
                let pieces: &[&[u8]] = &[&prefix, &ctx_len, ctx, oid, digest];
                let mut sig = [0u8; SIG_BYTES];
                internal::sign_internal_impl_pieces::<_, _, Ct>(
                    &$params, sk, pieces, rnd, &mut sig,
                );
                Some(sig)
            }

            /// HashML-DSA Verify (FIPS 204 §5.4): pre-hashed message
            /// representative `M' = 0x01 || |ctx| || ctx || OID || PHM(M)`.
            /// Used by TLS 1.3 + ML-DSA CertificateVerify.
            pub fn hash_verify(
                pk: &[u8; PK_BYTES],
                ph: &PreHash,
                ctx: &[u8],
                sig: &[u8; SIG_BYTES],
            ) -> bool {
                if ctx.len() > 255 {
                    return false;
                }
                let prefix = [0x01u8];
                let ctx_len = [ctx.len() as u8];
                let (oid, digest) = ph_pieces(ph);
                let pieces: &[&[u8]] = &[&prefix, &ctx_len, ctx, oid, digest];
                internal::verify_internal_impl_pieces::<_, _, fixed_bigint::Nct>(
                    &$params, pk, pieces, sig,
                )
            }

            /// CT-flavored sibling of [`hash_verify`].
            pub fn hash_verify_ct(
                pk: &[u8; PK_BYTES],
                ph: &PreHash,
                ctx: &[u8],
                sig: &[u8; SIG_BYTES],
            ) -> bool {
                if ctx.len() > 255 {
                    return false;
                }
                let prefix = [0x01u8];
                let ctx_len = [ctx.len() as u8];
                let (oid, digest) = ph_pieces(ph);
                let pieces: &[&[u8]] = &[&prefix, &ctx_len, ctx, oid, digest];
                internal::verify_internal_impl_pieces::<_, _, Ct>(&$params, pk, pieces, sig)
            }

            // RNG-driven entry points. `try_fill_bytes` lets HW RNGs
            // that can fail propagate their error type rather than
            // panic; the bound is `TryCryptoRng` for that reason.

            /// RNG-driven ML-DSA KeyGen. Draws the 32-byte seed `xi`
            /// from `rng`; returns `(pk, sk)`.
            pub fn keygen<R: rand_core::TryCryptoRng + ?Sized>(
                rng: &mut R,
            ) -> Result<([u8; PK_BYTES], [u8; SK_BYTES]), R::Error> {
                let mut xi = zeroize::Zeroizing::new([0u8; 32]);
                rng.try_fill_bytes(&mut *xi)?;
                Ok(keygen_internal(&xi))
            }

            /// RNG-driven pure ML-DSA Sign. Draws the 32-byte `rnd`
            /// from `rng` and builds the FIPS 204 §5.2 `M'` from
            /// `(m, ctx)`. Returns `CtxTooLong` if `ctx.len() > 255`
            /// and `Rng(R::Error)` on RNG failure.
            pub fn sign_random<R: rand_core::TryCryptoRng + ?Sized>(
                sk: &[u8; SK_BYTES],
                m: &[u8],
                ctx: &[u8],
                rng: &mut R,
            ) -> Result<[u8; SIG_BYTES], crate::SignError<R::Error>> {
                if ctx.len() > 255 {
                    return Err(crate::SignError::CtxTooLong);
                }
                let mut rnd = [0u8; 32];
                rng.try_fill_bytes(&mut rnd)
                    .map_err(crate::SignError::Rng)?;
                Ok(sign(sk, m, ctx, &rnd).expect("ctx already validated"))
            }

            /// CT-flavored sibling of [`sign_random`].
            pub fn sign_random_ct<R: rand_core::TryCryptoRng + ?Sized>(
                sk: &[u8; SK_BYTES],
                m: &[u8],
                ctx: &[u8],
                rng: &mut R,
            ) -> Result<[u8; SIG_BYTES], crate::SignError<R::Error>> {
                if ctx.len() > 255 {
                    return Err(crate::SignError::CtxTooLong);
                }
                let mut rnd = [0u8; 32];
                rng.try_fill_bytes(&mut rnd)
                    .map_err(crate::SignError::Rng)?;
                Ok(sign_ct(sk, m, ctx, &rnd).expect("ctx already validated"))
            }

            /// RNG-driven HashML-DSA Sign.
            pub fn hash_sign_random<R: rand_core::TryCryptoRng + ?Sized>(
                sk: &[u8; SK_BYTES],
                ph: &PreHash,
                ctx: &[u8],
                rng: &mut R,
            ) -> Result<[u8; SIG_BYTES], crate::SignError<R::Error>> {
                if ctx.len() > 255 {
                    return Err(crate::SignError::CtxTooLong);
                }
                let mut rnd = [0u8; 32];
                rng.try_fill_bytes(&mut rnd)
                    .map_err(crate::SignError::Rng)?;
                Ok(hash_sign(sk, ph, ctx, &rnd).expect("ctx already validated"))
            }

            /// CT-flavored sibling of [`hash_sign_random`].
            pub fn hash_sign_random_ct<R: rand_core::TryCryptoRng + ?Sized>(
                sk: &[u8; SK_BYTES],
                ph: &PreHash,
                ctx: &[u8],
                rng: &mut R,
            ) -> Result<[u8; SIG_BYTES], crate::SignError<R::Error>> {
                if ctx.len() > 255 {
                    return Err(crate::SignError::CtxTooLong);
                }
                let mut rnd = [0u8; 32];
                rng.try_fill_bytes(&mut rnd)
                    .map_err(crate::SignError::Rng)?;
                Ok(hash_sign_ct(sk, ph, ctx, &rnd).expect("ctx already validated"))
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
