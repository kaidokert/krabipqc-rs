//! Per-parameter-set facades (ML-DSA-44 / 65 / 87) over the generic
//! [`crate::internal`] verify functions.
//!
//! Each `*_ct` sibling routes NTT-domain Mont arithmetic through
//! `wide::ct::mul` and yields byte-identical accept/reject decisions;
//! time-domain post-processing (the `sample_in_ball` rejection loop
//! and the rounding helpers) is not yet constant-time, so the `_ct`
//! suffix is a partial guarantee.

macro_rules! per_set {
    ($mod:ident, $params:ident, $pk:expr, $sig:expr, $doc:expr) => {
        #[doc = $doc]
        pub mod $mod {
            use fixed_bigint::Ct;

            use crate::internal;
            use crate::params::$params;

            pub const PK_BYTES: usize = $pk;
            pub const SIG_BYTES: usize = $sig;

            pub fn verify_internal(
                pk: &[u8; PK_BYTES],
                m_prime: &[u8],
                sig: &[u8; SIG_BYTES],
            ) -> bool {
                internal::verify_internal(&$params, pk, m_prime, sig)
            }

            /// CT-flavored sibling of [`verify_internal`].
            pub fn verify_internal_ct(
                pk: &[u8; PK_BYTES],
                m_prime: &[u8],
                sig: &[u8; SIG_BYTES],
            ) -> bool {
                internal::verify_internal_impl::<_, _, Ct>(&$params, pk, m_prime, sig)
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
        }
    };
}

per_set!(
    ml_dsa_44,
    ML_DSA_44,
    1312,
    2420,
    "ML-DSA-44 (FIPS 204, parameter set 1): K=4, L=4, η=2, τ=39, λ=128.\n\nPublic key: 1312 B. Signature: 2420 B."
);
per_set!(
    ml_dsa_65,
    ML_DSA_65,
    1952,
    3309,
    "ML-DSA-65 (FIPS 204, parameter set 2): K=6, L=5, η=4, τ=49, λ=192.\n\nPublic key: 1952 B. Signature: 3309 B."
);
per_set!(
    ml_dsa_87,
    ML_DSA_87,
    2592,
    4627,
    "ML-DSA-87 (FIPS 204, parameter set 3): K=8, L=7, η=2, τ=60, λ=256.\n\nPublic key: 2592 B. Signature: 4627 B."
);
