//! Per-parameter-set wrappers (ML-KEM-512, ML-KEM-768, ML-KEM-1024) over the
//! generic [`crate::mlkem::kem`] functions.
//!
//! Each submodule exposes:
//! * `EK_BYTES`, `DK_BYTES`, `CT_BYTES`, `SS_BYTES` — fixed-size byte lengths.
//! * `keygen_from_seed(d, z)` — FIPS 203 Alg 16.
//! * `encaps_from_seed(ek, m)` — FIPS 203 Alg 17.
//! * `decaps(dk, ct)` — FIPS 203 Alg 18.
//!
//! All three route NTT-domain Mont arithmetic through `wide::ct::mul`
//! — decaps mixes the dk-derived `K'` with adversary-controlled `ct`,
//! and encaps/keygen consume secret randomness, so a variable-time
//! REDC finalize is unsafe on every path.
//!
//! Every entry returns `Result` so that no internal codec / buffer
//! mismatch can panic. With the const-pinned buffers allocated here the
//! Err variant is structurally unreachable for in-tree callers, but the
//! shape is preserved end-to-end.

macro_rules! per_set {
    ($mod:ident, $params:ident, $ek:expr, $dk:expr, $ct:expr, $doc:expr) => {
        #[doc = $doc]
        pub mod $mod {
            use fixed_bigint::Ct;
            use zeroize::Zeroizing;

            use crate::mlkem::kem;
            use crate::mlkem::params::{SS_BYTES, $params};
            use crate::{EncodeError, KemError};

            pub const EK_BYTES: usize = $ek;
            pub const DK_BYTES: usize = $dk;
            pub const CT_BYTES: usize = $ct;
            pub use crate::mlkem::params::SS_BYTES as SHARED_SECRET_BYTES;

            /// Deterministic ML-KEM KeyGen (FIPS 203 §7.1 Alg 16).
            /// Takes seeds `d` and `z`; returns `(ek, dk)`.
            /// Use [`keygen`] when seeds should come from an RNG.
            pub fn keygen_from_seed(
                d: &[u8; 32],
                z: &[u8; 32],
            ) -> Result<([u8; EK_BYTES], [u8; DK_BYTES]), EncodeError> {
                let mut ek = [0u8; EK_BYTES];
                let mut dk = [0u8; DK_BYTES];
                kem::keygen_internal_impl::<_, Ct>(&$params, d, z, &mut ek, &mut dk)?;
                Ok((ek, dk))
            }

            /// Deterministic ML-KEM Encaps (FIPS 203 §7.2 Alg 17).
            /// Takes seed `m`; returns `(shared_secret, ciphertext)`.
            /// Use [`encaps`] when `m` should come from an RNG.
            pub fn encaps_from_seed(
                ek: &[u8; EK_BYTES],
                m: &[u8; 32],
            ) -> Result<([u8; SS_BYTES], [u8; CT_BYTES]), EncodeError> {
                let mut ss = [0u8; SS_BYTES];
                let mut ct = [0u8; CT_BYTES];
                kem::encaps_internal_impl::<_, Ct>(&$params, ek, m, &mut ss, &mut ct)?;
                Ok((ss, ct))
            }

            /// ML-KEM Decaps (FIPS 203 §7.3 Alg 18). Deterministic:
            /// no randomness input. Returns the shared secret.
            pub fn decaps(
                dk: &[u8; DK_BYTES],
                ct: &[u8; CT_BYTES],
            ) -> Result<[u8; SS_BYTES], EncodeError> {
                let mut ss = [0u8; SS_BYTES];
                kem::decaps_internal_impl::<_, Ct>(&$params, dk, ct, &mut ss)?;
                Ok(ss)
            }

            /// RNG-driven ML-KEM KeyGen. Draws 64 bytes (`d` and `z`,
            /// 32 each) from the RNG. `TryCryptoRng` lets embedded HW
            /// RNGs that can fail propagate their error.
            pub fn keygen<R: rand_core::TryCryptoRng + ?Sized>(
                rng: &mut R,
            ) -> Result<([u8; EK_BYTES], [u8; DK_BYTES]), KemError<R::Error>> {
                let mut d = Zeroizing::new([0u8; 32]);
                let mut z = Zeroizing::new([0u8; 32]);
                rng.try_fill_bytes(&mut *d).map_err(KemError::Rng)?;
                rng.try_fill_bytes(&mut *z).map_err(KemError::Rng)?;
                Ok(keygen_from_seed(&d, &z)?)
            }

            /// RNG-driven ML-KEM Encaps. Draws the 32-byte `m` randomness
            /// from the RNG.
            pub fn encaps<R: rand_core::TryCryptoRng + ?Sized>(
                ek: &[u8; EK_BYTES],
                rng: &mut R,
            ) -> Result<([u8; SS_BYTES], [u8; CT_BYTES]), KemError<R::Error>> {
                let mut m = Zeroizing::new([0u8; 32]);
                rng.try_fill_bytes(&mut *m).map_err(KemError::Rng)?;
                Ok(encaps_from_seed(ek, &m)?)
            }
        }
    };
}

per_set!(
    ml_kem_512,
    ML_KEM_512,
    800,
    1632,
    768,
    "ML-KEM-512 (FIPS 203, parameter set 1): K=2, η₁=3, η₂=2, d_u=10, d_v=4.\n\nEncapsulation key: 800 B. Decapsulation key: 1632 B. Ciphertext: 768 B. Shared secret: 32 B."
);
per_set!(
    ml_kem_768,
    ML_KEM_768,
    1184,
    2400,
    1088,
    "ML-KEM-768 (FIPS 203, parameter set 2): K=3, η₁=2, η₂=2, d_u=10, d_v=4.\n\nEncapsulation key: 1184 B. Decapsulation key: 2400 B. Ciphertext: 1088 B. Shared secret: 32 B."
);
per_set!(
    ml_kem_1024,
    ML_KEM_1024,
    1568,
    3168,
    1568,
    "ML-KEM-1024 (FIPS 203, parameter set 3): K=4, η₁=2, η₂=2, d_u=11, d_v=5.\n\nEncapsulation key: 1568 B. Decapsulation key: 3168 B. Ciphertext: 1568 B. Shared secret: 32 B."
);

#[cfg(test)]
mod tests {
    use super::*;

    struct FixedRng {
        byte: u8,
    }
    impl rand_core::TryRng for FixedRng {
        type Error = core::convert::Infallible;
        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Ok(u32::from_le_bytes([self.byte; 4]))
        }
        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            Ok(u64::from_le_bytes([self.byte; 8]))
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
            dest.fill(self.byte);
            Ok(())
        }
    }
    impl rand_core::TryCryptoRng for FixedRng {}

    #[test]
    fn kem_keygen_random_matches_internal() {
        let mut rng = FixedRng { byte: 0x51 };
        let (ek_r, dk_r) = ml_kem_512::keygen(&mut rng).unwrap();
        let (ek_d, dk_d) = ml_kem_512::keygen_from_seed(&[0x51u8; 32], &[0x51u8; 32]).unwrap();
        assert_eq!(ek_r, ek_d);
        assert_eq!(dk_r, dk_d);
    }

    #[test]
    fn kem_encaps_random_roundtrip() {
        let (ek, dk) = ml_kem_512::keygen_from_seed(&[0x51u8; 32], &[0x52u8; 32]).unwrap();
        let mut rng = FixedRng { byte: 0x53 };
        let (ss_enc, ct) = ml_kem_512::encaps(&ek, &mut rng).unwrap();
        let ss_dec = ml_kem_512::decaps(&dk, &ct).unwrap();
        assert_eq!(ss_enc, ss_dec);
    }
}
