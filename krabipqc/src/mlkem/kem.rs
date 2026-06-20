//! ML-KEM (FIPS 203 §6.1-6.3): the IND-CCA-secure KEM built from K-PKE
//! via the Fujisaki-Okamoto transform.
//!
//! Internal API (`*_internal`) takes the random inputs as parameters
//! so the result is deterministic — what NIST ACVP tests.

use fixed_bigint::Personality;
use zeroize::Zeroizing;

use crate::encoding::EncodeError;
use crate::field_ext::FieldExt;
use crate::hashing::{sha3_256, sha3_512, shake256};
use crate::mlkem::encoding::ek_modulus_check;
use crate::mlkem::params::{Params, SS_BYTES};
use crate::mlkem::pke;

/// ML-KEM.KeyGen_internal (Alg 16), generic over personality `P`.
pub fn keygen_internal_impl<const K: usize, P>(
    params: &Params<K>,
    d: &[u8; 32],
    z: &[u8; 32],
    ek_out: &mut [u8],
    dk_out: &mut [u8],
) -> Result<(), EncodeError>
where
    P: Personality + FieldExt<P>,
{
    if ek_out.len() != params.ek_bytes || dk_out.len() != params.dk_bytes {
        return Err(EncodeError::BufferTooSmall);
    }

    let dk_pke_len = 384 * K;
    let dk_pke_slot = dk_out
        .get_mut(..dk_pke_len)
        .ok_or(EncodeError::BufferTooSmall)?;
    pke::keygen_impl::<K, P>(params, d, ek_out, dk_pke_slot)?;

    let ek_off = dk_pke_len;
    let h_off = ek_off + params.ek_bytes;
    let z_off = h_off + 32;
    let ek_slot = dk_out
        .get_mut(ek_off..ek_off + params.ek_bytes)
        .ok_or(EncodeError::BufferTooSmall)?;
    ek_slot.copy_from_slice(ek_out);
    let h = sha3_256(&[ek_out]);
    let h_slot = dk_out
        .get_mut(h_off..h_off + 32)
        .ok_or(EncodeError::BufferTooSmall)?;
    h_slot.copy_from_slice(&h);
    let z_slot = dk_out
        .get_mut(z_off..z_off + 32)
        .ok_or(EncodeError::BufferTooSmall)?;
    z_slot.copy_from_slice(z);
    Ok(())
}

/// ML-KEM.Encaps_internal (Alg 17), generic over personality `P`.
pub fn encaps_internal_impl<const K: usize, P>(
    params: &Params<K>,
    ek: &[u8],
    m: &[u8; 32],
    ss_out: &mut [u8; SS_BYTES],
    ct_out: &mut [u8],
) -> Result<(), EncodeError>
where
    P: Personality + FieldExt<P>,
{
    if ek.len() != params.ek_bytes || ct_out.len() != params.ct_bytes {
        return Err(EncodeError::BufferTooSmall);
    }

    // FIPS 203 §7.2 encapsulation-key modulus check on the t_hat
    // portion of ek (first 384*K bytes). Rejects non-canonical
    // encodings with coefficients ≥ q.
    let t_hat_bytes = ek.get(..384 * K).ok_or(EncodeError::BufferTooSmall)?;
    ek_modulus_check::<K>(t_hat_bytes)?;

    let h_ek = sha3_256(&[ek]);
    // g_out splits into (ss, r): both are secret-derived (ss is the
    // shared secret, r is the FO encryption coin). Match
    // decaps_internal_impl's hygiene by Zeroizing both.
    let g_out = Zeroizing::new(sha3_512(&[m, &h_ek]));
    let ss_src = g_out.get(..32).ok_or(EncodeError::BufferTooSmall)?;
    ss_out.copy_from_slice(ss_src);
    let mut r = Zeroizing::new([0u8; 32]);
    let r_src = g_out.get(32..).ok_or(EncodeError::BufferTooSmall)?;
    r.copy_from_slice(r_src);

    pke::encrypt_impl::<K, P>(params, ek, m, &r, ct_out)
}

/// ML-KEM.Decaps_internal (Alg 18), generic over personality `P`.
///
/// Final shared-secret selection between `K'` (success) and `K_bar`
/// (implicit reject) is constant-time regardless of `P`; only the
/// upstream NTT-domain arithmetic is what `P` selects.
pub fn decaps_internal_impl<const K: usize, P>(
    params: &Params<K>,
    dk: &[u8],
    ct: &[u8],
    ss_out: &mut [u8; SS_BYTES],
) -> Result<(), EncodeError>
where
    P: Personality + FieldExt<P>,
{
    if dk.len() != params.dk_bytes || ct.len() != params.ct_bytes {
        return Err(EncodeError::BufferTooSmall);
    }

    let dk_pke_len = 384 * K;
    let dk_pke = dk.get(..dk_pke_len).ok_or(EncodeError::BufferTooSmall)?;
    let ek_pke = dk
        .get(dk_pke_len..dk_pke_len + params.ek_bytes)
        .ok_or(EncodeError::BufferTooSmall)?;
    let h_ek = dk
        .get(dk_pke_len + params.ek_bytes..dk_pke_len + params.ek_bytes + 32)
        .ok_or(EncodeError::BufferTooSmall)?;
    let z = dk
        .get(dk_pke_len + params.ek_bytes + 32..)
        .ok_or(EncodeError::BufferTooSmall)?;

    // FO transient state below is secret-mixed; Zeroizing-wrapped so it
    // doesn't survive past decaps return.
    let mut m_prime = Zeroizing::new([0u8; 32]);
    pke::decrypt_impl::<K, P>(params, dk_pke, ct, &mut m_prime)?;

    let g_out = Zeroizing::new(sha3_512(&[&*m_prime, h_ek]));
    let mut k_prime = Zeroizing::new([0u8; 32]);
    let k_prime_src = g_out.get(..32).ok_or(EncodeError::BufferTooSmall)?;
    k_prime.copy_from_slice(k_prime_src);
    let mut r_prime = Zeroizing::new([0u8; 32]);
    let r_prime_src = g_out.get(32..).ok_or(EncodeError::BufferTooSmall)?;
    r_prime.copy_from_slice(r_prime_src);

    let mut k_bar = Zeroizing::new([0u8; 32]);
    shake256(&[z, ct], &mut *k_bar);

    let mut ct_prime_buf: Zeroizing<[u8; 2048]> = Zeroizing::new([0u8; 2048]); // worst case 1568 (ML-KEM-1024).
    let ct_prime = ct_prime_buf
        .get_mut(..params.ct_bytes)
        .ok_or(EncodeError::BufferTooSmall)?;
    pke::encrypt_impl::<K, P>(params, ek_pke, &m_prime, &r_prime, ct_prime)?;

    let eq = ct_equal(ct, ct_prime)?;
    for i in 0..32 {
        ss_out[i] = (k_prime[i] & eq) | (k_bar[i] & !eq);
    }
    Ok(())
}

/// Constant-time byte-slice equality, returning 0xFF on equal else 0x00.
/// `zip` would silently truncate to the shorter operand and return 0xFF
/// on a shared prefix, so length mismatch is surfaced as Err.
#[inline]
fn ct_equal(a: &[u8], b: &[u8]) -> Result<u8, EncodeError> {
    if a.len() != b.len() {
        return Err(EncodeError::BufferTooSmall);
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    let nonzero = (diff as u32).wrapping_sub(1) >> 31; // 1 if diff == 0, 0 otherwise
    Ok((nonzero as u8).wrapping_neg()) // 0xFF if 1, 0x00 if 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mlkem::params::{ML_KEM_512, ML_KEM_768, ML_KEM_1024};
    use fixed_bigint::{Ct, Nct};

    fn roundtrip<const K: usize>(params: &Params<K>) {
        let d = [0xAAu8; 32];
        let z = [0xBBu8; 32];
        let mut ek = vec![0u8; params.ek_bytes];
        let mut dk = vec![0u8; params.dk_bytes];
        keygen_internal_impl::<K, Nct>(params, &d, &z, &mut ek, &mut dk).unwrap();

        let m = [0xC5u8; 32];
        let mut ss_enc = [0u8; SS_BYTES];
        let mut ct = vec![0u8; params.ct_bytes];
        encaps_internal_impl::<K, Nct>(params, &ek, &m, &mut ss_enc, &mut ct).unwrap();

        let mut ss_dec = [0u8; SS_BYTES];
        decaps_internal_impl::<K, Nct>(params, &dk, &ct, &mut ss_dec).unwrap();
        assert_eq!(ss_dec, ss_enc, "shared secret mismatch");
    }

    #[test]
    fn roundtrip_512() {
        roundtrip(&ML_KEM_512);
    }

    #[test]
    fn roundtrip_768() {
        roundtrip(&ML_KEM_768);
    }

    #[test]
    fn roundtrip_1024() {
        roundtrip(&ML_KEM_1024);
    }

    #[test]
    fn decaps_rejects_overlong_ct() {
        let params = &ML_KEM_768;
        let d = [9u8; 32];
        let z = [10u8; 32];
        let mut ek = vec![0u8; params.ek_bytes];
        let mut dk = vec![0u8; params.dk_bytes];
        keygen_internal_impl::<3, Nct>(params, &d, &z, &mut ek, &mut dk).unwrap();

        let mut ss = [0u8; SS_BYTES];
        let mut ct = vec![0u8; params.ct_bytes];
        encaps_internal_impl::<3, Nct>(params, &ek, &[11u8; 32], &mut ss, &mut ct).unwrap();
        ct.push(0xAA);

        let mut bogus = [0u8; SS_BYTES];
        assert_eq!(
            decaps_internal_impl::<3, Nct>(params, &dk, &ct, &mut bogus),
            Err(EncodeError::BufferTooSmall)
        );
    }

    /// Cross-personality equivalence: same seeds/randomness through the
    /// Nct and Ct paths must produce byte-identical `ek`, `dk`, `ss`,
    /// and `ct`. Load-bearing for routing the per-set facade through
    /// `Ct` without diverging on output bytes.
    fn cross_personality_equiv<const K: usize>(params: &Params<K>) {
        let d = [0x5Au8; 32];
        let z = [0xA5u8; 32];
        let mut ek_nct = vec![0u8; params.ek_bytes];
        let mut dk_nct = vec![0u8; params.dk_bytes];
        let mut ek_ct = vec![0u8; params.ek_bytes];
        let mut dk_ct = vec![0u8; params.dk_bytes];
        keygen_internal_impl::<K, Nct>(params, &d, &z, &mut ek_nct, &mut dk_nct).unwrap();
        keygen_internal_impl::<K, Ct>(params, &d, &z, &mut ek_ct, &mut dk_ct).unwrap();
        assert_eq!(ek_nct, ek_ct, "ek Nct/Ct mismatch");
        assert_eq!(dk_nct, dk_ct, "dk Nct/Ct mismatch");

        let m = [0x6Cu8; 32];
        let mut ss_enc_nct = [0u8; SS_BYTES];
        let mut ss_enc_ct = [0u8; SS_BYTES];
        let mut ct_nct = vec![0u8; params.ct_bytes];
        let mut ct_ct = vec![0u8; params.ct_bytes];
        encaps_internal_impl::<K, Nct>(params, &ek_nct, &m, &mut ss_enc_nct, &mut ct_nct).unwrap();
        encaps_internal_impl::<K, Ct>(params, &ek_ct, &m, &mut ss_enc_ct, &mut ct_ct).unwrap();
        assert_eq!(ct_nct, ct_ct, "ciphertext Nct/Ct mismatch");
        assert_eq!(ss_enc_nct, ss_enc_ct, "encaps ss Nct/Ct mismatch");

        let mut ss_dec_nct = [0u8; SS_BYTES];
        let mut ss_dec_ct = [0u8; SS_BYTES];
        decaps_internal_impl::<K, Nct>(params, &dk_nct, &ct_nct, &mut ss_dec_nct).unwrap();
        decaps_internal_impl::<K, Ct>(params, &dk_ct, &ct_ct, &mut ss_dec_ct).unwrap();
        assert_eq!(ss_dec_nct, ss_dec_ct, "decaps ss Nct/Ct mismatch");
        assert_eq!(ss_dec_nct, ss_enc_nct, "encaps/decaps disagree (Nct)");
    }

    #[test]
    fn cross_personality_equiv_512() {
        cross_personality_equiv(&ML_KEM_512);
    }

    #[test]
    fn cross_personality_equiv_768() {
        cross_personality_equiv(&ML_KEM_768);
    }

    #[test]
    fn cross_personality_equiv_1024() {
        cross_personality_equiv(&ML_KEM_1024);
    }

    /// FIPS 203 §7.2: an ek whose decoded t_hat has any coefficient ≥ q
    /// must be rejected by encaps. Forge one by setting the first
    /// 12-bit coefficient to 0xFFF (4095, well above q = 3329).
    #[test]
    fn encaps_rejects_non_canonical_ek() {
        let params = &ML_KEM_768;
        let d = [4u8; 32];
        let z = [5u8; 32];
        let mut ek = vec![0u8; params.ek_bytes];
        let mut dk = vec![0u8; params.dk_bytes];
        keygen_internal_impl::<3, Nct>(params, &d, &z, &mut ek, &mut dk).unwrap();

        // First coefficient is `ek[0] | ((ek[1] & 0x0F) << 8)`; force to 0xFFF.
        ek[0] = 0xFF;
        ek[1] = (ek[1] & 0xF0) | 0x0F;

        let mut ss = [0u8; SS_BYTES];
        let mut ct = vec![0u8; params.ct_bytes];
        assert_eq!(
            encaps_internal_impl::<3, Nct>(params, &ek, &[6u8; 32], &mut ss, &mut ct),
            Err(EncodeError::NotCanonical)
        );
    }

    #[test]
    fn decaps_rejects_corrupted_ct() {
        let params = &ML_KEM_768;
        let d = [1u8; 32];
        let z = [2u8; 32];
        let mut ek = vec![0u8; params.ek_bytes];
        let mut dk = vec![0u8; params.dk_bytes];
        keygen_internal_impl::<3, Nct>(params, &d, &z, &mut ek, &mut dk).unwrap();

        let mut ss_enc = [0u8; SS_BYTES];
        let mut ct = vec![0u8; params.ct_bytes];
        encaps_internal_impl::<3, Nct>(params, &ek, &[3u8; 32], &mut ss_enc, &mut ct).unwrap();

        // Flip a bit and re-decaps — should yield the implicit-rejection key,
        // not the original shared secret.
        ct[0] ^= 1;
        let mut ss_dec = [0u8; SS_BYTES];
        decaps_internal_impl::<3, Nct>(params, &dk, &ct, &mut ss_dec).unwrap();
        assert_ne!(ss_dec, ss_enc);
    }
}
