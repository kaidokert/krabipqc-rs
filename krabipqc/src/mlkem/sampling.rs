//! ML-KEM sampling (FIPS 203 §4.2):
//! * `SampleNTT` (Alg 6) — rejection sampling from a SHAKE-128 stream;
//!   produces an NTT-domain polynomial directly.
//! * `SamplePolyCBD_eta` (Alg 7) — centered binomial distribution, used
//!   for the secret/error polys.

use fixed_bigint::Nct;
use modmath::basic::pre_reduced as pr;

use zeroize::Zeroizing;

use crate::encoding::EncodeError;
use crate::field_ext::FieldExt;
use crate::hashing::{Shake128Stream, Shake256Stream};
use crate::mlkem::params::{Eta, N, PRF_BUF_LEN, Q, Q_N_PRIME, Q_R2_MOD_Q};
use crate::poly::Poly;
use crate::polyvec::{PolyMatrix, PolyVec};

/// SampleNTT (Alg 6): rejection-sample 256 12-bit coefficients < q from
/// a SHAKE-128 stream over `seed || j || i` (32 + 1 + 1 = 34 bytes).
///
/// Squeezes one full SHAKE-128 rate-block (168 bytes = 56 triples = up to
/// 112 candidate coefficients) at a time instead of per-triple.
pub fn sample_ntt(rho: &[u8; 32], j: u8, i: u8) -> Poly<u32> {
    let mut out = Poly::<u32>::zero();
    let mut stream = Shake128Stream::new(&[rho, &[j], &[i]]);
    let mut block = [0u8; Shake128Stream::RATE];
    let mut block_pos = block.len();
    let mut idx = 0usize;
    while idx < N {
        if block_pos + 3 > block.len() {
            stream.squeeze(&mut block);
            block_pos = 0;
        }
        let b0 = block[block_pos] as u32;
        let b1 = block[block_pos + 1] as u32;
        let b2 = block[block_pos + 2] as u32;
        block_pos += 3;
        let d1 = b0 | ((b1 & 0x0F) << 8);
        let d2 = (b1 >> 4) | (b2 << 4);
        if d1 < Q {
            // NTT-domain convention: coefficients carry Montgomery form.
            out.coeffs[idx] = <Nct as FieldExt<Nct>>::reduce(d1, Q, Q_N_PRIME, Q_R2_MOD_Q);
            idx += 1;
        }
        if d2 < Q && idx < N {
            out.coeffs[idx] = <Nct as FieldExt<Nct>>::reduce(d2, Q, Q_N_PRIME, Q_R2_MOD_Q);
            idx += 1;
        }
    }
    out
}

/// SamplePolyCBD_eta (Alg 7): per coefficient, sum `eta` bits → x and
/// the next `eta` bits → y; emit `x - y ∈ [-eta, eta]` in canonical
/// Z_q. `bytes` must have length `eta.buf_len()` (= 64·η).
pub fn sample_poly_cbd(bytes: &[u8], eta: Eta) -> Result<Poly<u32>, EncodeError> {
    let mut out = Poly::<u32>::zero();
    let eta_val = eta.value() as usize;
    let two_eta = 2 * eta_val;
    let bit = |k: usize| -> Result<u32, EncodeError> {
        let byte = *bytes.get(k / 8).ok_or(EncodeError::BufferTooSmall)?;
        Ok(((byte >> (k % 8)) & 1) as u32)
    };
    for i in 0..N {
        let base = i * two_eta;
        let mut x = 0u32;
        let mut y = 0u32;
        for j in 0..eta_val {
            x += bit(base + j)?;
        }
        for j in 0..eta_val {
            y += bit(base + eta_val + j)?;
        }
        out.coeffs[i] = pr::sub::<u32>(x, y, Q);
    }
    Ok(out)
}

/// One PRF_eta + SamplePolyCBD_eta step: SHAKE-256-squeeze `eta.buf_len()`
/// bytes from `s || b` and run them through the centered binomial
/// distribution. Inlines the buffer so callers don't move a
/// [`PRF_BUF_LEN`]-byte array around by value.
fn sample_cbd_from_seed(s: &[u8; 32], b: u8, eta: Eta) -> Result<Poly<u32>, EncodeError> {
    // The squeezed bytes become CBD-sampled secret coefficients, so
    // wrap the scratch buffer in Zeroizing to clear it on return.
    let mut buf: Zeroizing<[u8; PRF_BUF_LEN]> = Zeroizing::new([0u8; PRF_BUF_LEN]);
    let slot = buf
        .get_mut(..eta.buf_len())
        .ok_or(EncodeError::BufferTooSmall)?;
    Shake256Stream::new(&[s, &[b]]).squeeze(slot);
    sample_poly_cbd(slot, eta)
}

/// ExpandA (FIPS 203 §6.1.1): build the K×K matrix Â in NTT domain.
pub fn expand_a<const K: usize>(rho: &[u8; 32]) -> PolyMatrix<u32, K, K> {
    let mut m = PolyMatrix::<u32, K, K>::zero();
    for i in 0..K {
        for j in 0..K {
            // FIPS 203: A_hat[i,j] = SampleNTT(rho || j || i)
            m.rows[i].v[j] = sample_ntt(rho, j as u8, i as u8);
        }
    }
    m
}

/// Sample s and e — K-PKE.KeyGen step (FIPS 203 Alg 12 lines 7-12):
/// s_i = SamplePolyCBD_eta1(PRF_eta1(sigma, N))
/// e_i = SamplePolyCBD_eta1(PRF_eta1(sigma, N + K))
/// with N starting at 0 and incrementing.
pub fn sample_se<const K: usize>(
    sigma: &[u8; 32],
    eta1: Eta,
) -> Result<(PolyVec<u32, K>, PolyVec<u32, K>), EncodeError> {
    let mut s = PolyVec::<u32, K>::zero();
    let mut e = PolyVec::<u32, K>::zero();
    for i in 0..K {
        s.v[i] = sample_cbd_from_seed(sigma, i as u8, eta1)?;
    }
    for i in 0..K {
        e.v[i] = sample_cbd_from_seed(sigma, (K + i) as u8, eta1)?;
    }
    Ok((s, e))
}

/// Sample r (= y in encrypt) and e2, skipping e1.
///
/// Used by the encrypt paths to avoid holding e1 on the stack while the
/// u-rows are being generated — each `e1[i]` is sampled on demand via
/// [`sample_e1_row`] instead. Saves K×1 KiB of peak stack vs the old
/// `sample_re` bundle.
///
/// Nonce assignment (FIPS 203 Alg 13 lines 8-15):
/// r_i  = CBD_eta1(PRF(r_seed, i))      for i in 0..K
/// e1_i = CBD_eta2(PRF(r_seed, K + i))  ← skipped here
/// e2   = CBD_eta2(PRF(r_seed, 2K))
pub(crate) fn sample_re_y_e2<const K: usize>(
    r_seed: &[u8; 32],
    eta1: Eta,
    eta2: Eta,
) -> Result<(PolyVec<u32, K>, Poly<u32>), EncodeError> {
    let mut r = PolyVec::<u32, K>::zero();
    for i in 0..K {
        r.v[i] = sample_cbd_from_seed(r_seed, i as u8, eta1)?;
    }
    let e2 = sample_cbd_from_seed(r_seed, (2 * K) as u8, eta2)?;
    Ok((r, e2))
}

/// Sample the i-th e1 row on demand (FIPS 203 Alg 13 line 10).
///
/// Caller passes the loop index `i`; nonce is `K + i`.
pub(crate) fn sample_e1_row<const K: usize>(
    r_seed: &[u8; 32],
    i: usize,
    eta2: Eta,
) -> Result<Poly<u32>, EncodeError> {
    sample_cbd_from_seed(r_seed, (K + i) as u8, eta2)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mlkem::params::Q;
    use crate::params::to_signed;

    #[test]
    fn sample_ntt_in_range() {
        let rho = [0u8; 32];
        let p = sample_ntt(&rho, 0, 0);
        for &c in &p.coeffs {
            assert!(c < Q);
        }
    }

    #[test]
    fn cbd_eta2_in_range() {
        let bytes = [0xACu8; 128]; // 64 * 2
        let p = sample_poly_cbd(&bytes, Eta::Two).unwrap();
        for &c in &p.coeffs {
            let s = to_signed(c, Q);
            assert!(s.unsigned_abs() <= 2);
        }
    }

    #[test]
    fn cbd_eta3_in_range() {
        let bytes = [0x5Au8; 192]; // 64 * 3
        let p = sample_poly_cbd(&bytes, Eta::Three).unwrap();
        for &c in &p.coeffs {
            let s = to_signed(c, Q);
            assert!(s.unsigned_abs() <= 3);
        }
    }

    #[test]
    fn cbd_short_buf_errors() {
        let bytes = [0u8; 127]; // need 128 for eta=2
        assert_eq!(
            sample_poly_cbd(&bytes, Eta::Two),
            Err(EncodeError::BufferTooSmall)
        );
    }

    #[test]
    fn expand_a_smoke() {
        let rho = [1u8; 32];
        let a = expand_a::<3>(&rho);
        for row in &a.rows {
            for poly in &row.v {
                for &c in &poly.coeffs {
                    assert!(c < Q);
                }
            }
        }
    }

    #[test]
    fn sample_se_smoke() {
        let sigma = [2u8; 32];
        let (s, e) = sample_se::<2>(&sigma, Eta::Three).unwrap();
        for v in s.v.iter().chain(e.v.iter()) {
            for &c in &v.coeffs {
                assert!(to_signed(c, Q).unsigned_abs() <= 3);
            }
        }
    }
}
