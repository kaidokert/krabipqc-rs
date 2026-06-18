//! ML-KEM sampling (FIPS 203 §4.2):
//! * `SampleNTT` (Alg 6) — rejection sampling from a SHAKE-128 stream;
//!   produces an NTT-domain polynomial directly.
//! * `SamplePolyCBD_eta` (Alg 7) — centered binomial distribution, used
//!   for the secret/error polys.

use fixed_bigint::Nct;
use modmath::basic::pre_reduced as pr;

use crate::encoding::EncodeError;
use crate::field_ext::FieldExt;
use crate::hashing::{Shake128Stream, Shake256Stream};
use crate::mlkem::params::{N, Q, Q_N_PRIME, Q_R2_MOD_Q};
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
/// Z_q. `bytes` must have length `64 * eta`.
pub fn sample_poly_cbd(bytes: &[u8], eta: u32) -> Result<Poly<u32>, EncodeError> {
    let mut out = Poly::<u32>::zero();
    let two_eta = 2 * eta as usize;
    let bit = |k: usize| -> Result<u32, EncodeError> {
        let byte = *bytes.get(k / 8).ok_or(EncodeError::BufferTooSmall)?;
        Ok(((byte >> (k % 8)) & 1) as u32)
    };
    for i in 0..N {
        let base = i * two_eta;
        let mut x = 0u32;
        let mut y = 0u32;
        for j in 0..eta as usize {
            x += bit(base + j)?;
        }
        for j in 0..eta as usize {
            y += bit(base + eta as usize + j)?;
        }
        out.coeffs[i] = pr::sub::<u32>(x, y, Q);
    }
    Ok(out)
}

/// PRF_eta(s, b) — SHAKE-256 with output length 64*eta bytes, used by
/// ML-KEM to expand a seed into CBD input. The single-byte `b` is the
/// per-coefficient index.
pub fn prf_eta(s: &[u8; 32], b: u8, eta: u32) -> [u8; 64 * 6] {
    // Worst-case bound: eta <= 3 ⇒ output ≤ 192 bytes (well within 64*6 = 384).
    let mut buf = [0u8; 64 * 6];
    let want = 64 * eta as usize;
    let mut stream = Shake256Stream::new(&[s, &[b]]);
    stream.squeeze(&mut buf[..want]);
    buf
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
    eta1: u32,
) -> Result<(PolyVec<u32, K>, PolyVec<u32, K>), EncodeError> {
    let mut s = PolyVec::<u32, K>::zero();
    let mut e = PolyVec::<u32, K>::zero();
    let want = 64 * eta1 as usize;
    for i in 0..K {
        let buf = prf_eta(sigma, i as u8, eta1);
        let slice = buf.get(..want).ok_or(EncodeError::BufferTooSmall)?;
        s.v[i] = sample_poly_cbd(slice, eta1)?;
    }
    for i in 0..K {
        let buf = prf_eta(sigma, (K + i) as u8, eta1);
        let slice = buf.get(..want).ok_or(EncodeError::BufferTooSmall)?;
        e.v[i] = sample_poly_cbd(slice, eta1)?;
    }
    Ok((s, e))
}

/// (r, e1, e2) bundle produced by [`sample_re`] for K-PKE.Encrypt.
pub type EncryptSamples<const K: usize> = (PolyVec<u32, K>, PolyVec<u32, K>, Poly<u32>);

/// Sample r, e1, e2 for K-PKE.Encrypt (FIPS 203 Alg 13 lines 8-15):
/// r_i = CBD_eta1(PRF(r_seed, i))           for i in 0..K
/// e1_i = CBD_eta2(PRF(r_seed, K + i))      for i in 0..K
/// e2  = CBD_eta2(PRF(r_seed, 2K))
pub fn sample_re<const K: usize>(
    r_seed: &[u8; 32],
    eta1: u32,
    eta2: u32,
) -> Result<EncryptSamples<K>, EncodeError> {
    let mut r = PolyVec::<u32, K>::zero();
    let mut e1 = PolyVec::<u32, K>::zero();
    let want1 = 64 * eta1 as usize;
    let want2 = 64 * eta2 as usize;
    for i in 0..K {
        let buf = prf_eta(r_seed, i as u8, eta1);
        let slice = buf.get(..want1).ok_or(EncodeError::BufferTooSmall)?;
        r.v[i] = sample_poly_cbd(slice, eta1)?;
    }
    for i in 0..K {
        let buf = prf_eta(r_seed, (K + i) as u8, eta2);
        let slice = buf.get(..want2).ok_or(EncodeError::BufferTooSmall)?;
        e1.v[i] = sample_poly_cbd(slice, eta2)?;
    }
    let buf = prf_eta(r_seed, (2 * K) as u8, eta2);
    let slice = buf.get(..want2).ok_or(EncodeError::BufferTooSmall)?;
    let e2 = sample_poly_cbd(slice, eta2)?;
    Ok((r, e1, e2))
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
        let p = sample_poly_cbd(&bytes, 2).unwrap();
        for &c in &p.coeffs {
            let s = to_signed(c, Q);
            assert!(s.unsigned_abs() <= 2);
        }
    }

    #[test]
    fn cbd_eta3_in_range() {
        let bytes = [0x5Au8; 192]; // 64 * 3
        let p = sample_poly_cbd(&bytes, 3).unwrap();
        for &c in &p.coeffs {
            let s = to_signed(c, Q);
            assert!(s.unsigned_abs() <= 3);
        }
    }

    #[test]
    fn cbd_short_buf_errors() {
        let bytes = [0u8; 127]; // need 128 for eta=2
        assert_eq!(sample_poly_cbd(&bytes, 2), Err(EncodeError::BufferTooSmall));
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
        let (s, e) = sample_se::<2>(&sigma, 3).unwrap();
        for v in s.v.iter().chain(e.v.iter()) {
            for &c in &v.coeffs {
                assert!(to_signed(c, Q).unsigned_abs() <= 3);
            }
        }
    }
}
