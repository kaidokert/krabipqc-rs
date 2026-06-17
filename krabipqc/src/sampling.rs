//! Sampling primitives used by ML-DSA verify (FIPS 204 §7.3):
//! [`rej_ntt_poly`] for `A_hat`, [`sample_in_ball`] for the challenge
//! polynomial, [`bit_unpack_signed`] for decoding the signature's `z`.

use fixed_bigint::Nct;

use crate::field_ext::FieldExt;
use crate::hashing::{Shake128Stream, Shake256Stream};
use crate::params::{N, Q, Q_N_PRIME, Q_R2_MOD_Q, from_signed};
use crate::poly::Poly;

type DPoly = Poly<u32>;

/// CoeffFromThreeBytes (FIPS 204 Alg 14).
#[inline]
fn coeff_from_three_bytes(b0: u8, b1: u8, b2: u8) -> Option<u32> {
    let b2p = (b2 & 0x7F) as u32;
    let z = (b2p << 16) | ((b1 as u32) << 8) | (b0 as u32);
    if z < Q { Some(z) } else { None }
}

/// RejNTTPoly (FIPS 204 Alg 30) returning coefficients in Montgomery
/// form so they feed directly into [`crate::ntt::mul_ntt`] without a
/// per-coefficient redc.
pub fn rej_ntt_poly(rho: &[u8; 32], s: u8, r: u8) -> DPoly {
    let mut out = DPoly::zero();
    let mut stream = Shake128Stream::new(&[rho, &[s], &[r]]);
    let mut block = [0u8; Shake128Stream::RATE];
    let mut block_pos = block.len();
    let mut j = 0usize;
    while j < N {
        if block_pos + 3 > block.len() {
            stream.squeeze(&mut block);
            block_pos = 0;
        }
        let b0 = block[block_pos];
        let b1 = block[block_pos + 1];
        let b2 = block[block_pos + 2];
        block_pos += 3;
        if let Some(c) = coeff_from_three_bytes(b0, b1, b2) {
            out.coeffs[j] = <Nct as FieldExt<Nct>>::reduce(c, Q, Q_N_PRIME, Q_R2_MOD_Q);
            j += 1;
        }
    }
    out
}

/// SampleInBall (FIPS 204 Alg 29): polynomial with `tau` ±1
/// coefficients.
pub fn sample_in_ball(rho: &[u8], tau: usize) -> DPoly {
    let mut c = DPoly::zero();
    let mut stream = Shake256Stream::new(&[rho]);
    let mut s = [0u8; 8];
    stream.squeeze(&mut s);
    let sign_bit = |idx: usize| -> u8 { (s[idx / 8] >> (idx % 8)) & 1 };

    let mut block = [0u8; Shake256Stream::RATE];
    let mut block_pos = block.len();
    for i in (N - tau)..N {
        loop {
            if block_pos >= block.len() {
                stream.squeeze(&mut block);
                block_pos = 0;
            }
            let j = block[block_pos] as usize;
            block_pos += 1;
            if j <= i {
                c.coeffs[i] = c.coeffs[j];
                let sgn = sign_bit(i + tau - N);
                let val: u32 = if sgn == 0 { 1 } else { Q - 1 };
                c.coeffs[j] = val;
                break;
            }
        }
    }
    c
}

/// BitUnpack (FIPS 204 Alg 18) for the signed range
/// `[b - 2^c + 1, b]`; outputs canonical Z_q reps.
pub fn bit_unpack_signed(bytes: &[u8], _a: u32, b: u32, c_bits: usize) -> DPoly {
    let mut out = DPoly::zero();
    debug_assert!(bytes.len() * 8 >= N * c_bits);
    let mask = (1u32 << c_bits) - 1;
    let mut acc: u64 = 0;
    let mut bits_in_acc: u32 = 0;
    let mut byte_idx = 0usize;
    for j in 0..N {
        while bits_in_acc < c_bits as u32 {
            acc |= (bytes[byte_idx] as u64) << bits_in_acc;
            byte_idx += 1;
            bits_in_acc += 8;
        }
        let zp = (acc as u32) & mask;
        acc >>= c_bits;
        bits_in_acc -= c_bits as u32;
        let signed = (b as i64) - (zp as i64);
        out.coeffs[j] = from_signed(signed as i32, Q);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::ml_dsa_44::TAU;
    use crate::params::to_signed;

    #[test]
    fn coeff_from_three_bytes_basic() {
        assert_eq!(coeff_from_three_bytes(0, 0, 0), Some(0));
        assert_eq!(coeff_from_three_bytes(0x00, 0xE0, 0x7F), Some(Q - 1));
        assert_eq!(coeff_from_three_bytes(0, 0, 0x80), Some(0));
        assert_eq!(coeff_from_three_bytes(0xFF, 0xFF, 0x7F), None);
        assert_eq!(coeff_from_three_bytes(0x01, 0xE0, 0x7F), None);
    }

    #[test]
    fn rej_ntt_poly_smoke() {
        let rho = [0u8; 32];
        let p = rej_ntt_poly(&rho, 0, 0);
        for &c in &p.coeffs {
            assert!(c < Q);
        }
    }

    #[test]
    fn sample_in_ball_has_tau_nonzero_and_norm_one() {
        let rho = [9u8; 32];
        let c = sample_in_ball(&rho, TAU);
        let mut nonzero = 0usize;
        for &v in &c.coeffs {
            let s = to_signed(v, Q);
            if s != 0 {
                nonzero += 1;
                assert!(s == 1 || s == -1);
            }
        }
        assert_eq!(nonzero, TAU);
    }
}
