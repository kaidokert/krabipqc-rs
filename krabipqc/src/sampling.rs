//! Sampling primitives for ML-DSA (FIPS 204 §7.3).
//!
//! Secret-derived samplers ([`rej_bounded_poly`] and the helpers it
//! drives) take a fixed-budget CT lookup path so the per-byte
//! rejection timing doesn't leak `rho_prime`.

use fixed_bigint::Nct;

use crate::encoding::EncodeError;
use crate::field_ext::FieldExt;
use crate::hashing::{Shake128Stream, Shake256Stream};
use crate::params::{Eta, N, Q, Q_N_PRIME, Q_R2_MOD_Q, from_signed};
use crate::poly::Poly;
use crate::polyvec::{PolyMatrix, PolyVec};

type DPoly = Poly<u32>;

/// CoeffFromHalfByte (FIPS 204 Alg 15). Variable-time; the CT-amplified
/// primary path of [`rej_bounded_poly`] uses
/// [`ct_coeff_from_half_byte`] instead and only falls through here on
/// the `< 2^-30` tail event.
#[inline]
fn coeff_from_half_byte(b: u8, eta: Eta) -> Option<i32> {
    match eta {
        Eta::Eta2 => {
            if b < 15 {
                Some(2 - (b as i32 % 5))
            } else {
                None
            }
        }
        Eta::Eta4 => {
            if b < 9 {
                Some(4 - b as i32)
            } else {
                None
            }
        }
    }
}

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

/// RejBoundedPoly (FIPS 204 Alg 31): poly with coefficients in
/// `[-eta, eta]`.
///
/// `rho_prime` is secret-derived, so the per-byte rejection timing of
/// the spec's variable-time loop leaks. This version squeezes a
/// fixed budget of SHAKE-256 blocks up front and walks every candidate
/// nibble branchlessly with a mask. Budget is sized so the tail
/// probability of falling through to [`rej_bounded_poly_fallback`] is
/// `< 2^-30` for `eta = 4` (the worst case).
pub fn rej_bounded_poly(rho_prime: &[u8; 64], r: u16, eta: Eta) -> DPoly {
    // Block = 136 bytes = 272 candidate nibbles; 4 blocks → 1088
    // candidates. With N = 256 the probability of < 256 accepts sits
    // ~30σ above target for eta=2 and ~22σ for eta=4.
    const K_BLOCKS: usize = 4;
    const BUF_LEN: usize = K_BLOCKS * Shake256Stream::RATE;

    let mut out = DPoly::zero();
    let r_bytes = r.to_le_bytes();
    let mut stream = Shake256Stream::new(&[rho_prime, &r_bytes]);

    let mut buf = [0u8; BUF_LEN];
    stream.squeeze(&mut buf);

    let mut j: u32 = 0;
    for &b in buf.iter() {
        let (accept_lo, val_lo) = ct_coeff_from_half_byte(b & 0x0F, eta);
        ct_maybe_write(&mut out.coeffs, &mut j, accept_lo, val_lo);
        let (accept_hi, val_hi) = ct_coeff_from_half_byte(b >> 4, eta);
        ct_maybe_write(&mut out.coeffs, &mut j, accept_hi, val_hi);
    }

    if (j as usize) < N {
        rej_bounded_poly_fallback(&mut stream, &mut out, j as usize, eta);
    }

    out
}

/// Variable-time tail used when the fixed budget of
/// [`rej_bounded_poly`] doesn't yield `N` accepts. Probability of
/// reaching this path is `< 2^-30`; kept for robustness against the
/// astronomical tail event.
#[cold]
#[inline(never)]
fn rej_bounded_poly_fallback(stream: &mut Shake256Stream, out: &mut DPoly, start: usize, eta: Eta) {
    let mut j = start;
    let mut block = [0u8; Shake256Stream::RATE];
    let mut block_pos = block.len();
    while j < N {
        if block_pos >= block.len() {
            stream.squeeze(&mut block);
            block_pos = 0;
        }
        let b = block[block_pos];
        block_pos += 1;
        if let Some(z) = coeff_from_half_byte(b & 0x0F, eta) {
            out.coeffs[j] = from_signed(z, Q);
            j += 1;
            if j == N {
                break;
            }
        }
        if let Some(z) = coeff_from_half_byte(b >> 4, eta) {
            out.coeffs[j] = from_signed(z, Q);
            j += 1;
        }
    }
}

/// CT analogue of [`coeff_from_half_byte`]: returns `(accept, value)`
/// with `accept ∈ {0, 1}` and `value` the canonical Z_q
/// representation (meaningful only when `accept == 1`). The 16-entry
/// lookup tables let the load be data-independent on no-cache cores —
/// cortex-m3 reads from `.rodata`.
#[inline]
fn ct_coeff_from_half_byte(b: u8, eta: Eta) -> (u32, u32) {
    const Q_VAL: u32 = Q;
    match eta {
        Eta::Eta2 => {
            // accept iff b in 0..=14; entry at index 15 is don't-care
            // (suppressed by accept = 0).
            const TBL: [u32; 16] = [
                2,
                1,
                0,
                Q_VAL - 1,
                Q_VAL - 2,
                2,
                1,
                0,
                Q_VAL - 1,
                Q_VAL - 2,
                2,
                1,
                0,
                Q_VAL - 1,
                Q_VAL - 2,
                0,
            ];
            let accept = (b < 15) as u32;
            (accept, TBL[b as usize])
        }
        Eta::Eta4 => {
            // accept iff b in 0..=8.
            const TBL: [u32; 16] = [
                4,
                3,
                2,
                1,
                0,
                Q_VAL - 1,
                Q_VAL - 2,
                Q_VAL - 3,
                Q_VAL - 4,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            ];
            let accept = (b < 9) as u32;
            (accept, TBL[b as usize])
        }
    }
}

/// Branchless conditional store: write `val` into `coeffs[*j]` and
/// bump `*j` iff `accept == 1` and `*j < N`. The saturating index keeps
/// the array access in-bounds once `N` accepts have landed.
#[inline]
fn ct_maybe_write(coeffs: &mut [u32; N], j: &mut u32, accept: u32, val: u32) {
    let in_range = ((*j).wrapping_sub(N as u32) >> 31) & 1;
    let do_write = accept & in_range;
    let mask = 0u32.wrapping_sub(do_write);
    // Bitmask saturation (N is 256 = a power of two) keeps the index
    // in [0, N) without a `min` branch.
    let idx = (*j as usize) & (N - 1);
    coeffs[idx] = (val & mask) | (coeffs[idx] & !mask);
    *j = j.wrapping_add(do_write);
}

/// ExpandA (FIPS 204 Alg 32): build the `K x L` matrix `A_hat` in NTT
/// domain from `rho`. Used by keygen; verify and sign stream
/// individual columns via [`rej_ntt_poly`] instead.
pub fn expand_a<const K: usize, const L: usize>(rho: &[u8; 32]) -> PolyMatrix<u32, K, L> {
    let mut m = PolyMatrix::<u32, K, L>::zero();
    for r in 0..K {
        for s in 0..L {
            m.rows[r].v[s] = rej_ntt_poly(rho, s as u8, r as u8);
        }
    }
    m
}

/// ExpandS (FIPS 204 Alg 33): sample `s1` (length `L`) and `s2`
/// (length `K`) with coefficients in `[-eta, eta]`.
pub fn expand_s<const K: usize, const L: usize>(
    rho_prime: &[u8; 64],
    eta: Eta,
) -> (PolyVec<u32, L>, PolyVec<u32, K>) {
    let mut s1 = PolyVec::<u32, L>::zero();
    let mut s2 = PolyVec::<u32, K>::zero();
    for r in 0..L {
        s1.v[r] = rej_bounded_poly(rho_prime, r as u16, eta);
    }
    for r in 0..K {
        s2.v[r] = rej_bounded_poly(rho_prime, (r + L) as u16, eta);
    }
    (s1, s2)
}

/// ExpandMask (FIPS 204 Alg 34): sample `y` with coefficients in
/// `(-gamma1, gamma1]`. `mu` is the running kappa counter from
/// `sign_msg_repr`; row `r`'s seed is `SHAKE256(rho_pp || (mu+r) as 2 bytes)`.
pub fn expand_mask<const L: usize>(
    rho_pp: &[u8; 64],
    mu: u16,
    gamma1: u32,
    gamma1_bits: usize,
) -> Result<PolyVec<u32, L>, EncodeError> {
    let mut out = PolyVec::<u32, L>::zero();
    // c = 1 + bitlen(gamma1 - 1); for gamma1 = 2^17, c = 18.
    let c_bits = 1 + gamma1_bits;
    let bytes_per_poly = N * c_bits / 8;
    // gamma1 = 2^19 → 640 bytes per poly; 1024 covers it with slack.
    let mut buf = [0u8; 32 * 32];
    let buf = buf
        .get_mut(..bytes_per_poly)
        .ok_or(EncodeError::BufferTooSmall)?;
    for r in 0..L {
        let mu_r = mu.wrapping_add(r as u16);
        let n_bytes = mu_r.to_le_bytes();
        let mut stream = Shake256Stream::new(&[rho_pp, &n_bytes]);
        stream.squeeze(buf);
        out.v[r] = bit_unpack_signed(buf, gamma1, c_bits)?;
    }
    Ok(out)
}

/// BitUnpack (FIPS 204 Alg 18) for the signed range
/// `[b - 2^c + 1, b]`; outputs canonical Z_q reps. The `a` argument of
/// the FIPS API is implicit (`a = 2^c - 1 - b`) since verify only
/// decodes ranges with that shape.
pub fn bit_unpack_signed(bytes: &[u8], b: u32, c_bits: usize) -> Result<DPoly, EncodeError> {
    let mut out = DPoly::zero();
    let mask = (1u32 << c_bits) - 1;
    let mut acc: u64 = 0;
    let mut bits_in_acc: u32 = 0;
    let mut byte_idx = 0usize;
    for j in 0..N {
        while bits_in_acc < c_bits as u32 {
            let byte = *bytes.get(byte_idx).ok_or(EncodeError::BufferTooSmall)?;
            acc |= (byte as u64) << bits_in_acc;
            byte_idx += 1;
            bits_in_acc += 8;
        }
        let zp = (acc as u32) & mask;
        acc >>= c_bits;
        bits_in_acc -= c_bits as u32;
        let signed = (b as i64) - (zp as i64);
        out.coeffs[j] = from_signed(signed as i32, Q);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::{ML_DSA_44, to_signed};
    const K: usize = 4;
    const L: usize = 4;
    const ETA: crate::params::Eta = ML_DSA_44.eta;
    const TAU: usize = ML_DSA_44.tau;
    const GAMMA1: u32 = ML_DSA_44.gamma1;
    const GAMMA1_BITS: usize = ML_DSA_44.gamma1_bits;

    #[test]
    fn coeff_from_three_bytes_basic() {
        assert_eq!(coeff_from_three_bytes(0, 0, 0), Some(0));
        assert_eq!(coeff_from_three_bytes(0x00, 0xE0, 0x7F), Some(Q - 1));
        assert_eq!(coeff_from_three_bytes(0, 0, 0x80), Some(0));
        assert_eq!(coeff_from_three_bytes(0xFF, 0xFF, 0x7F), None);
        assert_eq!(coeff_from_three_bytes(0x01, 0xE0, 0x7F), None);
    }

    #[test]
    fn coeff_from_half_byte_eta2() {
        assert_eq!(coeff_from_half_byte(0, Eta::Eta2), Some(2));
        assert_eq!(coeff_from_half_byte(1, Eta::Eta2), Some(1));
        assert_eq!(coeff_from_half_byte(2, Eta::Eta2), Some(0));
        assert_eq!(coeff_from_half_byte(3, Eta::Eta2), Some(-1));
        assert_eq!(coeff_from_half_byte(4, Eta::Eta2), Some(-2));
        assert_eq!(coeff_from_half_byte(5, Eta::Eta2), Some(2));
        assert_eq!(coeff_from_half_byte(14, Eta::Eta2), Some(-2));
        assert_eq!(coeff_from_half_byte(15, Eta::Eta2), None);
    }

    #[test]
    fn coeff_from_half_byte_eta4() {
        assert_eq!(coeff_from_half_byte(0, Eta::Eta4), Some(4));
        assert_eq!(coeff_from_half_byte(4, Eta::Eta4), Some(0));
        assert_eq!(coeff_from_half_byte(8, Eta::Eta4), Some(-4));
        assert_eq!(coeff_from_half_byte(9, Eta::Eta4), None);
        assert_eq!(coeff_from_half_byte(15, Eta::Eta4), None);
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
    fn rej_bounded_poly_smoke_eta2() {
        let rho_prime = [1u8; 64];
        let p = rej_bounded_poly(&rho_prime, 0, ETA);
        let bound = ETA.value();
        for &c in &p.coeffs {
            let s = to_signed(c, Q);
            assert!(s.unsigned_abs() <= bound, "out of bounds: {}", s);
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

    #[test]
    fn expand_a_smoke() {
        let rho = [0u8; 32];
        let a = expand_a::<K, L>(&rho);
        for row in &a.rows {
            for poly in &row.v {
                for &c in &poly.coeffs {
                    assert!(c < Q);
                }
            }
        }
    }

    #[test]
    fn expand_s_smoke() {
        let rho_prime = [2u8; 64];
        let (s1, s2) = expand_s::<K, L>(&rho_prime, ETA);
        let bound = ETA.value();
        for p in s1.v.iter().chain(s2.v.iter()) {
            for &c in &p.coeffs {
                let s = to_signed(c, Q);
                assert!(s.unsigned_abs() <= bound);
            }
        }
    }

    #[test]
    fn expand_mask_bounded() {
        let rho_pp = [3u8; 64];
        let y = expand_mask::<L>(&rho_pp, 0, GAMMA1, GAMMA1_BITS).unwrap();
        for p in &y.v {
            for &c in &p.coeffs {
                let s = to_signed(c, Q);
                assert!(s.unsigned_abs() <= GAMMA1);
            }
        }
    }
}
