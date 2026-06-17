//! Rounding helpers used by ML-DSA verify (FIPS 204 §8): [`decompose`]
//! / [`high_bits`] / [`low_bits`] for the `r1` recovery from
//! `A·z − c·t1·2^d`, and [`use_hint`] for folding the signature hint
//! into the recovered `w1`.
//!
//! Per-coefficient timing is independent of the input: the sign
//! selects are branchless mask blends, and `% (2*gamma2)` /
//! `/ (2*gamma2)` go through Barrett reduction (with the factor
//! picked from `gamma2` by another mask blend), so the code runs in
//! constant time on cores without a hardware divider too.

use modmath::basic::pre_reduced as pr;

use crate::params::Q;

// Only two `gamma2` values appear across ML-DSA-44/65/87, so the
// Barrett factor and the UseHint divisor are precomputed for each.

const GAMMA2_88: u32 = (Q - 1) / 88;
const GAMMA2_32: u32 = (Q - 1) / 32;

const BF_2GAMMA2_88: u32 = ((1u64 << 32) / (2 * GAMMA2_88) as u64) as u32;
const BF_2GAMMA2_32: u32 = ((1u64 << 32) / (2 * GAMMA2_32) as u64) as u32;

const USE_HINT_M_88: u32 = (Q - 1) / (2 * GAMMA2_88);
const USE_HINT_M_32: u32 = (Q - 1) / (2 * GAMMA2_32);

/// Pick the Barrett factor matching `gamma2` via a branchless mask
/// blend so the choice doesn't leak through timing.
#[inline(always)]
const fn barrett_2gamma2(gamma2: u32) -> u32 {
    let is_88 = (gamma2 == GAMMA2_88) as u32;
    let mask_88 = 0u32.wrapping_sub(is_88);
    (BF_2GAMMA2_88 & mask_88) | (BF_2GAMMA2_32 & !mask_88)
}

/// Pick `(q-1)/(2*gamma2)` (the `m` in UseHint) via the same
/// branchless blend.
#[inline(always)]
const fn use_hint_m(gamma2: u32) -> u32 {
    let is_88 = (gamma2 == GAMMA2_88) as u32;
    let mask_88 = 0u32.wrapping_sub(is_88);
    (USE_HINT_M_88 & mask_88) | (USE_HINT_M_32 & !mask_88)
}

/// Constant-time `(x / two_g, x % two_g)` via Barrett reduction.
/// Caller-supplied `bf` must be the Barrett factor for `two_g`; `x`
/// must be `< 2^24` (callers pass `r < q` or `diff ≤ q`, both `< 2^23`).
#[inline(always)]
fn barrett_div_rem(x: u32, two_g: u32, bf: u32) -> (u32, u32) {
    let q_est = ((x as u64 * bf as u64) >> 32) as u32;
    let r_unred = x.wrapping_sub(q_est.wrapping_mul(two_g));
    let needs_sub = (r_unred.wrapping_sub(two_g) >> 31) ^ 1;
    let mask = 0u32.wrapping_sub(needs_sub);
    let r = r_unred.wrapping_sub(two_g & mask);
    let q = q_est.wrapping_add(needs_sub);
    (q, r)
}

/// Decompose (FIPS 204 Alg 36). Returns `(r1, r0)` with `r1` in
/// `[0, (q-1)/(2*gamma2))` and `r0` the canonical Z_q rep of the
/// centered low part.
pub fn decompose(r: u32, gamma2: u32) -> (u32, u32) {
    debug_assert!(r < Q);
    let two_g = 2 * gamma2;
    let bf = barrett_2gamma2(gamma2);

    let (_, r0_u) = barrett_div_rem(r, two_g, bf);

    let sign_neg = (gamma2.wrapping_sub(r0_u) >> 31) & 1;
    let sign_mask = 0u32.wrapping_sub(sign_neg);

    let neg_r0 = Q.wrapping_sub(two_g.wrapping_sub(r0_u));
    let r0_canon0 = (r0_u & !sign_mask) | (neg_r0 & sign_mask);

    let diff = r.wrapping_sub(r0_u).wrapping_add(two_g & sign_mask);

    // FIPS 204 wrap: when diff == Q-1, r1 collapses to 0 and r0_canon
    // shifts down by 1 (mod Q). Detect and fold branchlessly.
    let diff_xor = diff ^ (Q - 1);
    let wrap = ((diff_xor | diff_xor.wrapping_neg()) >> 31).wrapping_sub(1) & 1;
    let wrap_mask = 0u32.wrapping_sub(wrap);

    let (r1_nowrap, _) = barrett_div_rem(diff, two_g, bf);
    let r0_minus1 = pr::sub::<u32>(r0_canon0, 1, Q);

    let r1 = r1_nowrap & !wrap_mask;
    let r0_canon = (r0_canon0 & !wrap_mask) | (r0_minus1 & wrap_mask);

    (r1, r0_canon)
}

pub fn high_bits(r: u32, gamma2: u32) -> u32 {
    decompose(r, gamma2).0
}

pub fn low_bits(r: u32, gamma2: u32) -> u32 {
    decompose(r, gamma2).1
}

/// UseHint (FIPS 204 Alg 40). The `% m` spec ops collapse to a single
/// conditional subtract because the dividends sit in `[0, 2m)`.
pub fn use_hint(h: u32, r: u32, gamma2: u32) -> u32 {
    let m = use_hint_m(gamma2);
    let (r1, r0) = decompose(r, gamma2);

    let h_bit = h & 1;
    let h_mask = 0u32.wrapping_sub(h_bit);

    let r0_nonzero = ((r0 | r0.wrapping_neg()) >> 31) & 1;
    let r0_in_low_half = (r0.wrapping_sub(Q / 2 + 1) >> 31) & 1;
    let r0_pos = r0_nonzero & r0_in_low_half;
    let pos_mask = 0u32.wrapping_sub(r0_pos);

    let raw_inc = r1 + 1;
    let inc_needs_sub = (raw_inc.wrapping_sub(m) >> 31) ^ 1;
    let inc = raw_inc.wrapping_sub(m & 0u32.wrapping_sub(inc_needs_sub));

    let raw_dec = r1 + m - 1;
    let dec_needs_sub = (raw_dec.wrapping_sub(m) >> 31) ^ 1;
    let dec = raw_dec.wrapping_sub(m & 0u32.wrapping_sub(dec_needs_sub));

    let adjusted = (inc & pos_mask) | (dec & !pos_mask);

    (r1 & !h_mask) | (adjusted & h_mask)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::{from_signed, ml_dsa_44::GAMMA2, to_signed};

    #[test]
    fn decompose_recombines() {
        let g = GAMMA2;
        for &r in &[0u32, 1, g, 2 * g, Q / 2, Q - 1, Q - 2] {
            let (r1, r0) = decompose(r, g);
            let r0_signed = to_signed(r0, Q);
            let r1_2g = pr::mul::<u32>(r1, 2 * g, Q);
            let recomb = pr::add::<u32>(r1_2g, from_signed(r0_signed, Q), Q);
            assert_eq!(recomb, r);
            assert!(r1 < (Q - 1) / (2 * g));
            assert!(r0_signed.unsigned_abs() <= g);
        }
    }

    #[test]
    fn high_low_bits_consistency() {
        let g = GAMMA2;
        for r in (0..Q).step_by(101) {
            assert_eq!(high_bits(r, g), decompose(r, g).0);
            assert_eq!(low_bits(r, g), decompose(r, g).1);
        }
    }

    // -- Reference (branchy) versions, used to cross-check the
    // branchless implementations on a dense input sweep.

    fn ref_to_signed(x: u32) -> i32 {
        let x = x % Q;
        if x > Q / 2 {
            x as i32 - Q as i32
        } else {
            x as i32
        }
    }

    fn ref_decompose(r: u32, gamma2: u32) -> (u32, u32) {
        let r_plus = r % Q;
        let two_g = 2 * gamma2;
        let r0_u = r_plus % two_g;
        let (r0_canon, r0_signed_neg) = if r0_u > gamma2 {
            (pr::sub::<u32>(0, two_g - r0_u, Q), true)
        } else {
            (r0_u, false)
        };
        let diff = if r0_signed_neg {
            r_plus - r0_u + two_g
        } else {
            r_plus - r0_u
        };
        if diff == Q - 1 {
            (0, pr::sub::<u32>(r0_canon, 1, Q))
        } else {
            (diff / two_g, r0_canon)
        }
    }

    fn ref_use_hint(h: u32, r: u32, gamma2: u32) -> u32 {
        let m = (Q - 1) / (2 * gamma2);
        let (r1, r0) = ref_decompose(r, gamma2);
        if h == 0 {
            return r1;
        }
        let r0s = ref_to_signed(r0);
        if r0s > 0 {
            (r1 + 1) % m
        } else {
            (r1 + m - 1) % m
        }
    }

    #[test]
    fn decompose_matches_reference_dense() {
        for &g in &[((Q - 1) / 88), ((Q - 1) / 32)] {
            for r in (0..Q).step_by(503) {
                assert_eq!(decompose(r, g), ref_decompose(r, g), "r={} g={}", r, g);
            }
        }
    }

    #[test]
    fn use_hint_matches_reference() {
        let g = (Q - 1) / 88;
        for r in (0..Q).step_by(1009) {
            for h in 0..2u32 {
                assert_eq!(use_hint(h, r, g), ref_use_hint(h, r, g), "h={} r={}", h, r);
            }
        }
    }
}
