//! Rounding helpers (FIPS 204 §8): `Power2Round` for keygen's
//! `(t1, t0)` split, `Decompose` / `HighBits` / `LowBits` for the
//! `w1 = HighBits(A·y)` step in sign and the `r1` recovery in verify,
//! `MakeHint` / `UseHint` for the per-coefficient hint that lets
//! verify reproduce `w1` from `(z, h)`.
//!
//! Per-coefficient timing is independent of the input: the sign
//! selects are branchless mask blends, and `% (2*gamma2)` /
//! `/ (2*gamma2)` go through Barrett reduction (with the factor
//! picked from `gamma2` by another mask blend), so the code runs in
//! constant time on cores without a hardware divider too.

use modmath::basic::pre_reduced as pr;

use crate::params::{D, N, Q};
use crate::polyvec::PolyVec;

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

/// Power2Round (FIPS 204 Alg 35): splits `r ∈ [0, Q)` as
/// `r = r1 · 2^d + r0` with `r0` centered. Returns `(r1, r0_canon)`
/// where `r0_canon` is the canonical Z_q rep of the (possibly
/// negative) low part.
pub fn power2round(r: u32) -> (u32, u32) {
    debug_assert!(r < Q);
    let two_d: u32 = 1 << D;
    let half: u32 = 1 << (D - 1);
    let r0_u = r & (two_d - 1);

    let gt_half = (half.wrapping_sub(r0_u) >> 31) & 1;
    let mask = 0u32.wrapping_sub(gt_half);

    let neg_r0 = Q.wrapping_sub(two_d.wrapping_sub(r0_u));
    let r0_canon = (r0_u & !mask) | (neg_r0 & mask);

    let r1 = (r.wrapping_sub(r0_u).wrapping_add(two_d & mask)) >> D;

    (r1, r0_canon)
}

/// Coefficient-wise [`power2round`] over a `PolyVec`. `t1` lands in
/// `[0, 2^{bitlen(q-1) - d})` and `t0` in canonical Z_q.
pub fn power2round_vec<const K: usize>(t: &PolyVec<u32, K>) -> (PolyVec<u32, K>, PolyVec<u32, K>) {
    let mut t1 = PolyVec::<u32, K>::zero();
    let mut t0 = PolyVec::<u32, K>::zero();
    for i in 0..K {
        for j in 0..N {
            let (a, b) = power2round(t.v[i].coeffs[j]);
            t1.v[i].coeffs[j] = a;
            t0.v[i].coeffs[j] = b;
        }
    }
    (t1, t0)
}

/// Decompose (FIPS 204 Alg 36). Returns `(r1, r0)` with `r1` in
/// `[0, (q-1)/(2*gamma2))` and `r0` the canonical Z_q rep of the
/// centered low part.
pub fn decompose(r: u32, gamma2: u32) -> (u32, u32) {
    debug_assert!(r < Q);
    debug_assert!(gamma2 == GAMMA2_88 || gamma2 == GAMMA2_32);
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

/// HighBits (FIPS 204 Alg 37): the `r1` half of [`decompose`].
#[inline]
pub fn high_bits(r: u32, gamma2: u32) -> u32 {
    decompose(r, gamma2).0
}

/// LowBits (FIPS 204 Alg 38): the `r0` half of [`decompose`].
#[inline]
pub fn low_bits(r: u32, gamma2: u32) -> u32 {
    decompose(r, gamma2).1
}

/// MakeHint (FIPS 204 Alg 39): returns 1 iff
/// `HighBits(r + z) != HighBits(r)`. `z` and `r` are canonical Z_q reps.
pub fn make_hint(z: u32, r: u32, gamma2: u32) -> u8 {
    let r1 = high_bits(r, gamma2);
    let v1 = high_bits(pr::add::<u32>(r, z, Q), gamma2);
    let diff = r1 ^ v1;
    (((diff | diff.wrapping_neg()) >> 31) & 1) as u8
}

/// UseHint (FIPS 204 Alg 40). The `% m` spec ops collapse to a single
/// conditional subtract because the dividends sit in `[0, 2m)`.
pub fn use_hint(h: u32, r: u32, gamma2: u32) -> u32 {
    debug_assert!(gamma2 == GAMMA2_88 || gamma2 == GAMMA2_32);
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

    fn ref_power2round(r: u32) -> (u32, u32) {
        let r_plus = r % Q;
        let two_d: u32 = 1 << D;
        let half: u32 = 1 << (D - 1);
        let r0_u = r_plus & (two_d - 1);
        let (r0c, r1) = if r0_u > half {
            (
                pr::sub::<u32>(0, two_d - r0_u, Q),
                (r_plus - r0_u + two_d) >> D,
            )
        } else {
            (r0_u, (r_plus - r0_u) >> D)
        };
        (r1, r0c)
    }

    fn ref_make_hint(z: u32, r: u32, gamma2: u32) -> u8 {
        let r1 = ref_decompose(r, gamma2).0;
        let v1 = ref_decompose(pr::add::<u32>(r, z, Q), gamma2).0;
        if r1 != v1 { 1 } else { 0 }
    }

    #[test]
    fn power2round_recombines() {
        let two_d: u32 = 1 << D;
        for &r in &[0u32, 1, 8191, 8192, 9000, Q / 2, Q - 1] {
            let (r1, r0) = power2round(r);
            let r0_signed = crate::params::to_signed(r0, Q);
            let r1_2d = pr::mul::<u32>(r1, two_d, Q);
            let recomb = pr::add::<u32>(r1_2d, crate::params::from_signed(r0_signed, Q), Q);
            assert_eq!(recomb, r);
            assert!(r0_signed > -(1 << (D - 1)));
            assert!(r0_signed <= 1 << (D - 1));
        }
    }

    #[test]
    fn power2round_matches_reference_dense() {
        for r in (0..Q).step_by(509) {
            assert_eq!(power2round(r), ref_power2round(r), "r={}", r);
        }
    }

    #[test]
    fn make_hint_matches_reference() {
        let g = (Q - 1) / 88;
        for r in (0..Q).step_by(2003) {
            for &z in &[0u32, 1, Q - 1, g, Q - g] {
                assert_eq!(make_hint(z, r, g), ref_make_hint(z, r, g));
            }
        }
    }

    #[test]
    fn make_use_hint_roundtrip() {
        let g = GAMMA2;
        let mut rng_state: u64 = 0xfeedfacecafebeef;
        let mut rng = || {
            rng_state = rng_state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (rng_state as u32) % Q
        };
        for _ in 0..200 {
            let r = rng();
            let z_signed = ((rng() as i64 % (g as i64)) - (g as i64 / 2)) as i32;
            let z = crate::params::from_signed(z_signed, Q);
            let h = make_hint(z, r, g);
            let recovered = use_hint(h as u32, r, g);
            let expected = high_bits(pr::add::<u32>(r, z, Q), g);
            assert_eq!(recovered, expected, "z={}, r={}, h={}", z_signed, r, h);
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
