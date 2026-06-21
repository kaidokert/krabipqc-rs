//! ML-KEM (FIPS 203 §4.3) Number Theoretic Transform.
//!
//! Unlike ML-DSA, the ML-KEM NTT is *incomplete*: it stops at length-2
//! polynomials, so the transform image `T_q` is a product of 128 copies of
//! `Z_q[X]/(X^2 − ζ^(2·BitRev_7(i)+1))`. Multiplication in `T_q` is therefore
//! 128 invocations of `BaseCaseMultiply` (Alg 12), not the trivial
//! elementwise product used by ML-DSA.

use fixed_bigint::Personality;
#[cfg(test)]
use modmath::basic::pre_reduced as pr;

use crate::field_ext::FieldExt;
#[cfg(test)]
use crate::mlkem::params::ZETA;
use crate::mlkem::params::{N, Q, Q_N_PRIME, Q_R2_MOD_Q};
use crate::poly::Poly;

#[inline]
fn reduce<P: FieldExt<P> + Personality>(x: u32) -> u32 {
    <P as FieldExt<P>>::reduce(x, Q, Q_N_PRIME, Q_R2_MOD_Q)
}
#[inline]
fn mul_mont_p<P: FieldExt<P> + Personality>(a: u32, b: u32) -> u32 {
    <P as FieldExt<P>>::mul_mont(a, b, Q, Q_N_PRIME)
}
#[inline]
fn add_mont<P: FieldExt<P> + Personality>(a: u32, b: u32) -> u32 {
    <P as FieldExt<P>>::add_mont(a, b, Q)
}
#[inline]
fn sub_mont<P: FieldExt<P> + Personality>(a: u32, b: u32) -> u32 {
    <P as FieldExt<P>>::sub_mont(a, b, Q)
}

/// Bit-reverse the low 7 bits of `i`. Used by the [`ZETAS_MONT`] /
/// [`GAMMAS_MONT`] cross-checks.
#[cfg(test)]
#[inline]
const fn bitrev7(mut i: u32) -> u32 {
    // 7-bit reverse: ABCDEFG -> GFEDCBA
    let mut r = 0u32;
    let mut bits = 0;
    while bits < 7 {
        r = (r << 1) | (i & 1);
        i >>= 1;
        bits += 1;
    }
    r
}

/// Canonical `ZETAS[i] = ZETA^BitRev_7(i) mod Q`; the Mont-form
/// [`ZETAS_MONT`] is what the hot path indexes.
#[cfg(test)]
#[rustfmt::skip]
const ZETAS: [u32; 128] = [
       1, 1729, 2580, 3289, 2642,  630, 1897,  848,
    1062, 1919,  193,  797, 2786, 3260,  569, 1746,
     296, 2447, 1339, 1476, 3046,   56, 2240, 1333,
    1426, 2094,  535, 2882, 2393, 2879, 1974,  821,
     289,  331, 3253, 1756, 1197, 2304, 2277, 2055,
     650, 1977, 2513,  632, 2865,   33, 1320, 1915,
    2319, 1435,  807,  452, 1438, 2868, 1534, 2402,
    2647, 2617, 1481,  648, 2474, 3110, 1227,  910,
      17, 2761,  583, 2649, 1637,  723, 2288, 1100,
    1409, 2662, 3281,  233,  756, 2156, 3015, 3050,
    1703, 1651, 2789, 1789, 1847,  952, 1461, 2687,
     939, 2308, 2437, 2388,  733, 2337,  268,  641,
    1584, 2298, 2037, 3220,  375, 2549, 2090, 1645,
    1063,  319, 2773,  757, 2099,  561, 2466, 2594,
    2804, 1092,  403, 1026, 1143, 2150, 2775,  886,
    1722, 1212, 1874, 1029, 2110, 2935,  885, 2154,
];

/// Montgomery-form `ZETAS_MONT[i] = ZETAS[i] * R mod Q`.
#[rustfmt::skip]
const ZETAS_MONT: [u32; 128] = [
   1353,    2379,    1948,    2473,    2609,     166,    3311,    2168,
   2087,    3116,    1467,    3074,    1030,    3184,     858,    2077,
   1008,    1765,     691,    2957,    3265,    2530,    1330,    2560,
   1887,     203,    1462,    1087,    1941,     357,     964,    2256,
   1524,    1757,     371,    2291,    1647,    1368,    1456,     700,
    594,    1694,    1180,    2872,    1389,    1372,    1616,    1033,
   1689,     748,    3288,    2349,    1478,    2119,    1535,     802,
   2716,    2074,    3064,    1217,    1677,    3303,    2289,    2829,
   3027,     495,    3155,    2093,    1076,    2822,    3023,     237,
   2189,    3037,    1636,    2323,     865,     864,    1270,    2019,
    491,      44,    1760,     334,    2241,    3062,    2636,     243,
   2118,     122,    1551,    1834,    3036,    2740,    3072,    1733,
   2605,    3237,    2978,    2328,    1367,    3282,    1449,    1913,
    111,    2166,      86,    2218,     310,      21,     840,     916,
   2081,    2729,    2632,    3314,    1823,    2733,    2792,     318,
   2895,    1968,    2153,     715,    1877,    2887,    2294,    1487,
];

/// Canonical `GAMMAS[i] = ZETA^(2·BitRev_7(i)+1) mod Q`; the
/// Mont-form [`GAMMAS_MONT`] is what the base-case multiply indexes.
#[cfg(test)]
#[rustfmt::skip]
const GAMMAS: [u32; 128] = [
      17, 3312, 2761,  568,  583, 2746, 2649,  680,
    1637, 1692,  723, 2606, 2288, 1041, 1100, 2229,
    1409, 1920, 2662,  667, 3281,   48,  233, 3096,
     756, 2573, 2156, 1173, 3015,  314, 3050,  279,
    1703, 1626, 1651, 1678, 2789,  540, 1789, 1540,
    1847, 1482,  952, 2377, 1461, 1868, 2687,  642,
     939, 2390, 2308, 1021, 2437,  892, 2388,  941,
     733, 2596, 2337,  992,  268, 3061,  641, 2688,
    1584, 1745, 2298, 1031, 2037, 1292, 3220,  109,
     375, 2954, 2549,  780, 2090, 1239, 1645, 1684,
    1063, 2266,  319, 3010, 2773,  556,  757, 2572,
    2099, 1230,  561, 2768, 2466,  863, 2594,  735,
    2804,  525, 1092, 2237,  403, 2926, 1026, 2303,
    1143, 2186, 2150, 1179, 2775,  554,  886, 2443,
    1722, 1607, 1212, 2117, 1874, 1455, 1029, 2300,
    2110, 1219, 2935,  394,  885, 2444, 2154, 1175,
];

/// Montgomery-form `GAMMAS_MONT[i] = GAMMAS[i] * R mod Q`.
/// Asserted equal to `to_mont(GAMMAS[i])` in tests.
#[rustfmt::skip]
pub const GAMMAS_MONT: [u32; 128] = [
   3027,     302,     495,    2834,    3155,     174,    2093,    1236,
   1076,    2253,    2822,     507,    3023,     306,     237,    3092,
   2189,    1140,    3037,     292,    1636,    1693,    2323,    1006,
    865,    2464,     864,    2465,    1270,    2059,    2019,    1310,
    491,    2838,      44,    3285,    1760,    1569,     334,    2995,
   2241,    1088,    3062,     267,    2636,     693,     243,    3086,
   2118,    1211,     122,    3207,    1551,    1778,    1834,    1495,
   3036,     293,    2740,     589,    3072,     257,    1733,    1596,
   2605,     724,    3237,      92,    2978,     351,    2328,    1001,
   1367,    1962,    3282,      47,    1449,    1880,    1913,    1416,
    111,    3218,    2166,    1163,      86,    3243,    2218,    1111,
    310,    3019,      21,    3308,     840,    2489,     916,    2413,
   2081,    1248,    2729,     600,    2632,     697,    3314,      15,
   1823,    1506,    2733,     596,    2792,     537,     318,    3011,
   2895,     434,    1968,    1361,    2153,    1176,     715,    2614,
   1877,    1452,    2887,     442,    2294,    1035,    1487,    1842,
];

/// 128^-1 mod 3329 = 3303 — undoes the magnitude doubling from 7 NTT layers.
pub const N_INV_128: u32 = 3303;

/// Recompute the ZETAS table via modmath. Test-only cross-check of
/// the hardcoded [`ZETAS`].
#[cfg(test)]
fn compute_zetas() -> [u32; 128] {
    let mut z = [0u32; 128];
    for i in 0..128u32 {
        z[i as usize] = pr::exp::<u32>(ZETA, bitrev7(i), Q);
    }
    z
}

/// Recompute the GAMMAS table via modmath. Test-only cross-check of
/// the hardcoded [`GAMMAS`].
#[cfg(test)]
fn compute_gammas() -> [u32; 128] {
    let mut g = [0u32; 128];
    for i in 0..128u32 {
        g[i as usize] = pr::exp::<u32>(ZETA, 2 * bitrev7(i) + 1, Q);
    }
    g
}

/// Forward NTT (FIPS 203 Algorithm 9, 7 layers).
pub fn ntt<P: Personality + FieldExt<P>>(p: &mut Poly<u32>) {
    for c in p.coeffs.iter_mut() {
        *c = reduce::<P>(*c);
    }
    let mut i: usize = 1;
    let mut len: usize = 128;
    while len >= 2 {
        let mut start = 0;
        while start < N {
            let zeta = ZETAS_MONT[i];
            i += 1;
            for j in start..start + len {
                let a = p.coeffs[j];
                let b = p.coeffs[j + len];
                let t = mul_mont_p::<P>(zeta, b);
                p.coeffs[j + len] = sub_mont::<P>(a, t);
                p.coeffs[j] = add_mont::<P>(a, t);
            }
            start += 2 * len;
        }
        len /= 2;
    }
}

/// Inverse NTT (FIPS 203 Algorithm 10).
pub fn inv_ntt<P: Personality + FieldExt<P>>(p: &mut Poly<u32>) {
    let mut i: usize = 127;
    let mut len: usize = 2;
    while len <= 128 {
        let mut start = 0;
        while start < N {
            let zeta = ZETAS_MONT[i];
            i = i.wrapping_sub(1);
            for j in start..start + len {
                let a = p.coeffs[j];
                let b = p.coeffs[j + len];
                p.coeffs[j] = add_mont::<P>(a, b);
                p.coeffs[j + len] = mul_mont_p::<P>(zeta, sub_mont::<P>(b, a));
            }
            start += 2 * len;
        }
        len *= 2;
    }
    for c in p.coeffs.iter_mut() {
        *c = mul_mont_p::<P>(N_INV_128, *c);
    }
}

/// BaseCaseMultiply (FIPS 203 Alg 12): one (a0, a1) × (b0, b1) in
/// Z_q[X]/(X^2 − gamma). All inputs are Mont-form. `c1` fuses the two
/// cross multiplies into one wide accumulator + REDC.
#[inline]
fn base_case_mul<P: Personality + FieldExt<P>>(
    a0: u32,
    a1: u32,
    b0: u32,
    b1: u32,
    gamma_mont: u32,
) -> (u32, u32) {
    let a0b0 = mul_mont_p::<P>(a0, b0);
    let a1b1g = mul_mont_p::<P>(mul_mont_p::<P>(a1, b1), gamma_mont);
    let c0 = add_mont::<P>(a0b0, a1b1g);
    let (lo, hi) = <P as FieldExt<P>>::mul_acc(0, 0, a0, b1);
    let (lo, hi) = <P as FieldExt<P>>::mul_acc(lo, hi, a1, b0);
    let c1 = <P as FieldExt<P>>::redc(lo, hi, Q, Q_N_PRIME);
    (c0, c1)
}

/// MultiplyNTTs (FIPS 203 Alg 11).
pub fn mul_ntt<P: Personality + FieldExt<P>>(a: &Poly<u32>, b: &Poly<u32>) -> Poly<u32> {
    let mut out = Poly::<u32>::zero();
    for (i, &gamma_mont) in GAMMAS_MONT.iter().enumerate() {
        let (c0, c1) = base_case_mul::<P>(
            a.coeffs[2 * i],
            a.coeffs[2 * i + 1],
            b.coeffs[2 * i],
            b.coeffs[2 * i + 1],
            gamma_mont,
        );
        out.coeffs[2 * i] = c0;
        out.coeffs[2 * i + 1] = c1;
    }
    out
}

/// Fused inner product of two length-`K` NTT-domain polynomial vectors
/// under BaseCaseMultiply: `out[k] = Σ_j mul_ntt(a_row[j], b_vec[j])[k]`.
/// `out` is overwritten.
///
/// `K ≤ R/q = 2³²/3329 ≈ 2²⁰` for the fused wide accumulators not to
/// overflow — trivially satisfied for ML-KEM (K ≤ 4).
pub fn mul_ntt_acc<const K: usize, P: Personality + FieldExt<P>>(
    out: &mut Poly<u32>,
    a_row: &[Poly<u32>; K],
    b_vec: &[Poly<u32>; K],
) {
    for (i, &gamma_mont) in GAMMAS_MONT.iter().enumerate() {
        let (mut a0b0_lo, mut a0b0_hi) = (0u32, 0u32);
        let (mut a1b1_lo, mut a1b1_hi) = (0u32, 0u32);
        let (mut c1_lo, mut c1_hi) = (0u32, 0u32);
        for j in 0..K {
            let a0 = a_row[j].coeffs[2 * i];
            let a1 = a_row[j].coeffs[2 * i + 1];
            let b0 = b_vec[j].coeffs[2 * i];
            let b1 = b_vec[j].coeffs[2 * i + 1];
            (a0b0_lo, a0b0_hi) = <P as FieldExt<P>>::mul_acc(a0b0_lo, a0b0_hi, a0, b0);
            (a1b1_lo, a1b1_hi) = <P as FieldExt<P>>::mul_acc(a1b1_lo, a1b1_hi, a1, b1);
            (c1_lo, c1_hi) = <P as FieldExt<P>>::mul_acc(c1_lo, c1_hi, a0, b1);
            (c1_lo, c1_hi) = <P as FieldExt<P>>::mul_acc(c1_lo, c1_hi, a1, b0);
        }
        // γ is loop-invariant, so fold the Σ a1·b1 collapse and the γ
        // scale into a single REDC + mul_mont after the j loop.
        let a0b0 = <P as FieldExt<P>>::redc(a0b0_lo, a0b0_hi, Q, Q_N_PRIME);
        let a1b1 = <P as FieldExt<P>>::redc(a1b1_lo, a1b1_hi, Q, Q_N_PRIME);
        let a1b1g = mul_mont_p::<P>(a1b1, gamma_mont);
        out.coeffs[2 * i] = add_mont::<P>(a0b0, a1b1g);
        out.coeffs[2 * i + 1] = <P as FieldExt<P>>::redc(c1_lo, c1_hi, Q, Q_N_PRIME);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fixed_bigint::{Ct, Nct};

    #[test]
    fn bitrev7_known() {
        assert_eq!(bitrev7(0), 0);
        assert_eq!(bitrev7(1), 64);
        assert_eq!(bitrev7(0x7F), 0x7F);
        assert_eq!(bitrev7(0b101_0101), 0b101_0101);
    }

    #[test]
    fn n_inv_128_correct() {
        assert_eq!(pr::mul::<u32>(N_INV_128, 128, Q), 1);
    }

    #[test]
    fn zetas_known_values() {
        let z = compute_zetas();
        // ZETAS[0] = 1, ZETAS[1] = zeta^BitRev_7(1) = zeta^64 = 1729 (well-known).
        assert_eq!(z[0], 1);
        assert_eq!(z[1], 1729);
        assert_eq!(z, ZETAS);
    }

    #[test]
    fn gammas_match_compute() {
        assert_eq!(compute_gammas(), GAMMAS);
        // GAMMAS[0] = zeta^1 = 17.
        assert_eq!(GAMMAS[0], 17);
    }

    #[test]
    fn zetas_mont_matches_to_mont_zetas() {
        for (i, &z) in ZETAS.iter().enumerate() {
            assert_eq!(
                ZETAS_MONT[i],
                <Nct as FieldExt<Nct>>::reduce(z, Q, Q_N_PRIME, Q_R2_MOD_Q),
                "ZETAS_MONT[{i}]"
            );
        }
    }

    #[test]
    fn gammas_mont_matches_to_mont_gammas() {
        for (i, &g) in GAMMAS.iter().enumerate() {
            assert_eq!(
                GAMMAS_MONT[i],
                <Nct as FieldExt<Nct>>::reduce(g, Q, Q_N_PRIME, Q_R2_MOD_Q),
                "GAMMAS_MONT[{i}]"
            );
        }
    }

    #[test]
    fn ntt_invntt_roundtrip() {
        let mut p = Poly::<u32>::zero();
        for i in 0..N {
            p.coeffs[i] = (i as u32 * 17 + 13) % Q;
        }
        let orig = p;
        ntt::<Nct>(&mut p);
        inv_ntt::<Nct>(&mut p);
        assert_eq!(p, orig);
    }

    #[test]
    fn ntt_mul_matches_schoolbook() {
        // Anti-cyclic schoolbook multiply on small polys.
        let mut a = Poly::<u32>::zero();
        let mut b = Poly::<u32>::zero();
        a.coeffs[0] = 2;
        a.coeffs[1] = 3;
        a.coeffs[5] = 7;
        b.coeffs[0] = 5;
        b.coeffs[2] = 11;
        b.coeffs[10] = 13;
        let want = a.schoolbook_mul(&b, Q);

        let mut na = a;
        let mut nb = b;
        ntt::<Nct>(&mut na);
        ntt::<Nct>(&mut nb);
        let mut prod = mul_ntt::<Nct>(&na, &nb);
        inv_ntt::<Nct>(&mut prod);
        assert_eq!(prod, want);
    }

    #[test]
    fn ntt_nct_ct_identical_output() {
        let mut a_nct = Poly::<u32>::zero();
        let mut state: u64 = 0xabcd_0123_4567_89ef;
        for i in 0..N {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            a_nct.coeffs[i] = (state as u32) % Q;
        }
        let mut a_ct = a_nct;
        ntt::<Nct>(&mut a_nct);
        ntt::<Ct>(&mut a_ct);
        assert_eq!(a_nct, a_ct, "ml-kem forward NTT Nct vs Ct mismatch");

        let mut b_nct = a_nct;
        let mut b_ct = a_ct;
        inv_ntt::<Nct>(&mut b_nct);
        inv_ntt::<Ct>(&mut b_ct);
        assert_eq!(b_nct, b_ct, "ml-kem inverse NTT Nct vs Ct mismatch");
    }

    #[test]
    fn mul_ntt_nct_ct_identical_output() {
        let mut a = Poly::<u32>::zero();
        let mut b = Poly::<u32>::zero();
        let mut state: u64 = 0x1357_2468_9bdf_ace0;
        for i in 0..N {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            a.coeffs[i] = (state as u32) % Q;
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            b.coeffs[i] = (state as u32) % Q;
        }
        ntt::<Nct>(&mut a);
        ntt::<Nct>(&mut b);
        let nct_prod = mul_ntt::<Nct>(&a, &b);
        let ct_prod = mul_ntt::<Ct>(&a, &b);
        assert_eq!(nct_prod, ct_prod, "ml-kem mul_ntt Nct vs Ct mismatch");
    }

    #[test]
    fn ntt_mul_matches_schoolbook_random_dense() {
        let mut a = Poly::<u32>::zero();
        let mut b = Poly::<u32>::zero();
        let mut state: u64 = 0x1234_5678_9abc_def0;
        for i in 0..N {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            a.coeffs[i] = (state as u32) % Q;
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            b.coeffs[i] = (state as u32) % Q;
        }
        let want = a.schoolbook_mul(&b, Q);
        let mut na = a;
        let mut nb = b;
        ntt::<Nct>(&mut na);
        ntt::<Nct>(&mut nb);
        let mut prod = mul_ntt::<Nct>(&na, &nb);
        inv_ntt::<Nct>(&mut prod);
        assert_eq!(prod, want);
    }
}
