//! ML-DSA Number Theoretic Transform (FIPS 204 Alg 41 & 42).
//!
//! Butterflies dispatch through [`FieldExt<P>`] so a single body
//! serves both personalities (`Nct` / `Ct`).

use fixed_bigint::Personality;
use modmath::basic::pre_reduced as pr;

use crate::field_ext::FieldExt;
use crate::params::{N, Q, Q_N_PRIME, Q_R2_MOD_Q, ZETA};
use crate::poly::Poly;

// ML-DSA-pinned shims so the NTT bodies don't restate the modulus
// constants on every call.
#[inline]
fn reduce<P: FieldExt<P> + Personality>(x: u32) -> u32 {
    <P as FieldExt<P>>::reduce(x, Q, Q_N_PRIME, Q_R2_MOD_Q)
}
#[inline]
fn mul_mont<P: FieldExt<P> + Personality>(a: u32, b: u32) -> u32 {
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

/// Bit-reverse the low 8 bits of `i`.
#[inline]
const fn bitrev8(mut i: u32) -> u32 {
    i = ((i & 0xF0) >> 4) | ((i & 0x0F) << 4);
    i = ((i & 0xCC) >> 2) | ((i & 0x33) << 2);
    i = ((i & 0xAA) >> 1) | ((i & 0x55) << 1);
    i
}

/// `ZETAS[i] = ZETA^bitrev8(i) mod Q`. Hardcoded to skip 256 modular
/// exponentiations per NTT call; cross-checked against
/// [`compute_zetas`] in a unit test below.
#[rustfmt::skip]
pub const ZETAS: [u32; 256] = [
          1, 4808194, 3765607, 3761513, 5178923, 5496691, 5234739, 5178987,
    7778734, 3542485, 2682288, 2129892, 3764867, 7375178,  557458, 7159240,
    5010068, 4317364, 2663378, 6705802, 4855975, 7946292,  676590, 7044481,
    5152541, 1714295, 2453983, 1460718, 7737789, 4795319, 2815639, 2283733,
    3602218, 3182878, 2740543, 4793971, 5269599, 2101410, 3704823, 1159875,
     394148,  928749, 1095468, 4874037, 2071829, 4361428, 3241972, 2156050,
    3415069, 1759347, 7562881, 4805951, 3756790, 6444618, 6663429, 4430364,
    5483103, 3192354,  556856, 3870317, 2917338, 1853806, 3345963, 1858416,
    3073009, 1277625, 5744944, 3852015, 4183372, 5157610, 5258977, 8106357,
    2508980, 2028118, 1937570, 4564692, 2811291, 5396636, 7270901, 4158088,
    1528066,  482649, 1148858, 5418153, 7814814,  169688, 2462444, 5046034,
    4213992, 4892034, 1987814, 5183169, 1736313,  235407, 5130263, 3258457,
    5801164, 1787943, 5989328, 6125690, 3482206, 4197502, 7080401, 6018354,
    7062739, 2461387, 3035980,  621164, 3901472, 7153756, 2925816, 3374250,
    1356448, 5604662, 2683270, 5601629, 4912752, 2312838, 7727142, 7921254,
     348812, 8052569, 1011223, 6026202, 4561790, 6458164, 6143691, 1744507,
       1753, 6444997, 5720892, 6924527, 2660408, 6600190, 8321269, 2772600,
    1182243,   87208,  636927, 4415111, 4423672, 6084020, 5095502, 4663471,
    8352605,  822541, 1009365, 5926272, 6400920, 1596822, 4423473, 4620952,
    6695264, 4969849, 2678278, 4611469, 4829411,  635956, 8129971, 5925040,
    4234153, 6607829, 2192938, 6653329, 2387513, 4768667, 8111961, 5199961,
    3747250, 2296099, 1239911, 4541938, 3195676, 2642980, 1254190, 8368000,
    2998219,  141835, 8291116, 2513018, 7025525,  613238, 7070156, 6161950,
    7921677, 6458423, 4040196, 4908348, 2039144, 6500539, 7561656, 6201452,
    6757063, 2105286, 6006015, 6346610,  586241, 7200804,  527981, 5637006,
    6903432, 1994046, 2491325, 6987258,  507927, 7192532, 7655613, 6545891,
    5346675, 8041997, 2647994, 3009748, 5767564, 4148469,  749577, 4357667,
    3980599, 2569011, 6764887, 1723229, 1665318, 2028038, 1163598, 5011144,
    3994671, 8368538, 7009900, 3020393, 3363542,  214880,  545376, 7609976,
    3105558, 7277073,  508145, 7826699,  860144, 3430436,  140244, 6866265,
    6195333, 3123762, 2358373, 6187330, 5365997, 6663603, 2926054, 7987710,
    8077412, 3531229, 4405932, 4606686, 1900052, 7598542, 1054478, 7648983,
];

/// Recompute ZETAS. Used by the consistency test against the
/// hardcoded [`ZETAS`]; not on the runtime hot path.
pub fn compute_zetas() -> [u32; 256] {
    let mut z = [0u32; 256];
    for i in 0..256u32 {
        z[i as usize] = pr::exp::<u32>(ZETA, bitrev8(i), Q);
    }
    z
}

/// `256^-1 mod Q` — the post-NTT scaling factor.
pub const N_INV: u32 = 8347681;

/// `ZETAS_MONT[i] = ZETAS[i] * R mod Q`. Cross-checked against
/// `to_mont(ZETAS[i])` in tests.
#[rustfmt::skip]
pub const ZETAS_MONT: [u32; 256] = [
    4193792,   25847, 5771523, 7861508,  237124, 7602457, 7504169,  466468,
    1826347, 2353451, 8021166, 6288512, 3119733, 5495562, 3111497, 2680103,
    2725464, 1024112, 7300517, 3585928, 7830929, 7260833, 2619752, 6271868,
    6262231, 4520680, 6980856, 5102745, 1757237, 8360995, 4010497,  280005,
    2706023,   95776, 3077325, 3530437, 6718724, 4788269, 5842901, 3915439,
    4519302, 5336701, 3574422, 5512770, 3539968, 8079950, 2348700, 7841118,
    6681150, 6736599, 3505694, 4558682, 3507263, 6239768, 6779997, 3699596,
     811944,  531354,  954230, 3881043, 3900724, 5823537, 2071892, 5582638,
    4450022, 6851714, 4702672, 5339162, 6927966, 3475950, 2176455, 6795196,
    7122806, 1939314, 4296819, 7380215, 5190273, 5223087, 4747489,  126922,
    3412210, 7396998, 2147896, 2715295, 5412772, 4686924, 7969390, 5903370,
    7709315, 7151892, 8357436, 7072248, 7998430, 1349076, 1852771, 6949987,
    5037034,  264944,  508951, 3097992,   44288, 7280319,  904516, 3958618,
    4656075, 8371839, 1653064, 5130689, 2389356, 8169440,  759969, 7063561,
     189548, 4827145, 3159746, 6529015, 5971092, 8202977, 1315589, 1341330,
    1285669, 6795489, 7567685, 6940675, 5361315, 4499357, 4751448, 3839961,
    2091667, 3407706, 2316500, 3817976, 5037939, 2244091, 5933984, 4817955,
     266997, 2434439, 7144689, 3513181, 4860065, 4621053, 7183191, 5187039,
     900702, 1859098,  909542,  819034,  495491, 6767243, 8337157, 7857917,
    7725090, 5257975, 2031748, 3207046, 4823422, 7855319, 7611795, 4784579,
     342297,  286988, 5942594, 4108315, 3437287, 5038140, 1735879,  203044,
    2842341, 2691481, 5790267, 1265009, 4055324, 1247620, 2486353, 1595974,
    4613401, 1250494, 2635921, 4832145, 5386378, 1869119, 1903435, 7329447,
    7047359, 1237275, 5062207, 6950192, 7929317, 1312455, 3306115, 6417775,
    7100756, 1917081, 5834105, 7005614, 1500165,  777191, 2235880, 3406031,
    7838005, 5548557, 6709241, 6533464, 5796124, 4656147,  594136, 4603424,
    6366809, 2432395, 2454455, 8215696, 1957272, 3369112,  185531, 7173032,
    5196991,  162844, 1616392, 3014001,  810149, 1652634, 4686184, 6581310,
    5341501, 3523897, 3866901,  269760, 2213111, 7404533, 1717735,  472078,
    7953734, 1723600, 6577327, 1910376, 6712985, 7276084, 8119771, 4546524,
    5441381, 6144432, 7959518, 6094090,  183443, 7403526, 1612842, 4834730,
    7826001, 3919660, 8332111, 7018208, 3937738, 1400424, 7534263, 1976782,
];

/// Forward NTT. Input canonical, output Mont-form.
pub fn ntt<P: Personality + FieldExt<P>>(p: &mut Poly<u32>) {
    for c in p.coeffs.iter_mut() {
        *c = reduce::<P>(*c);
    }
    let mut k: usize = 0;
    let mut len: usize = 128;
    while len >= 1 {
        let mut start = 0;
        while start < N {
            k += 1;
            let zeta = ZETAS_MONT[k];
            for j in start..start + len {
                let a = p.coeffs[j];
                let b = p.coeffs[j + len];
                let t = mul_mont::<P>(zeta, b);
                p.coeffs[j + len] = sub_mont::<P>(a, t);
                p.coeffs[j] = add_mont::<P>(a, t);
            }
            start += 2 * len;
        }
        len /= 2;
    }
}

/// Inverse NTT. Input Mont-form, output canonical.
///
/// The final pass multiplies by the canonical `N_INV` through
/// `mul_mont`, folding the `256^-1` scaling and the Mont→canonical
/// strip into one REDC: `wide::mul(N_INV_canon, c_mont) / R = N_INV · c`
/// in canonical form.
pub fn inv_ntt<P: Personality + FieldExt<P>>(p: &mut Poly<u32>) {
    let mut k: usize = 256;
    let mut len: usize = 1;
    while len < N {
        let mut start = 0;
        while start < N {
            k -= 1;
            let zeta = pr::sub::<u32>(0, ZETAS_MONT[k], Q);
            for j in start..start + len {
                let a = p.coeffs[j];
                let b = p.coeffs[j + len];
                p.coeffs[j] = add_mont::<P>(a, b);
                p.coeffs[j + len] = mul_mont::<P>(zeta, sub_mont::<P>(a, b));
            }
            start += 2 * len;
        }
        len *= 2;
    }
    for c in p.coeffs.iter_mut() {
        *c = mul_mont::<P>(N_INV, *c);
    }
}

/// Elementwise multiply of two NTT-domain (Mont-form) polynomials.
pub fn mul_ntt<P: Personality + FieldExt<P>>(a: &Poly<u32>, b: &Poly<u32>) -> Poly<u32> {
    let mut out = Poly::<u32>::zero();
    for i in 0..N {
        out.coeffs[i] = mul_mont::<P>(a.coeffs[i], b.coeffs[i]);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    use fixed_bigint::{Ct, Nct};

    #[test]
    fn bitrev8_known() {
        assert_eq!(bitrev8(0), 0);
        assert_eq!(bitrev8(1), 0b1000_0000);
        assert_eq!(bitrev8(2), 0b0100_0000);
        assert_eq!(bitrev8(0xFF), 0xFF);
        assert_eq!(bitrev8(0b1010_1010), 0b0101_0101);
    }

    #[test]
    fn n_inv_is_correct() {
        assert_eq!(pr::mul::<u32>(N_INV, N as u32, Q), 1);
    }

    #[test]
    fn zeta_is_primitive_512th_root() {
        // zeta^256 = -1 (mod q), zeta^512 = 1 (mod q)
        assert_eq!(pr::exp::<u32>(ZETA, 256, Q), Q - 1);
        assert_eq!(pr::exp::<u32>(ZETA, 512, Q), 1);
    }

    #[test]
    fn zetas_known_values() {
        let z = compute_zetas();
        assert_eq!(z[0], 1);
        assert_eq!(z[1], pr::exp::<u32>(ZETA, 128, Q));
        assert_eq!(z[1], 4808194);
    }

    #[test]
    fn zetas_const_matches_computed() {
        let computed = compute_zetas();
        assert_eq!(ZETAS, computed);
    }

    #[test]
    fn zetas_mont_matches_to_mont_zetas() {
        for (i, &z) in ZETAS.iter().enumerate() {
            assert_eq!(
                ZETAS_MONT[i],
                <Nct as FieldExt<Nct>>::reduce(z, Q, Q_N_PRIME, Q_R2_MOD_Q),
                "ZETAS_MONT[{i}] mismatch"
            );
        }
    }

    #[test]
    fn ntt_invntt_roundtrip() {
        let mut p = Poly::<u32>::zero();
        for i in 0..N {
            p.coeffs[i] = ((i as u32) * 1234567 + 89) % Q;
        }
        let orig = p;
        ntt::<Nct>(&mut p);
        inv_ntt::<Nct>(&mut p);
        assert_eq!(p, orig);
    }

    #[test]
    fn ntt_pointwise_matches_schoolbook() {
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
        // The Ct path must produce identical Mont-form bytes to the Nct
        // path. Same canonical input → same NTT output via both
        // personalities.

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
        assert_eq!(a_nct, a_ct, "forward NTT Nct vs Ct mismatch");

        let mut b_nct = a_nct;
        let mut b_ct = a_ct;
        inv_ntt::<Nct>(&mut b_nct);
        inv_ntt::<Ct>(&mut b_ct);
        assert_eq!(b_nct, b_ct, "inverse NTT Nct vs Ct mismatch");
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
        assert_eq!(nct_prod, ct_prod, "mul_ntt Nct vs Ct mismatch");
    }

    #[test]
    fn ntt_pointwise_matches_schoolbook_random_dense() {
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
