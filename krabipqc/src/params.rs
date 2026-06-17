//! ML-DSA scheme parameters (FIPS 204 §4 + Table 2). The per-set
//! `const` blocks ([`ML_DSA_44`], [`ML_DSA_65`], [`ML_DSA_87`]) carry
//! the matrix shape, eta, gamma1/gamma2, tau, omega, and derived
//! encoding byte lengths.

/// Modulus q = 2^23 - 2^13 + 1.
pub const Q: u32 = 8_380_417;

/// `-Q^-1 mod 2^32`, used by `wide::mul` Montgomery REDC.
pub const Q_N_PRIME: u32 = 4_236_238_847;

/// `R^2 mod Q` = `2^64 mod Q`, used by canonical-to-Mont conversion.
pub const Q_R2_MOD_Q: u32 = 2_365_951;

/// `R mod Q` = `2^32 mod Q`, used as the Mont-form 1.
pub const Q_R_MOD_Q: u32 = 4_193_792;

/// Polynomial degree.
pub const N: usize = 256;

/// 512-th principal root of unity mod q used by the NTT.
pub const ZETA: u32 = 1753;

/// 2^d split used in Power2Round.
pub const D: u32 = 13;

// ML-DSA stores canonical `[0, q)` reps but reasons about norms in
// centered `(-q/2, q/2]` form. The three branchless conversions below
// are written with mask selects so per-coefficient timing is
// data-independent.

/// Centered `(-q/2, q/2]` → canonical `[0, q)`. Correct for
/// `|x| < 2*q`; all in-tree callers pass `|x| < q`.
#[inline]
pub fn from_signed(x: i32, q: u32) -> u32 {
    let neg_mask = (x >> 31) as u32;
    let abs = x.wrapping_abs() as u32;
    let geq_q = (((abs.wrapping_sub(q) >> 31) ^ 1) & 1).wrapping_neg();
    let abs_red = abs.wrapping_sub(q & geq_q);
    let pos = abs_red;
    let zero_mask = ((abs_red | abs_red.wrapping_neg()) >> 31).wrapping_sub(1);
    let neg = q.wrapping_sub(abs_red) & !zero_mask;
    (pos & !neg_mask) | (neg & neg_mask)
}

/// Canonical `[0, q)` → centered `(-q/2, q/2]`.
#[inline]
pub fn to_signed(x: u32, q: u32) -> i32 {
    let in_high = ((q / 2).wrapping_sub(x) >> 31) & 1;
    let mask = 0u32.wrapping_sub(in_high);
    let x_minus_q = x.wrapping_sub(q);
    ((x & !mask) | (x_minus_q & mask)) as i32
}

/// Absolute value of the centered representative: `min(x, q - x)` for
/// `x < q`.
#[inline]
pub fn abs_centered(x: u32, q: u32) -> u32 {
    let q_minus_x = q.wrapping_sub(x);
    let take_q_minus_x = (q_minus_x.wrapping_sub(x) >> 31) & 1;
    let mask = 0u32.wrapping_sub(take_q_minus_x);
    (x & !mask) | (q_minus_x & mask)
}

/// Per-set ML-DSA constants. `K` (rows) and `L` (columns) are const
/// generics so `PolyVec` / `PolyMatrix` sizes specialize at compile
/// time.
pub struct Params<const K: usize, const L: usize> {
    pub eta: u32,
    pub tau: usize,
    pub beta: u32,
    pub gamma1: u32,
    pub gamma1_bits: usize,
    pub gamma2: u32,
    pub omega: usize,
    pub lambda: usize,
    pub w1_bits: usize,
    pub pk_bytes: usize,
    pub sk_bytes: usize,
    pub sig_bytes: usize,
    pub ctilde_bytes: usize,
}

impl<const K: usize, const L: usize> Params<K, L> {
    pub const K: usize = K;
    pub const L: usize = L;
}

/// SHAKE-256 expansion buffer for keygen's seed bundle
/// `(rho | rho_prime | big_k)` = 32 + 64 + 32 bytes.
pub const SEED_EXPAND_BYTES: usize = 128;

/// Worst-case ctilde length across all three sets (`lambda/4` at
/// `lambda = 256`).
pub const MAX_CTILDE_BYTES: usize = 64;

/// Worst-case packed-w1 length across all three sets (`K * 32 * w1_bits`).
pub const MAX_W1_PACKED_BYTES: usize = 1024;

const fn eta_bits(eta: u32) -> usize {
    let mut a = 2 * eta;
    let mut n = 0;
    while a > 0 {
        n += 1;
        a >>= 1;
    }
    n
}

const fn pk_bytes(k: usize) -> usize {
    32 + 32 * k * 10
}
const fn sk_bytes(k: usize, l: usize, eta: u32) -> usize {
    32 + 32 + 64 + 32 * ((k + l) * eta_bits(eta) + (D as usize) * k)
}
const fn sig_bytes(k: usize, l: usize, lambda: usize, gamma1_bits: usize, omega: usize) -> usize {
    lambda / 4 + l * 32 * (1 + gamma1_bits) + omega + k
}

/// ML-DSA-44 (k=4, l=4, eta=2, gamma1=2^17, gamma2=(q-1)/88).
pub const ML_DSA_44: Params<4, 4> = Params {
    eta: 2,
    tau: 39,
    beta: 39 * 2,
    gamma1: 1 << 17,
    gamma1_bits: 17,
    gamma2: (Q - 1) / 88,
    omega: 80,
    lambda: 128,
    w1_bits: 6,
    pk_bytes: pk_bytes(4),
    sk_bytes: sk_bytes(4, 4, 2),
    sig_bytes: sig_bytes(4, 4, 128, 17, 80),
    ctilde_bytes: 128 / 4,
};

/// ML-DSA-65 (k=6, l=5, eta=4, gamma1=2^19, gamma2=(q-1)/32).
pub const ML_DSA_65: Params<6, 5> = Params {
    eta: 4,
    tau: 49,
    beta: 49 * 4,
    gamma1: 1 << 19,
    gamma1_bits: 19,
    gamma2: (Q - 1) / 32,
    omega: 55,
    lambda: 192,
    w1_bits: 4,
    pk_bytes: pk_bytes(6),
    sk_bytes: sk_bytes(6, 5, 4),
    sig_bytes: sig_bytes(6, 5, 192, 19, 55),
    ctilde_bytes: 192 / 4,
};

/// ML-DSA-87 (k=8, l=7, eta=2, gamma1=2^19, gamma2=(q-1)/32).
pub const ML_DSA_87: Params<8, 7> = Params {
    eta: 2,
    tau: 60,
    beta: 60 * 2,
    gamma1: 1 << 19,
    gamma1_bits: 19,
    gamma2: (Q - 1) / 32,
    omega: 75,
    lambda: 256,
    w1_bits: 4,
    pk_bytes: pk_bytes(8),
    sk_bytes: sk_bytes(8, 7, 2),
    sig_bytes: sig_bytes(8, 7, 256, 19, 75),
    ctilde_bytes: 256 / 4,
};

pub mod ml_dsa_44 {
    use super::*;

    pub const K: usize = 4;
    pub const L: usize = 4;
    pub const ETA: u32 = ML_DSA_44.eta;
    pub const TAU: usize = ML_DSA_44.tau;
    pub const BETA: u32 = ML_DSA_44.beta;
    pub const GAMMA1: u32 = ML_DSA_44.gamma1;
    pub const GAMMA2: u32 = ML_DSA_44.gamma2;
    pub const OMEGA: usize = ML_DSA_44.omega;
    pub const LAMBDA: usize = ML_DSA_44.lambda;
    pub const GAMMA1_BITS: usize = ML_DSA_44.gamma1_bits;
    pub const W1_BITS: usize = ML_DSA_44.w1_bits;
    pub const PK_BYTES: usize = ML_DSA_44.pk_bytes;
    pub const SK_BYTES: usize = ML_DSA_44.sk_bytes;
    pub const SIG_BYTES: usize = ML_DSA_44.sig_bytes;
    pub const CTILDE_BYTES: usize = ML_DSA_44.ctilde_bytes;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_44() {
        assert_eq!(ML_DSA_44.pk_bytes, 1312);
        assert_eq!(ML_DSA_44.sk_bytes, 2560);
        assert_eq!(ML_DSA_44.sig_bytes, 2420);
        assert_eq!(ML_DSA_44.ctilde_bytes, 32);
    }

    #[test]
    fn sizes_65() {
        assert_eq!(ML_DSA_65.pk_bytes, 1952);
        assert_eq!(ML_DSA_65.sk_bytes, 4032);
        assert_eq!(ML_DSA_65.sig_bytes, 3309);
        assert_eq!(ML_DSA_65.ctilde_bytes, 48);
    }

    #[test]
    fn sizes_87() {
        assert_eq!(ML_DSA_87.pk_bytes, 2592);
        assert_eq!(ML_DSA_87.sk_bytes, 4896);
        assert_eq!(ML_DSA_87.sig_bytes, 4627);
        assert_eq!(ML_DSA_87.ctilde_bytes, 64);
    }

    #[test]
    fn w1_packed_bound() {
        for &(k, w1) in &[(4, 6), (6, 4), (8, 4)] {
            assert!(k * 32 * w1 <= MAX_W1_PACKED_BYTES);
        }
    }

    #[test]
    fn signed_roundtrip() {
        for x in [0, 1, 100, Q / 2 - 1, Q / 2, Q / 2 + 1, Q - 1] {
            let s = to_signed(x, Q);
            let r = from_signed(s, Q);
            assert_eq!(r, x);
        }
    }
}
