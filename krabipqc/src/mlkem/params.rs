//! ML-KEM scheme parameters and Z_q modulus (FIPS 203 §8 + Table 2).
//!
//! ML-KEM's modulus is q = 3329; the incomplete 7-layer NTT lives in
//! [`crate::mlkem::ntt`].
//!
//! Three parameter sets ship as `const` instances:
//! [`ML_KEM_512`], [`ML_KEM_768`], [`ML_KEM_1024`].

/// Modulus q = 2^8 * 13 + 1 = 3329.
pub const Q: u32 = 3329;

/// `-Q^-1 mod 2^32`, used by `wide::mul` Montgomery REDC.
pub const Q_N_PRIME: u32 = 2_488_732_927;

/// `R^2 mod Q` = `2^64 mod Q`, used by canonical-to-Mont conversion.
pub const Q_R2_MOD_Q: u32 = 2988;

/// Polynomial degree (same n as ML-DSA).
pub const N: usize = 256;

/// 256-th principal root of unity mod 3329 (FIPS 203 uses zeta = 17, a
/// primitive 256-th root; the incomplete NTT splits `R_q` into 128 copies
/// of `Z_q[X]/(X^2 − zeta^{2*BitRev_7(i)+1})`).
#[cfg(test)]
pub const ZETA: u32 = 17;

/// CBD parameter η — FIPS 203 only defines η ∈ {2, 3}. Closed enum so
/// `prf_eta`/`sample_poly_cbd` can size the SHAKE-256 squeeze buffer
/// without runtime range checks or worst-case over-allocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Eta {
    /// η = 2 — used by ML-KEM-768/1024 (eta1, eta2) and ML-KEM-512 (eta2).
    Two,
    /// η = 3 — used by ML-KEM-512 (eta1).
    Three,
}

impl Eta {
    /// Numeric value (2 or 3).
    #[inline]
    pub const fn value(self) -> u32 {
        match self {
            Eta::Two => 2,
            Eta::Three => 3,
        }
    }

    /// PRF output / CBD input length in bytes (64 · η).
    #[inline]
    pub const fn buf_len(self) -> usize {
        64 * self.value() as usize
    }
}

/// PRF output buffer size that fits both η values without
/// over-allocating beyond what the larger one needs.
pub const PRF_BUF_LEN: usize = 64 * 3;

/// Per-parameter-set constants. `K` is the module rank.
///
/// `#[non_exhaustive]` prevents external code from constructing custom
/// (potentially invalid) parameter sets — only [`ML_KEM_512`],
/// [`ML_KEM_768`], [`ML_KEM_1024`] are reachable from outside the crate.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct Params<const K: usize> {
    pub eta1: Eta,
    pub eta2: Eta,
    pub du: usize,
    pub dv: usize,
    pub ek_bytes: usize, // public key (encapsulation key)
    pub dk_bytes: usize, // private key (decapsulation key)
    pub ct_bytes: usize, // ciphertext
}

/// Shared-secret length (always 32 bytes).
pub const SS_BYTES: usize = 32;

const fn ek_bytes(k: usize) -> usize {
    // 32 (rho) + 384 bytes per encoded polynomial (12 bits * 256 / 8)
    32 + 384 * k
}
const fn dk_bytes(k: usize) -> usize {
    // dk_PKE (384*k) + ek (32 + 384*k) + H(ek) (32) + z (32)
    384 * k + ek_bytes(k) + 32 + 32
}
const fn ct_bytes(k: usize, du: usize, dv: usize) -> usize {
    32 * (du * k + dv)
}

/// ML-KEM-512 (k=2, eta1=3, eta2=2, du=10, dv=4).
pub const ML_KEM_512: Params<2> = Params {
    eta1: Eta::Three,
    eta2: Eta::Two,
    du: 10,
    dv: 4,
    ek_bytes: ek_bytes(2),
    dk_bytes: dk_bytes(2),
    ct_bytes: ct_bytes(2, 10, 4),
};

/// ML-KEM-768 (k=3, eta1=2, eta2=2, du=10, dv=4).
pub const ML_KEM_768: Params<3> = Params {
    eta1: Eta::Two,
    eta2: Eta::Two,
    du: 10,
    dv: 4,
    ek_bytes: ek_bytes(3),
    dk_bytes: dk_bytes(3),
    ct_bytes: ct_bytes(3, 10, 4),
};

/// ML-KEM-1024 (k=4, eta1=2, eta2=2, du=11, dv=5).
pub const ML_KEM_1024: Params<4> = Params {
    eta1: Eta::Two,
    eta2: Eta::Two,
    du: 11,
    dv: 5,
    ek_bytes: ek_bytes(4),
    dk_bytes: dk_bytes(4),
    ct_bytes: ct_bytes(4, 11, 5),
};

#[cfg(test)]
mod tests {
    use super::*;
    use modmath::basic::pre_reduced as pr;

    #[test]
    fn sizes_512() {
        assert_eq!(ML_KEM_512.ek_bytes, 800);
        assert_eq!(ML_KEM_512.dk_bytes, 1632);
        assert_eq!(ML_KEM_512.ct_bytes, 768);
    }

    #[test]
    fn sizes_768() {
        assert_eq!(ML_KEM_768.ek_bytes, 1184);
        assert_eq!(ML_KEM_768.dk_bytes, 2400);
        assert_eq!(ML_KEM_768.ct_bytes, 1088);
    }

    #[test]
    fn sizes_1024() {
        assert_eq!(ML_KEM_1024.ek_bytes, 1568);
        assert_eq!(ML_KEM_1024.dk_bytes, 3168);
        assert_eq!(ML_KEM_1024.ct_bytes, 1568);
    }

    #[test]
    fn zeta_is_primitive_256th_root() {
        // zeta^128 = -1 mod q, zeta^256 = 1 mod q.
        assert_eq!(pr::exp::<u32>(ZETA, 128, Q), Q - 1);
        assert_eq!(pr::exp::<u32>(ZETA, 256, Q), 1);
    }
}
