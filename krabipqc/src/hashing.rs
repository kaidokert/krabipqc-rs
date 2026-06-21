//! SHAKE128/256 wrappers used by ML-DSA, plus the SHA3-256 / SHA3-512
//! helpers needed by ML-KEM (FIPS 203's H and G respectively).

use sha3::digest::{ExtendableOutput, FixedOutput, Update, XofReader};
use sha3::{Sha3_256, Sha3_512, Shake128, Shake256};

/// A simple streaming SHAKE-128 absorber/squeezer.
pub struct Shake128Stream(sha3::Shake128Reader);

impl Shake128Stream {
    /// SHAKE-128 rate in bytes (= (1600 - 2*128) / 8).
    pub const RATE: usize = 168;

    pub fn new(inputs: &[&[u8]]) -> Self {
        let mut h = Shake128::default();
        for x in inputs {
            h.update(x);
        }
        Self(h.finalize_xof())
    }

    pub fn squeeze(&mut self, out: &mut [u8]) {
        self.0.read(out);
    }
}

/// A simple streaming SHAKE-256 absorber/squeezer.
pub struct Shake256Stream(sha3::Shake256Reader);

impl Shake256Stream {
    /// SHAKE-256 rate in bytes (= (1600 - 2*256) / 8).
    pub const RATE: usize = 136;

    pub fn new(inputs: &[&[u8]]) -> Self {
        let mut h = Shake256::default();
        for x in inputs {
            h.update(x);
        }
        Self(h.finalize_xof())
    }

    pub fn squeeze(&mut self, out: &mut [u8]) {
        self.0.read(out);
    }
}

/// Convenience: SHAKE-256 to a fixed-size output, one-shot.
pub fn shake256(inputs: &[&[u8]], out: &mut [u8]) {
    let mut s = Shake256Stream::new(inputs);
    s.squeeze(out);
}

/// Convenience: SHAKE-128 to a fixed-size output, one-shot.
#[cfg(test)]
pub fn shake128(inputs: &[&[u8]], out: &mut [u8]) {
    let mut s = Shake128Stream::new(inputs);
    s.squeeze(out);
}

/// SHA3-256 one-shot — FIPS 203's `H`.
pub fn sha3_256(inputs: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha3_256::default();
    for x in inputs {
        h.update(x);
    }
    let mut out = [0u8; 32];
    h.finalize_into((&mut out).into());
    out
}

/// SHA3-512 one-shot — FIPS 203's `G`.
pub fn sha3_512(inputs: &[&[u8]]) -> [u8; 64] {
    let mut h = Sha3_512::default();
    for x in inputs {
        h.update(x);
    }
    let mut out = [0u8; 64];
    h.finalize_into((&mut out).into());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Known SHAKE-256 test vector (NIST CAVS): SHAKE256("",0).
    #[test]
    fn shake256_empty_short() {
        let mut out = [0u8; 16];
        shake256(&[b""], &mut out);
        assert_eq!(
            out,
            [
                0x46, 0xb9, 0xdd, 0x2b, 0x0b, 0xa8, 0x8d, 0x13, 0x23, 0x3b, 0x3f, 0xeb, 0x74, 0x3e,
                0xeb, 0x24
            ]
        );
    }

    #[test]
    fn shake128_empty_short() {
        let mut out = [0u8; 16];
        shake128(&[b""], &mut out);
        assert_eq!(
            out,
            [
                0x7f, 0x9c, 0x2b, 0xa4, 0xe8, 0x8f, 0x82, 0x7d, 0x61, 0x60, 0x45, 0x50, 0x76, 0x05,
                0x85, 0x3e
            ]
        );
    }

    #[test]
    fn streaming_matches_oneshot() {
        let mut a = [0u8; 64];
        shake256(&[b"hello", b" ", b"world"], &mut a);
        let mut b = [0u8; 64];
        let mut s = Shake256Stream::new(&[b"hello world"]);
        s.squeeze(&mut b);
        assert_eq!(a, b);
    }
}
