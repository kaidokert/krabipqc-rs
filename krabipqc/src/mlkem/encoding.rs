//! ML-KEM encoding helpers (FIPS 203 §4.2):
//!
//! * `Compress_d` / `Decompress_d` (Alg 4/5) — d-bit rounding.
//! * `ByteEncode_d` / `ByteDecode_d` (Alg 5/6) — pack 256 d-bit ints.

use crate::encoding::EncodeError;
use crate::mlkem::params::{N, Q};
use crate::poly::Poly;
use crate::polyvec::PolyVec;

const Q_VAL: u32 = Q;

/// Compress_d (Alg 4): map x ∈ Z_q to a d-bit integer via
/// `round((2^d / q) * x)`. u32 so the const-divisor lowers to
/// UMULL+shift on no-UDIV cores (cortex-m3). `d` must be in 1..=11.
#[inline]
pub(crate) fn compress_d(x: u32, d: usize) -> u32 {
    let num = (x << d).wrapping_mul(2) + Q_VAL;
    let y = num / (2 * Q_VAL);
    y & ((1u32 << d) - 1)
}

/// Decompress_d (Alg 5): map a d-bit integer y to Z_q via
/// `round((q / 2^d) * y)`. `d` must be in 1..=11.
#[inline]
pub(crate) fn decompress_d(y: u32, d: usize) -> u32 {
    (y * Q_VAL + (1u32 << (d - 1))) >> d
}

/// Apply [`compress_d`] coefficient-wise.
pub(crate) fn compress_poly(p: &Poly<u32>, d: usize) -> Poly<u32> {
    let mut out = Poly::<u32>::zero();
    for i in 0..N {
        out.coeffs[i] = compress_d(p.coeffs[i], d);
    }
    out
}

/// Apply [`decompress_d`] coefficient-wise.
pub(crate) fn decompress_poly(p: &Poly<u32>, d: usize) -> Poly<u32> {
    let mut out = Poly::<u32>::zero();
    for i in 0..N {
        out.coeffs[i] = decompress_d(p.coeffs[i], d);
    }
    out
}

/// ByteEncode_d (Alg 5): pack 256 coefficients, each occupying `d` bits,
/// into a 32*d byte buffer (LSB-first within each byte).
pub(crate) fn byte_encode(p: &Poly<u32>, d: usize, out: &mut [u8]) -> Result<(), EncodeError> {
    out.fill(0);
    let mut acc: u64 = 0;
    let mut bits: u32 = 0;
    let mut byte_idx = 0;
    for &c in &p.coeffs {
        acc |= (c as u64) << bits;
        bits += d as u32;
        while bits >= 8 {
            *out.get_mut(byte_idx).ok_or(EncodeError::BufferTooSmall)? = acc as u8;
            byte_idx += 1;
            acc >>= 8;
            bits -= 8;
        }
    }
    if bits > 0 {
        *out.get_mut(byte_idx).ok_or(EncodeError::BufferTooSmall)? = acc as u8;
    }
    Ok(())
}

/// ByteDecode_d (Alg 6): inverse of [`byte_encode`].
pub(crate) fn byte_decode(bytes: &[u8], d: usize) -> Result<Poly<u32>, EncodeError> {
    let mut out = Poly::<u32>::zero();
    let mask = (1u32 << d) - 1;
    let mut acc: u64 = 0;
    let mut bits: u32 = 0;
    let mut byte_idx = 0;
    for i in 0..N {
        while bits < d as u32 {
            let byte = *bytes.get(byte_idx).ok_or(EncodeError::BufferTooSmall)?;
            acc |= (byte as u64) << bits;
            byte_idx += 1;
            bits += 8;
        }
        out.coeffs[i] = (acc as u32) & mask;
        acc >>= d;
        bits -= d as u32;
    }
    Ok(out)
}

/// ByteEncode for a PolyVec: pack each polynomial with `d` bits per coeff.
pub(crate) fn byte_encode_vec<const LEN: usize>(
    v: &PolyVec<u32, LEN>,
    d: usize,
    out: &mut [u8],
) -> Result<(), EncodeError> {
    let chunk = 32 * d;
    for i in 0..LEN {
        let slot = out
            .get_mut(i * chunk..(i + 1) * chunk)
            .ok_or(EncodeError::BufferTooSmall)?;
        byte_encode(&v.v[i], d, slot)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::to_signed;
    use modmath::basic::pre_reduced as pr;

    #[test]
    fn compress_decompress_d_bounds() {
        // For random x, decompress(compress(x)) is within q / 2^(d+1) of x.
        let mut state: u64 = 0xdead_cafe_beef_1234;
        for _ in 0..2000 {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let x = (state as u32) % Q_VAL;
            for &d in &[1usize, 4, 5, 10, 11] {
                let y = compress_d(x, d);
                assert!(
                    y < (1u32 << d),
                    "compress_{}({}) = {} out of range",
                    d,
                    x,
                    y
                );
                let xr = decompress_d(y, d);
                // |xr - x| ≤ ceil(q / 2^(d+1))
                let bound = (Q_VAL + (1u32 << (d + 1)) - 1) >> (d + 1);
                let centered = to_signed(pr::sub::<u32>(xr, x, Q), Q).unsigned_abs();
                assert!(
                    centered <= bound,
                    "d={}, x={}, y={}, xr={}, centered diff={} > bound={}",
                    d,
                    x,
                    y,
                    xr,
                    centered,
                    bound
                );
            }
        }
    }

    #[test]
    fn byte_encode_decode_roundtrip_d12() {
        // d = 12 is full-precision: no information loss.
        let mut p = Poly::<u32>::zero();
        for i in 0..N {
            p.coeffs[i] = (i as u32 * 13 + 7) % Q_VAL;
        }
        let mut buf = vec![0u8; 32 * 12];
        byte_encode(&p, 12, &mut buf).unwrap();
        let q = byte_decode(&buf, 12).unwrap();
        assert_eq!(q, p);
    }

    #[test]
    fn byte_encode_decode_roundtrip_d10() {
        let mut p = Poly::<u32>::zero();
        let mask = (1u32 << 10) - 1;
        for i in 0..N {
            p.coeffs[i] = (i as u32 * 7) & mask;
        }
        let mut buf = vec![0u8; 32 * 10];
        byte_encode(&p, 10, &mut buf).unwrap();
        let q = byte_decode(&buf, 10).unwrap();
        assert_eq!(q, p);
    }

    #[test]
    fn compress_then_byte_encode_roundtrip() {
        // compress -> encode -> decode -> decompress should recover within bound.
        let mut p = Poly::<u32>::zero();
        for i in 0..N {
            p.coeffs[i] = (i as u32 * 19 + 3) % Q_VAL;
        }
        for &d in &[1usize, 4, 5, 10, 11] {
            let cp = compress_poly(&p, d);
            let mut buf = vec![0u8; 32 * d];
            byte_encode(&cp, d, &mut buf).unwrap();
            let dp = byte_decode(&buf, d).unwrap();
            assert_eq!(dp, cp, "byte enc/dec at d={}", d);
            let recovered = decompress_poly(&dp, d);
            let bound = (Q_VAL + (1u32 << (d + 1)) - 1) >> (d + 1);
            for (a, b) in p.coeffs.iter().zip(recovered.coeffs.iter()) {
                let diff = to_signed(pr::sub::<u32>(*b, *a, Q), Q).unsigned_abs();
                assert!(diff <= bound, "d={}, diff={} > bound={}", d, diff, bound);
            }
        }
    }

    #[test]
    fn byte_encode_short_buf_errors() {
        let p = Poly::<u32>::zero();
        let mut buf = vec![0u8; 32 * 12 - 1];
        assert_eq!(
            byte_encode(&p, 12, &mut buf),
            Err(EncodeError::BufferTooSmall)
        );
    }

    #[test]
    fn byte_decode_short_buf_errors() {
        let buf = vec![0u8; 32 * 12 - 1];
        assert_eq!(byte_decode(&buf, 12), Err(EncodeError::BufferTooSmall));
    }
}
