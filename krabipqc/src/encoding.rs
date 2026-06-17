//! ML-DSA byte / bit encoding routines used by verify (FIPS 204 §7).
//!
//! Streaming accessors ([`pk_t1_row`], [`sig_z_row`],
//! [`sig_hint_slice`], [`h_bit`], [`h_weight`]) read one polynomial
//! / one hint coefficient at a time straight from the input slice so
//! verify can run the matrix-vector multiply without materializing a
//! full `PolyVec<K>` scratch.

use crate::params::{N, Params};
use crate::poly::Poly;
use crate::sampling::bit_unpack_signed;

/// SimpleBitPack (FIPS 204 Alg 16). Output length: `32 * c_bits` bytes.
pub(crate) fn simple_bit_pack(p: &Poly<u32>, c_bits: usize, out: &mut [u8]) {
    debug_assert!(out.len() * 8 >= N * c_bits);
    out.fill(0);
    let mut acc: u64 = 0;
    let mut bits_in_acc: u32 = 0;
    let mut byte_idx = 0;
    for &coef in &p.coeffs {
        acc |= (coef as u64) << bits_in_acc;
        bits_in_acc += c_bits as u32;
        while bits_in_acc >= 8 {
            out[byte_idx] = acc as u8;
            byte_idx += 1;
            acc >>= 8;
            bits_in_acc -= 8;
        }
    }
    if bits_in_acc > 0 {
        out[byte_idx] = acc as u8;
    }
}

/// SimpleBitUnpack (FIPS 204 Alg 18): inverse of [`simple_bit_pack`].
pub(crate) fn simple_bit_unpack(bytes: &[u8], c_bits: usize) -> Poly<u32> {
    let mut out = Poly::<u32>::zero();
    let mask = (1u32 << c_bits) - 1;
    let mut acc: u64 = 0;
    let mut bits_in_acc: u32 = 0;
    let mut byte_idx = 0;
    for j in 0..N {
        while bits_in_acc < c_bits as u32 {
            acc |= (bytes[byte_idx] as u64) << bits_in_acc;
            byte_idx += 1;
            bits_in_acc += 8;
        }
        out.coeffs[j] = (acc as u32) & mask;
        acc >>= c_bits;
        bits_in_acc -= c_bits as u32;
    }
    out
}

/// BitUnpack (FIPS 204 Alg 19). Thin wrapper over
/// [`bit_unpack_signed`] kept in this module for naming symmetry.
pub(crate) fn bit_unpack(bytes: &[u8], b: u32, c_bits: usize) -> Poly<u32> {
    bit_unpack_signed(bytes, b, c_bits)
}

/// `i`-th `t1` row decoded straight from `pk`, without touching the
/// other rows.
pub fn pk_t1_row(pk: &[u8], i: usize) -> Poly<u32> {
    let chunk = 32 * 10;
    let start = 32 + i * chunk;
    simple_bit_unpack(&pk[start..start + chunk], 10)
}

/// `i`-th `z` row decoded straight from `sig`.
pub fn sig_z_row<const K: usize, const L: usize>(
    params: &Params<K, L>,
    sig: &[u8],
    i: usize,
) -> Poly<u32> {
    let z_bits = 1 + params.gamma1_bits;
    let z_chunk = 32 * z_bits;
    let off = params.ctilde_bytes + i * z_chunk;
    bit_unpack(&sig[off..off + z_chunk], params.gamma1, z_bits)
}

/// Subslice of `sig` covering the encoded hint, suitable for
/// [`h_bit`] / [`h_weight`] / [`validate_hint_bytes`].
pub fn sig_hint_slice<'a, const K: usize, const L: usize>(
    params: &Params<K, L>,
    sig: &'a [u8],
) -> &'a [u8] {
    let z_chunk = 32 * (1 + params.gamma1_bits);
    let off = params.ctilde_bytes + L * z_chunk;
    &sig[off..off + params.omega + K]
}

/// `j`-th coefficient (0 or 1) of the `i`-th hint polynomial, read
/// from the encoded form. Caller must have run [`validate_hint_bytes`]
/// first — out-of-range positions or non-monotone counts will panic
/// or return garbage here.
pub fn h_bit<const K: usize>(hint: &[u8], omega: usize, i: usize, j: usize) -> u32 {
    let start = if i == 0 {
        0
    } else {
        hint[omega + i - 1] as usize
    };
    let end = hint[omega + i] as usize;
    if hint[start..end].iter().any(|&pos| pos as usize == j) {
        1
    } else {
        0
    }
}

/// Total hint weight, read from the cumulative-count tail of the
/// encoded form.
pub fn h_weight<const K: usize>(hint: &[u8], omega: usize) -> u32 {
    hint[omega + K - 1] as u32
}

/// FIPS 204 `HintBitUnpack` validity check, without decoding. Returns
/// `false` on any malformed input; subsequent [`h_bit`] / [`h_weight`]
/// calls rely on this having passed.
pub fn validate_hint_bytes<const K: usize>(hint: &[u8], omega: usize) -> bool {
    if hint.len() != omega + K {
        return false;
    }
    let mut idx = 0usize;
    for i in 0..K {
        let end = hint[omega + i] as usize;
        if end < idx || end > omega {
            return false;
        }
        let mut prev: Option<u8> = None;
        for &pos in &hint[idx..end] {
            if pos as usize >= N {
                return false;
            }
            if let Some(p) = prev
                && pos <= p
            {
                return false;
            }
            prev = Some(pos);
        }
        idx = end;
    }
    if hint[idx..omega].iter().any(|&b| b != 0) {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::ml_dsa_44::W1_BITS;

    #[test]
    fn simple_bit_pack_unpack_roundtrip() {
        let mut p = Poly::<u32>::zero();
        let max = (1u32 << W1_BITS) - 1;
        for j in 0..N {
            p.coeffs[j] = (j as u32) & max;
        }
        let mut buf = [0u8; 32 * W1_BITS];
        simple_bit_pack(&p, W1_BITS, &mut buf);
        let q = simple_bit_unpack(&buf, W1_BITS);
        assert_eq!(q, p);
    }
}
