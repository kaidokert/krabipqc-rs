//! ML-DSA byte / bit encoding (FIPS 204 §7).
//!
//! Three families:
//!
//! * Bit packers / unpackers: [`simple_bit_pack`] / [`simple_bit_unpack`]
//!   for unsigned ranges, [`bit_pack`] / [`bit_unpack`] for centered
//!   ranges via [`crate::sampling::bit_unpack_signed`].
//! * Public/secret-key codecs: [`pk_encode`], [`sk_encode`] /
//!   [`sk_decode`]. Sign streams z + hint directly into the sig
//!   buffer rather than going through a `sig_encode` round-trip.
//! * Verify-side streaming accessors: [`pk_t1_row`], [`sig_z_row`],
//!   [`sig_hint_slice`], [`h_row_positions`], [`h_weight`],
//!   [`validate_hint_bytes`]. Let verify read one polynomial or one
//!   hint coefficient at a time without materializing a full
//!   `PolyVec<K>` scratch.

use crate::params::{D, N, Params, Q, to_signed};
use crate::poly::Poly;
use crate::polyvec::PolyVec;
use crate::sampling::bit_unpack_signed;

/// Out-of-range slice access while encoding or decoding, or a value
/// outside its valid range surfaced by an input-validation check
/// (e.g. FIPS 203 §7.2 encapsulation-key modulus check).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodeError {
    BufferTooSmall,
    /// A decoded coefficient was not in canonical range (e.g. ≥ q for
    /// a 12-bit-packed ML-KEM `t_hat`).
    NotCanonical,
}

impl core::fmt::Display for EncodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            EncodeError::BufferTooSmall => f.write_str("buffer too small"),
            EncodeError::NotCanonical => f.write_str("non-canonical encoding"),
        }
    }
}

impl core::error::Error for EncodeError {}

/// `ceil(log2(a+1))` — minimum unsigned bit count for representing `a`.
#[inline]
pub(crate) const fn bitlen(mut a: u32) -> usize {
    let mut n = 0;
    while a > 0 {
        n += 1;
        a >>= 1;
    }
    n
}

/// SimpleBitPack (FIPS 204 Alg 16). Output length: `32 * c_bits` bytes.
pub(crate) fn simple_bit_pack(
    p: &Poly<u32>,
    c_bits: usize,
    out: &mut [u8],
) -> Result<(), EncodeError> {
    out.fill(0);
    let mut acc: u64 = 0;
    let mut bits_in_acc: u32 = 0;
    let mut byte_idx = 0;
    for &coef in &p.coeffs {
        acc |= (coef as u64) << bits_in_acc;
        bits_in_acc += c_bits as u32;
        while bits_in_acc >= 8 {
            *out.get_mut(byte_idx).ok_or(EncodeError::BufferTooSmall)? = acc as u8;
            byte_idx += 1;
            acc >>= 8;
            bits_in_acc -= 8;
        }
    }
    if bits_in_acc > 0 {
        *out.get_mut(byte_idx).ok_or(EncodeError::BufferTooSmall)? = acc as u8;
    }
    Ok(())
}

/// SimpleBitUnpack (FIPS 204 Alg 18): inverse of [`simple_bit_pack`].
pub(crate) fn simple_bit_unpack(bytes: &[u8], c_bits: usize) -> Result<Poly<u32>, EncodeError> {
    let mut out = Poly::<u32>::zero();
    let mask = (1u32 << c_bits) - 1;
    let mut acc: u64 = 0;
    let mut bits_in_acc: u32 = 0;
    let mut byte_idx = 0;
    for j in 0..N {
        while bits_in_acc < c_bits as u32 {
            let byte = *bytes.get(byte_idx).ok_or(EncodeError::BufferTooSmall)?;
            acc |= (byte as u64) << bits_in_acc;
            byte_idx += 1;
            bits_in_acc += 8;
        }
        out.coeffs[j] = (acc as u32) & mask;
        acc >>= c_bits;
        bits_in_acc -= c_bits as u32;
    }
    Ok(out)
}

/// BitUnpack (FIPS 204 Alg 19). Thin wrapper over
/// [`bit_unpack_signed`] kept in this module for naming symmetry.
pub(crate) fn bit_unpack(bytes: &[u8], b: u32, c_bits: usize) -> Result<Poly<u32>, EncodeError> {
    bit_unpack_signed(bytes, b, c_bits)
}

/// BitPack (FIPS 204 Alg 17): pack 256 canonical-Z_q coefficients with
/// centered values in `[-a, b]` using `c = bitlen(a + b)` bits each.
/// Each coefficient is stored as `zp = b - centered ∈ [0, a + b]`;
/// the FIPS `a` argument is implicit since the caller computes
/// `c_bits` from `bitlen(a + b)` and we only need `b` to recover the
/// centered value.
pub(crate) fn bit_pack(
    p: &Poly<u32>,
    b: u32,
    c_bits: usize,
    out: &mut [u8],
) -> Result<(), EncodeError> {
    out.fill(0);
    let mut acc: u64 = 0;
    let mut bits_in_acc: u32 = 0;
    let mut byte_idx = 0;
    for &canon in &p.coeffs {
        let centered = to_signed(canon, Q) as i64;
        let zp = (b as i64) - centered;
        acc |= (zp as u64) << bits_in_acc;
        bits_in_acc += c_bits as u32;
        while bits_in_acc >= 8 {
            *out.get_mut(byte_idx).ok_or(EncodeError::BufferTooSmall)? = acc as u8;
            byte_idx += 1;
            acc >>= 8;
            bits_in_acc -= 8;
        }
    }
    if bits_in_acc > 0 {
        *out.get_mut(byte_idx).ok_or(EncodeError::BufferTooSmall)? = acc as u8;
    }
    Ok(())
}

/// `i`-th `t1` row decoded straight from `pk`, without touching the
/// other rows.
pub fn pk_t1_row(pk: &[u8], i: usize) -> Result<Poly<u32>, EncodeError> {
    let chunk = 32 * 10;
    let start = 32 + i * chunk;
    let slice = pk
        .get(start..start + chunk)
        .ok_or(EncodeError::BufferTooSmall)?;
    simple_bit_unpack(slice, 10)
}

/// `i`-th `z` row decoded straight from `sig`.
pub fn sig_z_row<const K: usize, const L: usize>(
    params: &Params<K, L>,
    sig: &[u8],
    i: usize,
) -> Result<Poly<u32>, EncodeError> {
    let z_bits = 1 + params.gamma1_bits;
    let z_chunk = 32 * z_bits;
    let off = params.ctilde_bytes + i * z_chunk;
    let slice = sig
        .get(off..off + z_chunk)
        .ok_or(EncodeError::BufferTooSmall)?;
    bit_unpack(slice, params.gamma1, z_bits)
}

/// `(b, bits)` for the `s1` / `s2` BitPack range (centered `[-eta, eta]`).
fn sk_s_packing<const K: usize, const L: usize>(params: &Params<K, L>) -> (u32, usize) {
    let eta = params.eta.value();
    (eta, bitlen(eta.saturating_mul(2)))
}

/// `(b, bits)` for the `t0` BitPack range. `D` is a compile-time
/// constant, so these fold and can't overflow at runtime.
fn sk_t0_packing() -> (u32, usize) {
    let t0_b = 1u32 << (D - 1);
    let t0_a = t0_b - 1;
    (t0_b, bitlen(t0_a + t0_b))
}

/// Decode `s1` / `s2` / `t0` from `sk` straight into the caller's NTT
/// slots, in canonical (pre-NTT) form. Bypasses the whole-sk
/// `DecodedSk` tuple — which would stage a second copy of the secrets
/// on the stack — and walks the key body one row at a time with
/// [`<[u8]>::split_at_checked`] rather than computing absolute byte
/// offsets. There is therefore no `i * chunk` / `off + chunk`
/// arithmetic to overflow: every step advances the cursor by one
/// chunk (sizes are `saturating_mul` so a degenerate parameter set
/// caps out instead of wrapping) and a short key surfaces as
/// `BufferTooSmall` instead of panicking.
///
/// The `lowmem` sign path re-derives rows on demand via
/// [`SkSecretReader`] instead, so this whole-secret decode is the
/// default path only.
#[cfg(not(feature = "lowmem"))]
pub(crate) fn decode_sk_secrets<const K: usize, const L: usize>(
    params: &Params<K, L>,
    sk: &[u8],
    s1: &mut PolyVec<u32, L>,
    s2: &mut PolyVec<u32, K>,
    t0: &mut PolyVec<u32, K>,
) -> Result<(), EncodeError> {
    let (eta, eta_bits) = sk_s_packing(params);
    let s_chunk = eta_bits.saturating_mul(32);
    let (t0_b, t0_bits) = sk_t0_packing();
    let t0_chunk = t0_bits.saturating_mul(32);

    // Skip the rho / K / tr header; the caller lifts those out itself.
    let mut cur = sk.get(128..).ok_or(EncodeError::BufferTooSmall)?;
    for poly in s1.v.iter_mut() {
        let (row, rest) = cur
            .split_at_checked(s_chunk)
            .ok_or(EncodeError::BufferTooSmall)?;
        *poly = bit_unpack(row, eta, eta_bits)?;
        cur = rest;
    }
    for poly in s2.v.iter_mut() {
        let (row, rest) = cur
            .split_at_checked(s_chunk)
            .ok_or(EncodeError::BufferTooSmall)?;
        *poly = bit_unpack(row, eta, eta_bits)?;
        cur = rest;
    }
    for poly in t0.v.iter_mut() {
        let (row, rest) = cur
            .split_at_checked(t0_chunk)
            .ok_or(EncodeError::BufferTooSmall)?;
        *poly = bit_unpack(row, t0_b, t0_bits)?;
        cur = rest;
    }
    Ok(())
}

/// Random-access view over the `s1` / `s2` / `t0` rows of an `sk`, for
/// the `lowmem` sign path which re-derives one secret row at a time
/// inside the kappa loop instead of holding the `s1_hat` / `s2_hat` /
/// `t0_hat` PolyVecs. The three regions are carved once with
/// `split_at_checked`; each row is `chunks_exact(..).nth(i)`, so no byte
/// offset is computed and a malformed key or out-of-range row yields
/// `BufferTooSmall` rather than panicking. Holds only borrows of `sk`,
/// so the reader itself costs no secret stack.
#[cfg(feature = "lowmem")]
pub(crate) struct SkSecretReader<'a> {
    s1: &'a [u8],
    s2: &'a [u8],
    t0: &'a [u8],
    eta: u32,
    eta_bits: usize,
    s_chunk: usize,
    t0_b: u32,
    t0_bits: usize,
    t0_chunk: usize,
}

#[cfg(feature = "lowmem")]
impl<'a> SkSecretReader<'a> {
    pub(crate) fn new<const K: usize, const L: usize>(
        params: &Params<K, L>,
        sk: &'a [u8],
    ) -> Result<Self, EncodeError> {
        let (eta, eta_bits) = sk_s_packing(params);
        let s_chunk = eta_bits.saturating_mul(32);
        let (t0_b, t0_bits) = sk_t0_packing();
        let t0_chunk = t0_bits.saturating_mul(32);
        // `chunks_exact` panics on a zero chunk size; a degenerate
        // (eta = 0) parameter set is rejected here instead.
        if s_chunk == 0 || t0_chunk == 0 {
            return Err(EncodeError::BufferTooSmall);
        }
        let body = sk.get(128..).ok_or(EncodeError::BufferTooSmall)?;
        let (s1, rest) = body
            .split_at_checked(s_chunk.saturating_mul(L))
            .ok_or(EncodeError::BufferTooSmall)?;
        let (s2, rest) = rest
            .split_at_checked(s_chunk.saturating_mul(K))
            .ok_or(EncodeError::BufferTooSmall)?;
        // Carve t0 to exactly K rows too, so a truncated key fails here
        // rather than later inside `t0_row`.
        let (t0, _) = rest
            .split_at_checked(t0_chunk.saturating_mul(K))
            .ok_or(EncodeError::BufferTooSmall)?;
        Ok(Self {
            s1,
            s2,
            t0,
            eta,
            eta_bits,
            s_chunk,
            t0_b,
            t0_bits,
            t0_chunk,
        })
    }

    pub(crate) fn s1_row(&self, i: usize) -> Result<Poly<u32>, EncodeError> {
        let row = self
            .s1
            .chunks_exact(self.s_chunk)
            .nth(i)
            .ok_or(EncodeError::BufferTooSmall)?;
        bit_unpack(row, self.eta, self.eta_bits)
    }

    pub(crate) fn s2_row(&self, i: usize) -> Result<Poly<u32>, EncodeError> {
        let row = self
            .s2
            .chunks_exact(self.s_chunk)
            .nth(i)
            .ok_or(EncodeError::BufferTooSmall)?;
        bit_unpack(row, self.eta, self.eta_bits)
    }

    pub(crate) fn t0_row(&self, i: usize) -> Result<Poly<u32>, EncodeError> {
        let row = self
            .t0
            .chunks_exact(self.t0_chunk)
            .nth(i)
            .ok_or(EncodeError::BufferTooSmall)?;
        bit_unpack(row, self.t0_b, self.t0_bits)
    }
}

/// Subslice of `sig` covering the encoded hint, suitable for
/// [`h_row_positions`] / [`h_weight`] / [`validate_hint_bytes`].
pub fn sig_hint_slice<'a, const K: usize, const L: usize>(
    params: &Params<K, L>,
    sig: &'a [u8],
) -> &'a [u8] {
    let z_chunk = 32 * (1 + params.gamma1_bits);
    let off = params.ctilde_bytes + L * z_chunk;
    &sig[off..off + params.omega + K]
}

/// Iterator over the set positions of the `i`-th hint polynomial.
/// Positions are strictly increasing (guaranteed by the prior
/// [`validate_hint_bytes`] check), so a single pass through the verify
/// loop can apply hints in `O(omega_row)` instead of `O(omega · N)`.
pub fn h_row_positions<const K: usize>(
    hint: &[u8],
    omega: usize,
    i: usize,
) -> impl Iterator<Item = usize> + '_ {
    let start = if i == 0 {
        0
    } else {
        hint[omega + i - 1] as usize
    };
    let end = hint[omega + i] as usize;
    hint[start..end].iter().map(|&pos| pos as usize)
}

/// Total hint weight, read from the cumulative-count tail of the
/// encoded form.
pub fn h_weight<const K: usize>(hint: &[u8], omega: usize) -> u32 {
    hint[omega + K - 1] as u32
}

/// FIPS 204 `HintBitUnpack` validity check, without decoding. Returns
/// `false` on any malformed input; subsequent [`h_row_positions`] /
/// [`h_weight`] calls rely on this having passed.
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

/// Decoded secret-key components produced by [`sk_decode`]. The sign
/// path decodes rows individually via `sk_s1_row` / `sk_s2_row` /
/// `sk_t0_row`, so the whole-sk decode is exercised only by the
/// round-trip tests — hence `#[cfg(test)]`.
#[cfg(test)]
pub type DecodedSk<const K: usize, const L: usize> = (
    [u8; 32],
    [u8; 32],
    [u8; 64],
    PolyVec<u32, L>,
    PolyVec<u32, K>,
    PolyVec<u32, K>,
);

/// pkEncode (FIPS 204 Alg 22). Output length: `32 + 32 * K * 10`.
pub fn pk_encode<const K: usize>(
    rho: &[u8; 32],
    t1: &PolyVec<u32, K>,
    out: &mut [u8],
) -> Result<(), EncodeError> {
    out.get_mut(..32)
        .ok_or(EncodeError::BufferTooSmall)?
        .copy_from_slice(rho);
    // bitlen(q-1) - d = 23 - 13 = 10.
    let c_bits = 10;
    let chunk = 32 * c_bits;
    for i in 0..K {
        let start = 32 + i * chunk;
        let dst = out
            .get_mut(start..start + chunk)
            .ok_or(EncodeError::BufferTooSmall)?;
        simple_bit_pack(&t1.v[i], c_bits, dst)?;
    }
    Ok(())
}

/// skEncode (FIPS 204 Alg 24). Output length: `params.sk_bytes`.
#[allow(clippy::too_many_arguments)]
pub fn sk_encode<const K: usize, const L: usize>(
    params: &Params<K, L>,
    rho: &[u8; 32],
    big_k: &[u8; 32],
    tr: &[u8; 64],
    s1: &PolyVec<u32, L>,
    s2: &PolyVec<u32, K>,
    t0: &PolyVec<u32, K>,
    out: &mut [u8],
) -> Result<(), EncodeError> {
    out.get_mut(..32)
        .ok_or(EncodeError::BufferTooSmall)?
        .copy_from_slice(rho);
    out.get_mut(32..64)
        .ok_or(EncodeError::BufferTooSmall)?
        .copy_from_slice(big_k);
    out.get_mut(64..128)
        .ok_or(EncodeError::BufferTooSmall)?
        .copy_from_slice(tr);

    let eta = params.eta.value();
    let eta_bits = bitlen(2 * eta);
    let s_chunk = 32 * eta_bits;
    let mut off = 128;
    for i in 0..L {
        let dst = out
            .get_mut(off..off + s_chunk)
            .ok_or(EncodeError::BufferTooSmall)?;
        bit_pack(&s1.v[i], eta, eta_bits, dst)?;
        off += s_chunk;
    }
    for i in 0..K {
        let dst = out
            .get_mut(off..off + s_chunk)
            .ok_or(EncodeError::BufferTooSmall)?;
        bit_pack(&s2.v[i], eta, eta_bits, dst)?;
        off += s_chunk;
    }
    let t0_a = (1u32 << (D - 1)) - 1;
    let t0_b = 1u32 << (D - 1);
    let t0_bits = bitlen(t0_a + t0_b);
    let t0_chunk = 32 * t0_bits;
    for i in 0..K {
        let dst = out
            .get_mut(off..off + t0_chunk)
            .ok_or(EncodeError::BufferTooSmall)?;
        bit_pack(&t0.v[i], t0_b, t0_bits, dst)?;
        off += t0_chunk;
    }
    Ok(())
}

/// skDecode (FIPS 204 Alg 25). Inverse of [`sk_encode`]; the sign path
/// streams rows via the `sk_*_row` accessors, so this whole-sk form is
/// kept for the encode/decode round-trip tests.
#[cfg(test)]
pub fn sk_decode<const K: usize, const L: usize>(
    params: &Params<K, L>,
    sk: &[u8],
) -> Result<DecodedSk<K, L>, EncodeError> {
    if sk.len() != params.sk_bytes {
        return Err(EncodeError::BufferTooSmall);
    }
    let mut rho = [0u8; 32];
    let mut big_k = [0u8; 32];
    let mut tr = [0u8; 64];
    rho.copy_from_slice(&sk[..32]);
    big_k.copy_from_slice(&sk[32..64]);
    tr.copy_from_slice(&sk[64..128]);

    let eta = params.eta.value();
    let eta_bits = bitlen(2 * eta);
    let s_chunk = 32 * eta_bits;
    let mut off = 128;
    let mut s1 = PolyVec::<u32, L>::zero();
    let mut s2 = PolyVec::<u32, K>::zero();
    for i in 0..L {
        let src = sk
            .get(off..off + s_chunk)
            .ok_or(EncodeError::BufferTooSmall)?;
        s1.v[i] = bit_unpack(src, eta, eta_bits)?;
        off += s_chunk;
    }
    for i in 0..K {
        let src = sk
            .get(off..off + s_chunk)
            .ok_or(EncodeError::BufferTooSmall)?;
        s2.v[i] = bit_unpack(src, eta, eta_bits)?;
        off += s_chunk;
    }
    let t0_a = (1u32 << (D - 1)) - 1;
    let t0_b = 1u32 << (D - 1);
    let t0_bits = bitlen(t0_a + t0_b);
    let t0_chunk = 32 * t0_bits;
    let mut t0 = PolyVec::<u32, K>::zero();
    for i in 0..K {
        let src = sk
            .get(off..off + t0_chunk)
            .ok_or(EncodeError::BufferTooSmall)?;
        t0.v[i] = bit_unpack(src, t0_b, t0_bits)?;
        off += t0_chunk;
    }
    Ok((rho, big_k, tr, s1, s2, t0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::ml_dsa_44::{ETA, GAMMA1, GAMMA1_BITS, W1_BITS};
    use crate::params::{ML_DSA_44, ML_DSA_65, ML_DSA_87, from_signed};

    #[test]
    fn bitlen_basic() {
        assert_eq!(bitlen(0), 0);
        assert_eq!(bitlen(1), 1);
        assert_eq!(bitlen(2), 2);
        assert_eq!(bitlen(3), 2);
        assert_eq!(bitlen(255), 8);
        assert_eq!(bitlen(256), 9);
    }

    #[test]
    fn simple_bit_pack_unpack_roundtrip() {
        let mut p = Poly::<u32>::zero();
        let max = (1u32 << W1_BITS) - 1;
        for j in 0..N {
            p.coeffs[j] = (j as u32) & max;
        }
        let mut buf = [0u8; 32 * W1_BITS];
        simple_bit_pack(&p, W1_BITS, &mut buf).unwrap();
        let q = simple_bit_unpack(&buf, W1_BITS).unwrap();
        assert_eq!(q, p);
    }

    #[test]
    fn bit_pack_unpack_eta() {
        let eta = ETA.value();
        let c_bits = bitlen(2 * eta);
        let mut p = Poly::<u32>::zero();
        for j in 0..N {
            let s = (j as i32 % (2 * eta as i32 + 1)) - eta as i32;
            p.coeffs[j] = from_signed(s, Q);
        }
        let mut buf = vec![0u8; 32 * c_bits];
        bit_pack(&p, eta, c_bits, &mut buf).unwrap();
        let q = bit_unpack(&buf, eta, c_bits).unwrap();
        assert_eq!(q, p);
    }

    #[test]
    fn bit_pack_unpack_gamma1() {
        let a = GAMMA1 - 1;
        let b = GAMMA1;
        let c_bits = 1 + GAMMA1_BITS;
        let mut p = Poly::<u32>::zero();
        let span = a + b + 1;
        let mut state: u64 = 0xa5a5a5a5a5a5a5a5;
        for j in 0..N {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let r = (state as u32) % span;
            let s = r as i32 - a as i32;
            p.coeffs[j] = from_signed(s, Q);
        }
        let mut buf = vec![0u8; 32 * c_bits];
        bit_pack(&p, b, c_bits, &mut buf).unwrap();
        let q = bit_unpack(&buf, b, c_bits).unwrap();
        assert_eq!(q, p);
    }

    fn pk_t1_row_roundtrip<const KK: usize, const LL: usize>(p: &Params<KK, LL>) {
        let rho = [7u8; 32];
        let mut t1 = PolyVec::<u32, KK>::zero();
        for i in 0..KK {
            for j in 0..N {
                t1.v[i].coeffs[j] = (i as u32 * 31 + j as u32) & 0x3FF;
            }
        }
        let mut pk = vec![0u8; p.pk_bytes];
        pk_encode(&rho, &t1, &mut pk).unwrap();
        assert_eq!(&pk[..32], &rho);
        for i in 0..KK {
            assert_eq!(pk_t1_row(&pk, i).unwrap(), t1.v[i]);
        }
    }

    fn sk_roundtrip<const KK: usize, const LL: usize>(p: &Params<KK, LL>) {
        let rho = [1u8; 32];
        let big_k = [2u8; 32];
        let tr = [3u8; 64];
        let mut s1 = PolyVec::<u32, LL>::zero();
        let mut s2 = PolyVec::<u32, KK>::zero();
        let mut t0 = PolyVec::<u32, KK>::zero();
        let eta = p.eta.value() as i32;
        for i in 0..LL {
            for j in 0..N {
                let s = ((i + j) as i32 % (2 * eta + 1)) - eta;
                s1.v[i].coeffs[j] = from_signed(s, Q);
            }
        }
        for i in 0..KK {
            for j in 0..N {
                let s = ((i + j + 5) as i32 % (2 * eta + 1)) - eta;
                s2.v[i].coeffs[j] = from_signed(s, Q);
                let t = (((j as i32) % (1 << D)) - (1 << (D - 1))) + 1;
                let t = t.clamp(-(1 << (D - 1)) + 1, 1 << (D - 1));
                t0.v[i].coeffs[j] = from_signed(t, Q);
            }
        }
        let mut sk = vec![0u8; p.sk_bytes];
        sk_encode(p, &rho, &big_k, &tr, &s1, &s2, &t0, &mut sk).unwrap();
        let (rho2, k2, tr2, s1_2, s2_2, t0_2) = sk_decode(p, &sk).unwrap();
        assert_eq!(rho2, rho);
        assert_eq!(k2, big_k);
        assert_eq!(tr2, tr);
        assert_eq!(s1_2, s1);
        assert_eq!(s2_2, s2);
        assert_eq!(t0_2, t0);
    }

    #[test]
    fn pk_roundtrip_44() {
        pk_t1_row_roundtrip(&ML_DSA_44);
    }
    #[test]
    fn pk_roundtrip_65() {
        pk_t1_row_roundtrip(&ML_DSA_65);
    }
    #[test]
    fn pk_roundtrip_87() {
        pk_t1_row_roundtrip(&ML_DSA_87);
    }

    #[test]
    fn sk_roundtrip_44() {
        sk_roundtrip(&ML_DSA_44);
    }
    #[test]
    fn sk_roundtrip_65() {
        sk_roundtrip(&ML_DSA_65);
    }
    #[test]
    fn sk_roundtrip_87() {
        sk_roundtrip(&ML_DSA_87);
    }
}
