#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

//! `no_std` math foundation for post-quantum cryptography.
//!
//! This crate is the substrate for the NIST PQC standards published in
//! FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA).
//!
//! Layout:
//!
//! * [`field`] — `Modulus` trait + branchless `add` / `sub` / `neg` +
//!   canonical-domain `mul` / `pow` / `inv` routed through modmath's
//!   `basic::montgomery::wide` primitives. Signed-conversion helpers
//!   are branchless mask selects from day one.
//! * [`hashing`] — SHAKE-128 / SHAKE-256 / SHA3-256 / SHA3-512
//!   wrappers, plus `Shake256Stream` / `Shake128Stream` for the
//!   streaming-squeeze pattern used by FIPS 204 §7.3 rejection
//!   samplers.
//! * [`mont`] — `Mont<M, P>` newtype carrying both `Nct` (variable
//!   time) and `Ct` (constant-time-leaning, via `subtle`) personality
//!   marker types. The `MontMath` trait routes the per-personality
//!   arithmetic; the NTT hot path is generic over `P`.
//! * [`poly`] — `Poly<M>` polynomial in `R_q = Z_q[X] / (X^N + 1)`
//!   with `add` / `sub` / `schoolbook_mul`. NTT-based fast multiplies
//!   land with the scheme code.
//! * [`polyvec`] — `PolyVec<M, LEN>` / `PolyMatrix<M, K, L>` plus the
//!   `NttScheme<P>` trait the schemes implement.
//!
//! Every Z_q operation eventually reduces to a `modmath::basic::
//! montgomery::wide::mul` (one `UMULL` on cortex-m3 via the `wide-mul`
//! feature). The `Mont<M, Ct>` path additionally swaps in the
//! constant-time wide REDC + `subtle::ConditionallySelectable` for
//! the conditional subtraction; output is byte-identical to the Nct
//! path.

pub mod field;
pub mod hashing;
pub mod mont;
pub mod params;
pub mod poly;
pub mod polyvec;
