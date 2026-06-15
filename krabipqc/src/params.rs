//! Shared parameters across the FIPS 203 / FIPS 204 family.
//!
//! Both ML-DSA and ML-KEM operate on polynomials of dimension `N`.

/// Polynomial dimension. Both FIPS 204 ML-DSA and FIPS 203 ML-KEM
/// fix this at 256.
pub const N: usize = 256;
