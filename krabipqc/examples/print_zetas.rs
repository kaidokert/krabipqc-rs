//! Print the NTT zetas tables (Montgomery form) for both schemes so
//! they can be hardcoded as `const` arrays in `ntt.rs` / `mlkem/ntt.rs`.
//!
//! The hot-path NTT bodies don't need the canonical zetas at runtime,
//! so the crate's `compute_zetas` / `compute_gammas` helpers live
//! behind `#[cfg(test)]`. This example reproduces them via inline
//! `modmath::basic::pre_reduced::exp` + bitreversal so it can stand
//! alone against the public crate API.
//!
//! Run with: `cargo run --release --example print_zetas`.

use modmath::basic::pre_reduced as pr;

// FIPS 204 §8.3 (ML-DSA) and FIPS 203 §4.3 (ML-KEM).
const DSA_Q: u32 = 8_380_417;
const DSA_ZETA: u32 = 1753; // primitive 512-th root of unity mod q
const DSA_N: usize = 256;
const DSA_N_INV: u32 = 8_347_681; // 256^-1 mod q, applied at inv-NTT tail.

const KEM_Q: u32 = 3329;
const KEM_ZETA: u32 = 17; // primitive 256-th root of unity mod q
const KEM_N_INV_128: u32 = 3303; // 128^-1 mod q, applied at inv-NTT tail.

/// `to_mont(x) = x · R mod q`, R = 2^32.
fn to_mont(x: u32, q: u32) -> u32 {
    (((x as u64) << 32) % q as u64) as u32
}

const fn bitrev8(mut i: u32) -> u32 {
    let mut r = 0u32;
    let mut bits = 0;
    while bits < 8 {
        r = (r << 1) | (i & 1);
        i >>= 1;
        bits += 1;
    }
    r
}

const fn bitrev7(mut i: u32) -> u32 {
    let mut r = 0u32;
    let mut bits = 0;
    while bits < 7 {
        r = (r << 1) | (i & 1);
        i >>= 1;
        bits += 1;
    }
    r
}

fn print_arr(name: &str, vals: &[u32], width: usize) {
    println!("pub const {}: [u32; {}] = [", name, vals.len());
    for chunk in vals.chunks(width) {
        let s: Vec<_> = chunk.iter().map(|v| format!("{:7}", v)).collect();
        println!("    {},", s.join(", "));
    }
    println!("];");
}

fn main() {
    // ML-DSA: ZETAS[i] = ZETA^BitRev_8(i) mod Q, i in 0..256.
    println!("// ML-DSA ZETAS in Montgomery form (R = 2^32):");
    let dsa_zetas_mont: [u32; DSA_N] = core::array::from_fn(|i| {
        to_mont(pr::exp::<u32>(DSA_ZETA, bitrev8(i as u32), DSA_Q), DSA_Q)
    });
    print_arr("ZETAS_MONT", &dsa_zetas_mont, 8);
    println!("pub const N_INV_MONT: u32 = {};", to_mont(DSA_N_INV, DSA_Q));

    println!();
    // ML-KEM ZETAS[i] = ZETA^BitRev_7(i) mod Q, i in 0..128.
    println!("// ML-KEM ZETAS in Montgomery form (R = 2^32):");
    let kem_zetas_mont: [u32; 128] = core::array::from_fn(|i| {
        to_mont(pr::exp::<u32>(KEM_ZETA, bitrev7(i as u32), KEM_Q), KEM_Q)
    });
    print_arr("ZETAS_MONT", &kem_zetas_mont, 8);

    println!();
    // ML-KEM GAMMAS[i] = ZETA^(2·BitRev_7(i) + 1) mod Q, i in 0..128.
    println!("// ML-KEM GAMMAS in Montgomery form:");
    let kem_gammas_mont: [u32; 128] = core::array::from_fn(|i| {
        to_mont(
            pr::exp::<u32>(KEM_ZETA, 2 * bitrev7(i as u32) + 1, KEM_Q),
            KEM_Q,
        )
    });
    print_arr("GAMMAS_MONT", &kem_gammas_mont, 8);
    println!(
        "pub const N_INV_128_MONT: u32 = {}; // 128^-1 * R mod 3329",
        to_mont(KEM_N_INV_128, KEM_Q)
    );
}
