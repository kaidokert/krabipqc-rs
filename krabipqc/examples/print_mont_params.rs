//! Print the Montgomery parameters for the ML-DSA and ML-KEM moduli
//! (`Q^-1 mod 2^32`, `R mod Q`, `R^2 mod Q`) so they can be hardcoded
//! as constants in `params.rs` / `mlkem/params.rs`.
//!
//! Run with: `cargo run --release --example print_mont_params`.

use modmath::{compute_n_prime_newton, compute_r_mod_n, compute_r2_mod_n};

fn main() {
    for (label, q) in [
        ("ML-DSA (q = 8 380 417)", 8_380_417_u32),
        ("ML-KEM (q = 3329)", 3329_u32),
    ] {
        let w: usize = 32;
        let n_prime = compute_n_prime_newton::<u32>(q, w);
        let r_mod_q = compute_r_mod_n::<u32>(q, w);
        let r2_mod_q = compute_r2_mod_n::<u32>(r_mod_q, q, w);
        let prod = q.wrapping_mul(n_prime);
        assert_eq!(prod.wrapping_neg(), 1, "{} N*N' check", label);
        println!("// {}", label);
        println!(
            "pub const N_PRIME: u32 = {}; // = 0x{:08X}",
            n_prime, n_prime
        );
        println!("pub const R_MOD_N: u32 = {};", r_mod_q);
        println!("pub const R2_MOD_N: u32 = {};", r2_mod_q);
        println!();
    }
}
