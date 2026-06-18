#![no_main]
#![no_std]

//! ML-KEM-512 decaps stack-and-cycles measurement under QEMU.
//! Decodes the deterministic (dk, ct, ss) test vector, runs
//! decaps, asserts the returned shared secret matches the
//! baked expected value.

use cortex_m_rt::entry;
use krabipqc_cortex_m3::test_fixture;
use krabipqc_cortex_m3::test_vector::{KEM_CT, KEM_DK, KEM_SS};

fn decaps_and_check() -> bool {
    let ss = krabipqc::ml_kem_512::decaps_internal(&KEM_DK, &KEM_CT).unwrap();
    ss == KEM_SS
}

#[entry]
fn main() -> ! {
    test_fixture(decaps_and_check, "ml_kem_512_decaps", "modmath");
    loop {}
}

use panic_semihosting as _;
