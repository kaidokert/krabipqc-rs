#![no_main]
#![no_std]

use cortex_m_rt::entry;
use krabipqc_cortex_m3::test_fixture;
use krabipqc_cortex_m3::test_vector::{KEM768_CT, KEM768_DK, KEM768_SS};

fn decaps_and_check() -> bool {
    match krabipqc::ml_kem_768::decaps_internal(&KEM768_DK, &KEM768_CT) {
        Ok(ss) => ss == KEM768_SS,
        Err(_) => false,
    }
}

#[entry]
fn main() -> ! {
    test_fixture(decaps_and_check, "ml_kem_768_decaps", "modmath");
    loop {}
}

use panic_semihosting as _;
