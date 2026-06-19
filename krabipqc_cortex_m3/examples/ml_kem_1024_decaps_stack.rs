#![no_main]
#![no_std]

use cortex_m_rt::entry;
use krabipqc_cortex_m3::test_fixture;
use krabipqc_cortex_m3::test_vector::{KEM1024_CT, KEM1024_DK, KEM1024_SS};

fn decaps_and_check() -> bool {
    match krabipqc::ml_kem_1024::decaps_internal(&KEM1024_DK, &KEM1024_CT) {
        Ok(ss) => ss == KEM1024_SS,
        Err(_) => false,
    }
}

#[entry]
fn main() -> ! {
    test_fixture(decaps_and_check, "ml_kem_1024_decaps", "modmath");
    loop {}
}

use panic_semihosting as _;
