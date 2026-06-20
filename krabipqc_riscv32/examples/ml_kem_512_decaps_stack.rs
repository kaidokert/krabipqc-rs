#![no_main]
#![no_std]

use krabipqc_riscv32::test_fixture;
use krabipqc_riscv32::test_vector::{KEM_CT, KEM_DK, KEM_SS};
use riscv_rt::entry;

fn decaps_and_check() -> bool {
    match krabipqc::ml_kem_512::decaps_internal(&KEM_DK, &KEM_CT) {
        Ok(ss) => ss == KEM_SS,
        Err(_) => false,
    }
}

#[entry]
fn main() -> ! {
    test_fixture(decaps_and_check, "ml_kem_512_decaps", "modmath");
    loop {}
}
