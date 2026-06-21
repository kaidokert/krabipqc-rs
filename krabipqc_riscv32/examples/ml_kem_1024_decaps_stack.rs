#![no_main]
#![no_std]

use hybrid_array::Array;
use kem::{TryDecapsulate, TryKeyInit};
use krabipqc::{Dk, MlKem1024};
use krabipqc_riscv32::test_fixture;
use krabipqc_riscv32::test_vector::{KEM1024_CT, KEM1024_DK, KEM1024_SS};
use riscv_rt::entry;

fn decaps_and_check() -> bool {
    let Ok(dk) = Dk::<MlKem1024>::new(&Array::from(KEM1024_DK)) else {
        return false;
    };
    match dk.try_decapsulate(&Array::from(KEM1024_CT)) {
        Ok(ss) => *ss == KEM1024_SS,
        Err(_) => false,
    }
}

#[entry]
fn main() -> ! {
    test_fixture(decaps_and_check, "ml_kem_1024_decaps", "modmath");
    loop {}
}
