#![no_main]
#![no_std]

use hybrid_array::Array;
use kem::{TryDecapsulate, TryKeyInit};
use krabipqc::{Dk, MlKem768};
use krabipqc_riscv32::test_fixture;
use krabipqc_riscv32::test_vector::{KEM768_CT, KEM768_DK, KEM768_SS};
use riscv_rt::entry;

fn decaps_and_check() -> bool {
    let Ok(dk) = Dk::<MlKem768>::new(&Array::from(KEM768_DK)) else {
        return false;
    };
    match dk.try_decapsulate(&Array::from(KEM768_CT)) {
        Ok(ss) => *ss == KEM768_SS,
        Err(_) => false,
    }
}

#[entry]
fn main() -> ! {
    test_fixture(decaps_and_check, "ml_kem_768_decaps", "modmath");
    loop {}
}
