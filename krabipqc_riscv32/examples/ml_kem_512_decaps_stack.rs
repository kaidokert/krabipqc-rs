#![no_main]
#![no_std]

use hybrid_array::Array;
use kem::{TryDecapsulate, TryKeyInit};
use krabipqc::{Dk, MlKem512};
use krabipqc_riscv32::test_fixture;
use krabipqc_riscv32::test_vector::{KEM_CT, KEM_DK, KEM_SS};
use riscv_rt::entry;

fn decaps_and_check() -> bool {
    let Ok(dk) = Dk::<MlKem512>::new(&Array::from(KEM_DK)) else {
        return false;
    };
    match dk.try_decapsulate(&Array::from(KEM_CT)) {
        Ok(ss) => *ss == KEM_SS,
        Err(_) => false,
    }
}

#[entry]
fn main() -> ! {
    test_fixture(decaps_and_check, "ml_kem_512_decaps", "modmath");
    loop {}
}
