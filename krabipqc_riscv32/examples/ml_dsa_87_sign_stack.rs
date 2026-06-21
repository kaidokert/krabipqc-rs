#![no_main]
#![no_std]

use krabipqc::ml_dsa_87;
use krabipqc_riscv32::test_fixture;
use krabipqc_riscv32::test_vector::{MESSAGE, RND, SIG_87, SK_87};
use riscv_rt::entry;

fn sign() -> bool {
    match ml_dsa_87::sign(&SK_87, MESSAGE, &[], &RND) {
        Ok(sig) => sig == SIG_87,
        Err(_) => false,
    }
}

#[entry]
fn main() -> ! {
    test_fixture(sign, "ml_dsa_87_sign", "modmath");
    loop {}
}
