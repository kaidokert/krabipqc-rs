#![no_main]
#![no_std]

use krabipqc::ml_dsa_44;
use krabipqc_riscv32::test_fixture;
use krabipqc_riscv32::test_vector::{MESSAGE, RND, SIG, SK};
use riscv_rt::entry;

fn sign() -> bool {
    match ml_dsa_44::sign(&SK, MESSAGE, &[], &RND) {
        Ok(sig) => sig == SIG,
        Err(_) => false,
    }
}

#[entry]
fn main() -> ! {
    test_fixture(sign, "ml_dsa_44_sign", "modmath");
    loop {}
}
