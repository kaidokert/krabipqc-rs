#![no_main]
#![no_std]

use cortex_m_rt::entry;
use krabipqc::{SigningRandomness, ml_dsa_65};
use krabipqc_cortex_m3::test_fixture;
use krabipqc_cortex_m3::test_vector::{MESSAGE, RND, SIG_65, SK_65};

fn sign() -> bool {
    match ml_dsa_65::sign(&SK_65, MESSAGE, &[], &SigningRandomness(RND)) {
        Ok(sig) => sig == SIG_65,
        Err(_) => false,
    }
}

#[entry]
fn main() -> ! {
    test_fixture(sign, "ml_dsa_65_sign", "modmath");
    loop {}
}

use panic_semihosting as _;
