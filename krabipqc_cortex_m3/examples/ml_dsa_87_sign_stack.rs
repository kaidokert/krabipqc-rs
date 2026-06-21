#![no_main]
#![no_std]

use cortex_m_rt::entry;
use krabipqc::ml_dsa_87;
use krabipqc_cortex_m3::test_fixture;
use krabipqc_cortex_m3::test_vector::{MESSAGE, RND, SIG_87, SK_87};

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

use panic_semihosting as _;
