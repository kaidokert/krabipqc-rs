#![no_main]
#![no_std]

//! ML-DSA-44 sign stack-and-cycles measurement under QEMU.
//! Measures sign only — verify lives outside the measured window
//! (would otherwise inflate the sign metric by the verify cost).

use cortex_m_rt::entry;
use krabipqc::{SigningRandomness, ml_dsa_44};
use krabipqc_cortex_m3::test_fixture;
use krabipqc_cortex_m3::test_vector::{MESSAGE, RND, SIG, SK};

fn sign() -> bool {
    match ml_dsa_44::sign(&SK, MESSAGE, &[], &SigningRandomness(RND)) {
        Ok(sig) => sig == SIG,
        Err(_) => false,
    }
}

#[entry]
fn main() -> ! {
    test_fixture(sign, "ml_dsa_44_sign", "modmath");
    loop {}
}

use panic_semihosting as _;
