#![no_main]
#![no_std]

//! ML-DSA-44 sign stack-and-cycles measurement under QEMU.
//! Runs through `test_fixture` which paints SRAM, runs sign, and
//! reports the high-water mark.

use cortex_m_rt::entry;
use krabipqc_cortex_m3::test_fixture;
use krabipqc_cortex_m3::test_vector::{MESSAGE, PK, RND, SK};

fn sign_and_verify() -> bool {
    let mut m_prime = [0u8; 256];
    m_prime[0] = 0x00;
    m_prime[1] = 0x00;
    let len = 2 + MESSAGE.len();
    m_prime[2..len].copy_from_slice(MESSAGE);
    let sig = krabipqc::ml_dsa_44::sign_internal(&SK, &m_prime[..len], &RND).unwrap();
    krabipqc::ml_dsa_44::verify_internal(&PK, &m_prime[..len], &sig)
}

#[entry]
fn main() -> ! {
    test_fixture(sign_and_verify, "ml_dsa_44_sign_with_stack", "modmath");
    loop {}
}

use panic_semihosting as _;
