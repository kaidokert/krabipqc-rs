#![no_main]
#![no_std]

//! One-shot stack-measuring variant of `ml_dsa_44_verify` -- runs through
//! the harness's `test_fixture` which paints the stack and reports the
//! high-water mark. Temporary; underscore-prefixed name flags it as a
//! README-snapshot helper, not a regular example.

use cortex_m_rt::entry;
use krabipqc_cortex_m3::test_fixture;
use krabipqc_cortex_m3::test_vector::{MESSAGE, PK, SIG};

fn verify() -> bool {
    let mut m_prime = [0u8; 256];
    m_prime[0] = 0x00;
    m_prime[1] = 0x00;
    let len = 2 + MESSAGE.len();
    m_prime[2..len].copy_from_slice(MESSAGE);
    krabipqc::ml_dsa_44::verify_internal(&PK, &m_prime[..len], &SIG)
}

#[entry]
fn main() -> ! {
    test_fixture(verify, "ml_dsa_44_verify_with_stack", "modmath");
    loop {}
}

use panic_semihosting as _;
