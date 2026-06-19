#![no_main]
#![no_std]

use cortex_m_rt::entry;
use krabipqc_cortex_m3::test_fixture;
use krabipqc_cortex_m3::test_vector::{MESSAGE, PK_65, SIG_65};

fn verify() -> bool {
    let mut m_prime = [0u8; 256];
    m_prime[0] = 0x00;
    m_prime[1] = 0x00;
    let len = 2 + MESSAGE.len();
    m_prime[2..len].copy_from_slice(MESSAGE);
    krabipqc::ml_dsa_65::verify_internal(&PK_65, &m_prime[..len], &SIG_65)
}

#[entry]
fn main() -> ! {
    test_fixture(verify, "ml_dsa_65_verify", "modmath");
    loop {}
}

use panic_semihosting as _;
