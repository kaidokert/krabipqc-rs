#![no_main]
#![no_std]

use krabipqc_riscv32::test_fixture;
use krabipqc_riscv32::test_vector::{MESSAGE, PK_87, SIG_87};
use riscv_rt::entry;

fn verify() -> bool {
    let mut m_prime = [0u8; 256];
    m_prime[0] = 0x00;
    m_prime[1] = 0x00;
    let len = 2 + MESSAGE.len();
    let Some(slot) = m_prime.get_mut(2..len) else {
        return false;
    };
    slot.copy_from_slice(MESSAGE);
    let Some(slice) = m_prime.get(..len) else {
        return false;
    };
    krabipqc::ml_dsa_87::verify_internal(&PK_87, slice, &SIG_87)
}

#[entry]
fn main() -> ! {
    test_fixture(verify, "ml_dsa_87_verify", "modmath");
    loop {}
}
