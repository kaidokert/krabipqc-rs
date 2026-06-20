#![no_main]
#![no_std]

use krabipqc_riscv32::test_fixture;
use krabipqc_riscv32::test_vector::{MESSAGE, RND, SK_87};
use riscv_rt::entry;

fn sign() -> bool {
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
    krabipqc::ml_dsa_87::sign_internal(&SK_87, slice, &RND).is_ok()
}

#[entry]
fn main() -> ! {
    test_fixture(sign, "ml_dsa_87_sign", "modmath");
    loop {}
}
