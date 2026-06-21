#![no_main]
#![no_std]

//! ML-KEM-512 decaps stack-and-cycles measurement under QEMU.
//! Loads the deterministic (dk, ct, ss) test vector via the public
//! `Dk<MlKem512>` API — EK modulus check included — and asserts
//! the recovered shared secret matches the baked expected value.

use cortex_m_rt::entry;
use hybrid_array::Array;
use kem::{TryDecapsulate, TryKeyInit};
use krabipqc::{Dk, MlKem512};
use krabipqc_cortex_m3::test_fixture;
use krabipqc_cortex_m3::test_vector::{KEM_CT, KEM_DK, KEM_SS};

fn decaps_and_check() -> bool {
    let Ok(dk) = Dk::<MlKem512>::new(&Array::from(KEM_DK)) else {
        return false;
    };
    match dk.try_decapsulate(&Array::from(KEM_CT)) {
        Ok(ss) => *ss == KEM_SS,
        Err(_) => false,
    }
}

#[entry]
fn main() -> ! {
    test_fixture(decaps_and_check, "ml_kem_512_decaps", "modmath");
    loop {}
}

use panic_semihosting as _;
