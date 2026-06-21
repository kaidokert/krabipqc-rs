#![no_main]
#![no_std]

use hybrid_array::Array;
use kem::KeyInit;
use krabipqc::{MlDsa65, MlDsaSignature, MlDsaVerifier};
use krabipqc_riscv32::test_fixture;
use krabipqc_riscv32::test_vector::{MESSAGE, PK_65, SIG_65};
use riscv_rt::entry;
use signature::Verifier;

fn verify() -> bool {
    let vk = MlDsaVerifier::<MlDsa65>::new(&Array::from(PK_65));
    let Ok(sig) = MlDsaSignature::<MlDsa65>::try_from(&SIG_65[..]) else {
        return false;
    };
    vk.verify(MESSAGE, &sig).is_ok()
}

#[entry]
fn main() -> ! {
    test_fixture(verify, "ml_dsa_65_verify", "modmath");
    loop {}
}
