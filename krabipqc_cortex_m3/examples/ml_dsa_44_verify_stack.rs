#![no_main]
#![no_std]

use cortex_m_rt::entry;
use hybrid_array::Array;
use kem::KeyInit;
use krabipqc::{MlDsa44, MlDsaSignature, MlDsaVerifier};
use krabipqc_cortex_m3::test_fixture;
use krabipqc_cortex_m3::test_vector::{MESSAGE, PK, SIG};
use signature::Verifier;

fn verify() -> bool {
    let vk = MlDsaVerifier::<MlDsa44>::new(&Array::from(PK));
    let Ok(sig) = MlDsaSignature::<MlDsa44>::try_from(&SIG[..]) else {
        return false;
    };
    vk.verify(MESSAGE, &sig).is_ok()
}

#[entry]
fn main() -> ! {
    test_fixture(verify, "ml_dsa_44_verify_with_stack", "modmath");
    loop {}
}

use panic_semihosting as _;
