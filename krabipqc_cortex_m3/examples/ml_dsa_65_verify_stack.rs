#![no_main]
#![no_std]

use cortex_m_rt::entry;
use hybrid_array::Array;
use kem::KeyInit;
use krabipqc::{MlDsa65, MlDsaSignature, MlDsaVerifier};
use krabipqc_cortex_m3::test_fixture;
use krabipqc_cortex_m3::test_vector::{MESSAGE, PK_65, SIG_65};
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

use panic_semihosting as _;
