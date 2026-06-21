#![no_main]
#![no_std]

use cortex_m_rt::entry;
use hybrid_array::Array;
use kem::KeyInit;
use krabipqc::{MlDsa87, MlDsaSignature, MlDsaVerifier};
use krabipqc_cortex_m3::test_fixture;
use krabipqc_cortex_m3::test_vector::{MESSAGE, PK_87, SIG_87};
use signature::Verifier;

fn verify() -> bool {
    let vk = MlDsaVerifier::<MlDsa87>::new(&Array::from(PK_87));
    let Ok(sig) = MlDsaSignature::<MlDsa87>::try_from(&SIG_87[..]) else {
        return false;
    };
    vk.verify(MESSAGE, &sig).is_ok()
}

#[entry]
fn main() -> ! {
    test_fixture(verify, "ml_dsa_87_verify", "modmath");
    loop {}
}

use panic_semihosting as _;
