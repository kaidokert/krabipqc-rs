#![no_main]
#![no_std]

use cortex_m_rt::entry;
use cortex_m_semihosting::debug;
use hybrid_array::Array;
use kem::KeyInit;
use krabipqc::{MlDsa44, MlDsaSignature, MlDsaVerifier};
use krabipqc_cortex_m3::test_vector::{MESSAGE, PK, SIG};
use signature::Verifier;

#[entry]
fn main() -> ! {
    krabipqc_cortex_m3::test_fixture(
        || {
            #[cfg(feature = "baseline")]
            {
                let mut m_prime = [0u8; 256];
                m_prime[0] = 0x00;
                m_prime[1] = 0x00;
                let len = 2 + MESSAGE.len();
                m_prime[2..len].copy_from_slice(MESSAGE);
                krabipqc_cortex_m3::fake_verify(&PK, &m_prime[..len], &SIG)
            }
            #[cfg(not(feature = "baseline"))]
            {
                let vk = MlDsaVerifier::<MlDsa44>::new(&Array::from(PK));
                let Ok(sig) = MlDsaSignature::<MlDsa44>::try_from(&SIG[..]) else {
                    debug::exit(debug::EXIT_FAILURE);
                    loop {}
                };
                vk.verify(MESSAGE, &sig).is_ok()
            }
        },
        "ml_dsa_44_verify",
        if cfg!(feature = "baseline") {
            "baseline"
        } else {
            "modmath"
        },
    );
    loop {}
}

use panic_semihosting as _;
