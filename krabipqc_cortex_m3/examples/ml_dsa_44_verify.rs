#![no_main]
#![no_std]

use cortex_m_rt::entry;
use cortex_m_semihosting::{debug, hprintln};
use hybrid_array::Array;
use kem::KeyInit;
use krabipqc::{MlDsa44, MlDsaSignature, MlDsaVerifier};
use krabipqc_cortex_m3::cyclecount::CycleCounter;
use krabipqc_cortex_m3::test_vector::{MESSAGE, PK, SIG};
use signature::Verifier;

#[entry]
fn main() -> ! {
    let counter = CycleCounter::new();
    let ok = {
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
    };
    let cycles_k = counter.elapsed() / 1000;

    if ok {
        hprintln!("ml_dsa_44_verify ACCEPT");
    } else {
        hprintln!("ml_dsa_44_verify REJECT");
    }
    hprintln!(
        "METRIC cycles:{} target:thumbv7m algo:ml_dsa_44_verify backend:{}",
        cycles_k,
        if cfg!(feature = "baseline") {
            "baseline"
        } else {
            "modmath"
        }
    );
    debug::exit(if ok {
        debug::EXIT_SUCCESS
    } else {
        debug::EXIT_FAILURE
    });
    loop {}
}

use panic_semihosting as _;
