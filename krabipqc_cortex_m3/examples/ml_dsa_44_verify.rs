#![no_main]
#![no_std]

//! Real ML-DSA-44 verify on cortex-m3 under QEMU.
//! Reports ACCEPT/REJECT plus a single METRIC line over semihosting.
//!
//! We deliberately skip the optional `paint_stack` / high-water check
//! used by the harness in `krabipqc_cortex_m3::test_fixture` because they
//! add significant QEMU wall-clock time without affecting verify
//! correctness. See `ml_dsa_44_verify_traced` for the instrumented
//! per-phase variant.

use cortex_m_rt::entry;
use cortex_m_semihosting::{debug, hprintln};
use krabipqc_cortex_m3::cyclecount::CycleCounter;
use krabipqc_cortex_m3::test_vector::{MESSAGE, PK, SIG};

#[entry]
fn main() -> ! {
    // FIPS 204 pure ML-DSA with ctx = "": M' = 0x00 || 0x00 || MESSAGE.
    let mut m_prime = [0u8; 256];
    m_prime[0] = 0x00;
    m_prime[1] = 0x00;
    let len = 2 + MESSAGE.len();
    m_prime[2..len].copy_from_slice(MESSAGE);

    let counter = CycleCounter::new();
    let ok = {
        #[cfg(feature = "baseline")]
        {
            krabipqc_cortex_m3::fake_verify(&PK, &m_prime[..len], &SIG)
        }
        #[cfg(not(feature = "baseline"))]
        {
            krabipqc::ml_dsa_44::verify_internal(&PK, &m_prime[..len], &SIG)
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
