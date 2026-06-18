#![no_std]

//! Cortex-M3 integration harness for the `krabipqc` crate.
//!
//! Provides:
//! * A deterministic ML-DSA-44 test vector (in [`test_vector`]).
//! * A `test_fixture` that paints the stack, runs the closure, prints
//!   `<algo> ACCEPT|REJECT` and a `METRIC stack:N cycles:K target:... algo:... backend:...`
//!   line over semihosting, then exits QEMU.
//! * A `fake_verify` stub baseline (returns true after touching the inputs
//!   so the call is not optimized away) used to measure the harness overhead.

use core::hint::black_box;
use cortex_m_semihosting::{debug, hprintln};

pub mod cyclecount;
pub mod stack;
pub mod test_vector;

use cyclecount::CycleCounter;
use stack::{check_stack_high_water_mark, paint_stack};

pub fn target_arch_name() -> &'static str {
    "thumbv7m"
}

pub fn test_fixture(testable: fn() -> bool, algo: &str, backend: &str) {
    hprintln!("setup");
    paint_stack();
    hprintln!("painted");
    let counter = CycleCounter::new();
    hprintln!("counter_started");
    let result = testable();
    // Cycle counts are reported in thousands.
    let elapsed = counter.elapsed() / 1000;
    hprintln!("ran");
    let stack = check_stack_high_water_mark();
    hprintln!("stack_checked");
    if result {
        hprintln!("{} ACCEPT", algo);
    } else {
        hprintln!("{} REJECT", algo);
    }
    hprintln!(
        "METRIC stack:{} cycles:{} target:{} algo:{} backend:{}",
        stack,
        elapsed,
        target_arch_name(),
        algo,
        backend
    );
    if result {
        debug::exit(debug::EXIT_SUCCESS);
    } else {
        debug::exit(debug::EXIT_FAILURE);
    }
}

/// Stub "verify" used by the baseline build to measure harness overhead.
/// Touches every input so the call cannot be optimized away.
#[inline(never)]
pub fn fake_verify(pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    let folded = pk[0] ^ pk[pk.len() - 1] ^ sig[0] ^ sig[sig.len() - 1] ^ (msg.len() as u8);
    black_box(folded);
    true
}

use panic_semihosting as _;
