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
    // No semihosting between paint_stack and testable: semihosting
    // calls cost tens of thousands of cycles AND use stack space, so
    // any print inside the measured window inflates both the
    // reported cycle count and the high-water mark.
    paint_stack();
    let counter = CycleCounter::new();
    let result = testable();
    let elapsed = counter.elapsed() / 1000; // cycles reported in thousands
    let stack = check_stack_high_water_mark();
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
/// Touches every input so the call cannot be optimized away. Guards
/// against empty slices so a malformed test vector doesn't panic the
/// baseline run.
#[inline(never)]
pub fn fake_verify(pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    let pk_first = pk.first().copied().unwrap_or(0);
    let pk_last = pk.last().copied().unwrap_or(0);
    let sig_first = sig.first().copied().unwrap_or(0);
    let sig_last = sig.last().copied().unwrap_or(0);
    let folded = pk_first ^ pk_last ^ sig_first ^ sig_last ^ (msg.len() as u8);
    black_box(folded);
    true
}

use panic_semihosting as _;
