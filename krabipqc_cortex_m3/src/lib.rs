#![no_std]

//! Cortex-M3 integration harness for the `krabipqc` crate.
//!
//! Provides:
//! * A deterministic ML-DSA-44 test vector (in [`test_vector`]).
//! * A `test_fixture` that measures one operation with `krabi-caliper`, emits
//!   canonical evidence over semihosting, then exits QEMU.
//! * A `fake_verify` stub baseline (returns true after touching the inputs
//!   so the call is not optimized away) used to measure the harness overhead.

use core::hint::black_box;
use cortex_m_semihosting::{debug, hprintln};
use krabi_caliper::cortex_m::{FootprintConfig, run_footprint};
use krabi_caliper::report::Field;

pub mod test_vector;

krabi_caliper::cortex_m_systick_overflow_handler!();

pub fn target_arch_name() -> &'static str {
    "thumbv7m"
}

pub fn test_fixture(testable: fn() -> bool, algo: &str, backend: &str) {
    let fields = [
        Field::token("architecture", target_arch_name()),
        Field::token("backend", backend),
    ];
    let result = unsafe {
        run_footprint::<256, _>(
            || {
                krabi_caliper::protocol::semihosting::init()
                    .expect("failed to open semihosting stdout")
            },
            FootprintConfig::new(algo, &fields),
            testable,
        )
    };
    match result {
        Ok(true) => debug::exit(debug::EXIT_SUCCESS),
        Ok(false) => {
            hprintln!("MEASUREMENT FAILED");
            debug::exit(debug::EXIT_FAILURE);
        }
        Err(krabi_caliper::FootprintError::CounterUnavailable) => {
            hprintln!("MEASUREMENT ERROR: counter unavailable");
            debug::exit(debug::EXIT_FAILURE);
        }
        Err(krabi_caliper::FootprintError::Stack(_)) => {
            hprintln!("MEASUREMENT ERROR: invalid stack bounds");
            debug::exit(debug::EXIT_FAILURE);
        }
        Err(krabi_caliper::FootprintError::Reporter(_)) => {
            hprintln!("MEASUREMENT ERROR: reporter failed");
            debug::exit(debug::EXIT_FAILURE);
        }
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
