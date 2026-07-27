#![no_std]

//! RISC-V (QEMU virt / riscv32imac) integration harness for `krabipqc`.
//!
//! Provides the same `test_fixture` surface as `krabipqc_cortex_m3`, emitting
//! canonical `krabi-caliper` evidence over the NS16550A UART. The
//! `qemu_wrapper.py` script terminates QEMU after the outcome record.

use core::fmt::Write;
use core::hint::black_box;
use krabi_caliper::report::{Field, TextReporter};
use krabi_caliper::risc_v::{FootprintConfig, run_footprint};

pub mod test_vector;
pub mod uart;

use uart::{UartWriter, uart_init};

pub fn target_arch_name() -> &'static str {
    "riscv32"
}

pub fn test_fixture(testable: fn() -> bool, algo: &str, backend: &str) {
    uart_init();
    let fields = [
        Field::token("architecture", target_arch_name()),
        Field::token("backend", backend),
    ];
    let result = unsafe {
        run_footprint::<256, _>(
            || TextReporter::new(UartWriter),
            FootprintConfig::new(algo, &fields),
            testable,
        )
    };
    if let Err(error) = result {
        let mut writer = UartWriter;
        let message = match error {
            krabi_caliper::FootprintError::CounterUnavailable => {
                "MEASUREMENT ERROR: counter unavailable"
            }
            krabi_caliper::FootprintError::Stack(_) => "MEASUREMENT ERROR: invalid stack bounds",
            krabi_caliper::FootprintError::Reporter(_) => "MEASUREMENT ERROR: reporter failed",
        };
        let _ = writeln!(writer, "{message}");
    }

    loop {
        core::hint::spin_loop();
    }
}

/// Stub "verify" for the baseline feature — touches every input without
/// performing any cryptographic work, so the measured delta reflects
/// only the operation under test.
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

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    uart_init();
    let mut w = UartWriter;
    let _ = writeln!(w, "PANIC: {}", info);
    loop {
        core::hint::spin_loop();
    }
}
