#![no_std]

//! RISC-V (QEMU virt / riscv32imac) integration harness for `krabipqc`.
//!
//! Provides the same `test_fixture` surface as `krabipqc_cortex_m3` but
//! outputs over the NS16550A UART (0x10000000) instead of semihosting,
//! and loops forever after emitting the METRIC line — the `qemu_wrapper.py`
//! script kills QEMU on that line since the virt machine has no exit
//! mechanism.

use core::fmt::Write;
use core::hint::black_box;

pub mod cyclecount;
pub mod stack;
pub mod test_vector;
pub mod uart;

use cyclecount::CycleCounter;
use stack::{check_stack_high_water_mark, paint_stack};
use uart::{UartWriter, uart_init};

pub fn target_arch_name() -> &'static str {
    "riscv32"
}

pub fn test_fixture(testable: fn() -> bool, algo: &str, backend: &str) {
    uart_init();
    // No UART calls between paint_stack and testable: I/O touches
    // the stack and inflates both the high-water mark and cycle count.
    paint_stack();
    let counter = CycleCounter::new();
    let result = testable();
    let elapsed = counter.elapsed() / 1000; // report in thousands
    let stack = check_stack_high_water_mark();

    let mut w = UartWriter;
    if result {
        let _ = writeln!(w, "{} ACCEPT", algo);
    } else {
        let _ = writeln!(w, "{} REJECT", algo);
    }
    let _ = writeln!(
        w,
        "METRIC stack:{} cycles:{} target:{} algo:{} backend:{}",
        stack,
        elapsed,
        target_arch_name(),
        algo,
        backend
    );

    // virt has no semihosting exit — loop and let qemu_wrapper.py kill QEMU.
    loop {
        unsafe { core::arch::asm!("wfi") }
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
        unsafe { core::arch::asm!("wfi") }
    }
}
