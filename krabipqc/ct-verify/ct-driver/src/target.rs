//! Per-target specifications: triple, toolchain pin, and ISA mnemonic tables.
//!
//! `ladder_allowed_branches` is the ceiling on conditional branches inside each
//! `ct_fix__*` symbol body. The current values are intentionally wide — they
//! must be tightened after the first successful CI run shows the actual counts
//! per target. The ctgrind taint gate (not this file) is the real CT proof;
//! this check is a structural regression gate.

use krabi_caliper::host::ct_asm::LadderTarget as TargetSpec;
use krabi_caliper::host::isa as mnemonics;

/// All targets we know how to verify, in priority order.
pub const TARGETS: &[TargetSpec] = &[
    // Priority 1: Cortex-M7 (thumbv7em — FPU core, most common embedded target)
    TargetSpec {
        triple: "thumbv7em-none-eabi",
        priority: 1,
        toolchain: "1.87.0",
        forbidden: mnemonics::THUMB_FORBIDDEN,
        allowed_cmov: mnemonics::THUMB_ALLOWED,
        ladder_allowed_branches: 60,
        extra_cargo_args: &[],
    },
    // Priority 1: Cortex-M3/M4 (thumbv7m — no FPU)
    TargetSpec {
        triple: "thumbv7m-none-eabi",
        priority: 1,
        toolchain: "1.87.0",
        forbidden: mnemonics::THUMB_FORBIDDEN,
        allowed_cmov: mnemonics::THUMB_ALLOWED,
        ladder_allowed_branches: 60,
        extra_cargo_args: &[],
    },
    // Priority 2: Cortex-M0/M0+ (thumbv6m)
    TargetSpec {
        triple: "thumbv6m-none-eabi",
        priority: 2,
        toolchain: "1.87.0",
        forbidden: mnemonics::THUMB_FORBIDDEN,
        allowed_cmov: mnemonics::THUMB_ALLOWED,
        ladder_allowed_branches: 60,
        extra_cargo_args: &[],
    },
    // Priority 3: 32-bit RISC-V without atomics (I+M+C: compressed, no 'a')
    TargetSpec {
        triple: "riscv32imc-unknown-none-elf",
        priority: 3,
        toolchain: "1.87.0",
        forbidden: mnemonics::RISCV_FORBIDDEN,
        allowed_cmov: &[],
        ladder_allowed_branches: 60,
        extra_cargo_args: &[],
    },
    // Priority 3: 32-bit RISC-V with atomics (I+M+A+C)
    TargetSpec {
        triple: "riscv32imac-unknown-none-elf",
        priority: 3,
        toolchain: "1.87.0",
        forbidden: mnemonics::RISCV_FORBIDDEN,
        allowed_cmov: &[],
        ladder_allowed_branches: 60,
        extra_cargo_args: &[],
    },
    // Priority 4: 8-bit AVR (nightly-only, needs build-std + target-cpu).
    TargetSpec {
        triple: "avr-none",
        priority: 4,
        toolchain: "nightly",
        forbidden: mnemonics::AVR_FORBIDDEN,
        allowed_cmov: &[],
        ladder_allowed_branches: 60,
        extra_cargo_args: &["-Z", "build-std=core"],
    },
    // Priority 5: aarch64 Linux
    TargetSpec {
        triple: "aarch64-unknown-linux-gnu",
        priority: 5,
        toolchain: "1.87.0",
        forbidden: mnemonics::AARCH64_FORBIDDEN,
        allowed_cmov: mnemonics::AARCH64_ALLOWED,
        ladder_allowed_branches: 60,
        extra_cargo_args: &[],
    },
    // Priority 6: x86_64 Linux
    TargetSpec {
        triple: "x86_64-unknown-linux-gnu",
        priority: 6,
        toolchain: "1.87.0",
        forbidden: mnemonics::X86_64_FORBIDDEN,
        allowed_cmov: mnemonics::X86_64_ALLOWED,
        ladder_allowed_branches: 60,
        extra_cargo_args: &[],
    },
    // Host fallback: aarch64-apple-darwin.
    // CI matrix doesn't run this; lets `cargo run -p ct-driver` work on macOS.
    TargetSpec {
        triple: "aarch64-apple-darwin",
        priority: 99,
        toolchain: "stable",
        forbidden: mnemonics::AARCH64_FORBIDDEN,
        allowed_cmov: mnemonics::AARCH64_ALLOWED,
        ladder_allowed_branches: 60,
        extra_cargo_args: &[],
    },
];
