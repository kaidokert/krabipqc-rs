//! Paint-and-watermark stack profiler for RISC-V.
//!
//! Mirrors `krabipqc_cortex_m3/src/stack.rs`; the only differences are
//! the inline-asm instruction (`mv` vs ARM `mov`) and the BSS-end symbol
//! name (`_ebss` from riscv-rt vs `__ebss` from cortex-m-rt).
//!
//! Using `_ebss` as the paint floor (not `_ram_length`) keeps the paint
//! region above the text + data sections when all sections share one RAM
//! region on the QEMU virt machine.

unsafe extern "C" {
    // Top of the stack region — riscv-rt's link.x:
    //   _stack_start = ORIGIN(REGION_STACK) + LENGTH(REGION_STACK)
    static _stack_start: u32;
    // First address above .bss — safe floor for the paint region.
    static _ebss: u32;
}

const SAFE_ZONE_BYTES: usize = 256;

#[inline(always)]
pub fn paint_stack() {
    paint_stack_inner::<SAFE_ZONE_BYTES>();
}

#[inline(always)]
pub fn check_stack_high_water_mark() -> usize {
    check_stack_high_water_mark_inner::<SAFE_ZONE_BYTES>()
}

pub(crate) fn paint_stack_inner<const SAFE: usize>() {
    unsafe {
        let bss_end = core::ptr::addr_of!(_ebss) as usize;
        let safe_stack_end = bss_end.saturating_add(SAFE);

        let mut sp: usize;
        core::arch::asm!("mv {}, sp", out(reg) sp, options(nomem, nostack));
        let live_limit = sp.saturating_sub(SAFE);

        let paint_end = if live_limit < safe_stack_end {
            safe_stack_end
        } else {
            live_limit
        };

        let bytes_to_write = paint_end.saturating_sub(safe_stack_end);
        if bytes_to_write > 0 {
            core::ptr::write_bytes(safe_stack_end as *mut u8, 0xAA, bytes_to_write);
        }
    }
}

pub(crate) fn check_stack_high_water_mark_inner<const SAFE: usize>() -> usize {
    unsafe {
        let stack_start = core::ptr::addr_of!(_stack_start) as usize;
        let bss_end = core::ptr::addr_of!(_ebss) as usize;
        let safe_stack_end = bss_end.saturating_add(SAFE);

        let mut current = safe_stack_end.min(stack_start);
        while current < stack_start && core::ptr::read_volatile(current as *const u8) == 0xAA {
            current += 1;
        }

        stack_start.saturating_sub(current)
    }
}
