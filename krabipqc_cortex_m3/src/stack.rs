//! Paint-and-watermark stack profiler.
//!
//! `paint_stack` fills the unused portion of the stack with `0xAA`;
//! `check_stack_high_water_mark` scans up from the floor until it
//! finds the first non-`0xAA` byte and returns the resulting depth.
//!
//! The floor is `__ebss` (provided by `cortex-m-rt`'s `link.x`), i.e.
//! the first address above the initialized + zero-initialized globals.
//! Using `_ram_length` as in earlier revisions would have allowed the
//! paint to overwrite `.data`/`.bss` whenever they exceeded the
//! `SAFE_ZONE_BYTES` margin — a real corruption risk for non-tiny
//! binaries, not a hypothetical one.

unsafe extern "C" {
    static _stack_start: u32;
    // First address above `.data` + `.bss`. cortex-m-rt's link.x
    // defines this regardless of whether the user opts into the heap
    // feature.
    static __ebss: u32;
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
        let bss_end = core::ptr::addr_of!(__ebss) as usize;
        // Leave a SAFE-byte margin above .bss so a near-miss between
        // the linker's RW-data end and the stack's deepest reach
        // doesn't accidentally clobber the last byte of a global.
        let safe_stack_end = bss_end.saturating_add(SAFE);

        // Don't paint over the live frame either: read SP, back off
        // by SAFE bytes, and paint only the region between
        // safe_stack_end and that live-frame margin.
        let mut sp: usize;
        core::arch::asm!("mov {}, sp", out(reg) sp, options(nomem, nostack));
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
        let bss_end = core::ptr::addr_of!(__ebss) as usize;
        let safe_stack_end = bss_end.saturating_add(SAFE);

        if safe_stack_end >= stack_start {
            // Paint floor is at or above stack top — layout is malformed.
            // Return the full range as a conservative estimate so the
            // harness reports maximum possible usage rather than zero.
            return stack_start.saturating_sub(bss_end);
        }

        // read_volatile so the scan isn't constant-folded or moved
        // above the paint/run window by an aggressive optimizer.
        let mut current = safe_stack_end;
        while current < stack_start && core::ptr::read_volatile(current as *const u8) == 0xAA {
            current += 1;
        }

        stack_start.saturating_sub(current)
    }
}
