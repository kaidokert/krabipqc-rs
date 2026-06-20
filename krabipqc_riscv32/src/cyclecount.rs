use core::arch::asm;

// RV32 split-read of the 64-bit mcycle counter: read mcycleh–mcycle–mcycleh
// and retry if the high word changed, guarding against a carry between reads.
fn read_mcycle() -> u64 {
    loop {
        let hi1: u32;
        let lo: u32;
        let hi2: u32;
        unsafe {
            asm!(
                "csrr {hi1}, mcycleh",
                "csrr {lo},  mcycle",
                "csrr {hi2}, mcycleh",
                hi1 = out(reg) hi1,
                lo  = out(reg) lo,
                hi2 = out(reg) hi2,
                options(nostack, nomem),
            );
        }
        if hi1 == hi2 {
            return ((hi1 as u64) << 32) | (lo as u64);
        }
    }
}

pub struct CycleCounter {
    start: u64,
}

impl CycleCounter {
    pub fn new() -> Self {
        Self {
            start: read_mcycle(),
        }
    }

    pub fn elapsed(&self) -> u64 {
        read_mcycle() - self.start
    }
}
