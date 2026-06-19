use core::sync::atomic::{AtomicU32, Ordering};

use cortex_m::peripheral::{SYST, syst::SystClkSource};
use cortex_m_rt::exception;

static SYSTICK_WRAPS: AtomicU32 = AtomicU32::new(0);

// SCB ICSR (Interrupt Control and State Register) sits at 0xE000_ED04.
// Bit 26 (PENDSTSET) is set while a SysTick exception is pending but
// not yet serviced — read by `total_cycles` to detect the
// "counter wrapped, handler not run yet" window.
const SCB_ICSR_ADDR: u32 = 0xE000_ED04;
const PENDSTSET_MASK: u32 = 1 << 26;

#[exception]
fn SysTick() {
    // fetch_add wraps on overflow and is a single atomic op, so the
    // increment is safe both against debug-mode overflow panics and
    // against re-entry from a future ISR-stacking refactor.
    SYSTICK_WRAPS.fetch_add(1, Ordering::Relaxed);
}

pub struct CycleCounter {
    start_cycles: u64,
}

impl Default for CycleCounter {
    fn default() -> Self {
        Self::new()
    }
}

impl CycleCounter {
    const RELOAD_VALUE: u32 = 0x00ffffff;

    /// Read total cycles since SysTick was started.
    ///
    /// Retries if `SYSTICK_WRAPS` changes between the two reads bracketing
    /// the counter sample. If the wrap counter is stable but the SysTick
    /// exception is pending in the ICSR (counter has wrapped but the
    /// handler hasn't run yet), bump the wrap count by one so we don't
    /// undercount by a full period.
    fn total_cycles() -> u64 {
        let period = Self::RELOAD_VALUE as u64 + 1;
        loop {
            let wraps1 = SYSTICK_WRAPS.load(Ordering::SeqCst);
            let val = SYST::get_current();
            let wraps2 = SYSTICK_WRAPS.load(Ordering::SeqCst);
            if wraps1 == wraps2 {
                // SysTick exception pending but not yet serviced ⇒ the
                // counter has wrapped past zero already; manually
                // promote the wrap count for this reading. Restrict
                // to val > half-reload so a freshly-loaded counter
                // before any wrap doesn't false-positive.
                let icsr = unsafe { core::ptr::read_volatile(SCB_ICSR_ADDR as *const u32) };
                let pending = (icsr & PENDSTSET_MASK) != 0;
                let mut wraps = wraps1 as u64;
                if pending && val > Self::RELOAD_VALUE / 2 {
                    wraps += 1;
                }
                // SysTick counts DOWN from reload, so elapsed = reload - val
                return wraps * period + (Self::RELOAD_VALUE as u64 - val as u64);
            }
        }
    }

    pub fn new() -> Self {
        // `Peripherals::take()` panics on second call. `steal()` doesn't,
        // and the only state we touch is SYST — owned by no one else in
        // this no_std harness. Construction must therefore stay
        // single-threaded by convention; the bench harness only
        // instantiates one CycleCounter per run.
        let mut peripherals = unsafe { cortex_m::Peripherals::steal() };
        let syst = &mut peripherals.SYST;
        syst.set_clock_source(SystClkSource::Core);
        syst.set_reload(Self::RELOAD_VALUE);
        syst.clear_current();
        syst.enable_interrupt();
        syst.enable_counter();

        // Wait for the counter to load from the reload register.
        cortex_m::asm::dsb();
        while SYST::get_current() == 0 {
            cortex_m::asm::nop();
        }

        Self {
            start_cycles: Self::total_cycles(),
        }
    }

    pub fn elapsed(&self) -> u64 {
        Self::total_cycles() - self.start_cycles
    }
}
