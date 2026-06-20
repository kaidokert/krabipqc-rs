use core::fmt;

// QEMU virt machine: NS16550A-compatible UART at 0x10000000.
// With -nographic, QEMU routes this UART's output to the host terminal.
const UART0_BASE: usize = 0x10000000;
const THR: usize = 0; // transmit holding register
const LSR: usize = 5; // line status register
const LCR: usize = 3; // line control register
const LSR_THRE: u8 = 0x20; // bit 5: transmit holding register empty

pub fn uart_init() {
    unsafe {
        let base = UART0_BASE as *mut u8;
        // 8N1, no DLAB — baud rate is irrelevant in QEMU simulation.
        core::ptr::write_volatile(base.add(LCR), 0x03);
    }
}

pub fn uart_putc(c: u8) {
    unsafe {
        let base = UART0_BASE as *mut u8;
        while core::ptr::read_volatile(base.add(LSR)) & LSR_THRE == 0 {}
        core::ptr::write_volatile(base.add(THR), c);
    }
}

pub struct UartWriter;

impl fmt::Write for UartWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for b in s.bytes() {
            uart_putc(b);
        }
        Ok(())
    }
}
