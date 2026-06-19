#![no_main]
#![no_std]

use cortex_m_rt::entry;
use cortex_m_semihosting::{debug, hprintln};

#[entry]
fn main() -> ! {
    hprintln!("hi from cortex-m3");
    hprintln!("about to exit");
    debug::exit(debug::EXIT_SUCCESS);
    loop {}
}

use panic_semihosting as _;
