#![no_main]
#![no_std]

use core::hint::black_box;

use cortex_m_rt::entry;
use krabi_caliper::Unit;
use krabi_caliper::cortex_m::DwtMeasurementPlatform;
use krabi_caliper::protocol::rtt::print;
use krabi_caliper::report::Field;
use krabi_caliper::stack::{StackProbe, paint_cortex_m_runtime};
use krabi_caliper::suite::{PairedSuite, PairedSuiteConfig, PairedSuiteFields};
use krabipqc::ml_kem_512;
use stm32f4xx_hal::{pac, prelude::*};

const TRIALS: usize = 4;
const HCLK_HZ: u32 = 30_000_000;
const MAX_POSITIVE_SPREAD: u64 = 32;
const STACK_SAFE_ZONE: usize = 512;
const SUITE: &str = "krabipqc-mlkem512-decaps";

#[derive(Clone)]
struct DecapsCase {
    dk: [u8; ml_kem_512::DK_BYTES],
    ct: [u8; ml_kem_512::CT_BYTES],
}

fn make_cases() -> (DecapsCase, DecapsCase) {
    let (ek, dk_a) = ml_kem_512::keygen_from_seed(&[0x11; 32], &[0x12; 32]).unwrap();
    let (_, dk_b) = ml_kem_512::keygen_from_seed(&[0xa1; 32], &[0xa2; 32]).unwrap();
    let (expected, ct) = ml_kem_512::encaps_from_seed(&ek, &[0x13; 32]).unwrap();
    assert_eq!(ml_kem_512::decaps(&dk_a, &ct).unwrap(), expected);
    assert_ne!(ml_kem_512::decaps(&dk_b, &ct).unwrap(), expected);
    (DecapsCase { dk: dk_a, ct }, DecapsCase { dk: dk_b, ct })
}

fn copy_case(case: &DecapsCase) -> DecapsCase {
    case.clone()
}

#[inline(never)]
fn decaps_once(case: &DecapsCase) -> bool {
    let out = ml_kem_512::decaps(black_box(&case.dk), black_box(&case.ct)).unwrap_or([0; 32]);
    let _ = black_box(out);
    true
}

#[inline(never)]
fn early_exit_once(secret: &[u8; 64]) -> bool {
    let mut leading_zeroes = 0u8;
    for &byte in black_box(secret) {
        if black_box(byte) != 0 {
            break;
        }
        leading_zeroes = leading_zeroes.wrapping_add(1);
    }
    let _ = black_box(leading_zeroes);
    true
}

fn paint_stack() -> StackProbe<'static> {
    // SAFETY: cortex-m-rt owns the single runtime stack and this firmware does
    // not schedule another context on it while the probe is painted.
    unsafe { paint_cortex_m_runtime::<STACK_SAFE_ZONE>() }.unwrap()
}

fn stop() -> ! {
    loop {
        cortex_m::asm::nop();
    }
}

#[entry]
fn main() -> ! {
    let mut reporter = krabi_caliper::protocol::rtt::init_ct_compatible();

    let (case_a, case_b) = make_cases();

    let mut peripherals = cortex_m::Peripherals::take().unwrap();
    let device = pac::Peripherals::take().unwrap();
    let _clocks = device.RCC.constrain().cfgr.sysclk(30.MHz()).freeze();
    let mut platform = DwtMeasurementPlatform::enable(
        &mut peripherals.DCB,
        &mut peripherals.DWT,
        Some(HCLK_HZ as u64),
    )
    .unwrap();
    let stack_probe = paint_stack();

    let run_fields = [
        Field::token("parameter_set", "ml-kem-512"),
        Field::token("clock_profile", "hsi-pll-30mhz-0ws"),
        Field::u64("hclk_hz", HCLK_HZ as u64),
        Field::u64("trials", TRIALS as u64),
        Field::u64("max_positive_spread", MAX_POSITIVE_SPREAD),
    ];
    let mut suite = PairedSuite::<_, _, TRIALS>::start(
        &mut platform,
        &mut reporter,
        PairedSuiteConfig {
            suite: SUITE,
            target: "cortex-m4f",
            board: Some("j-trace-stm32f407vg"),
            unit: Unit::CoreCycles,
            frequency_hz: Some(HCLK_HZ as u64),
            warmup_blocks: 1,
            batches: 1,
            positive_max_spread: MAX_POSITIVE_SPREAD,
            positive_require_overlap: false,
            fields: PairedSuiteFields {
                run: &run_fields,
                fixture: &[],
                summary: &[],
            },
        },
    )
    .unwrap();

    suite
        .positive_prepared("mlkem512_decaps", &case_a, &case_b, copy_case, decaps_once)
        .unwrap();

    const SLOW: [u8; 64] = [0; 64];
    const FAST: [u8; 64] = [1; 64];
    suite
        .negative("negative_early_exit", &SLOW, &FAST, early_exit_once)
        .unwrap();

    // SAFETY: the single-threaded firmware exclusively owns its runtime stack.
    let stack = unsafe { stack_probe.measure() };
    suite
        .stack_measurement(stack, &[Field::token("parameter_set", "ml-kem-512")])
        .unwrap();
    assert!(!stack.overflowed);
    suite.finish().unwrap();
    stop();
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    print(format_args!("PANIC: {info}\n"));
    stop();
}
