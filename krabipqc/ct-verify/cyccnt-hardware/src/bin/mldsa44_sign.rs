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
use krabipqc::{KeyGenSeed, SigningRandomness, ml_dsa_44};
use stm32f4xx_hal::{pac, prelude::*};

const TRIALS: usize = 4;
// Timing regression bound, not a statistical CT gate.  ML-DSA sign timing
// includes per-attempt variation from the rejection-loop iteration count
// (kappa increments when the candidate signature fails bounds checks); a
// fixed (sk, m, rnd) triple is always deterministic on this MCU.  The CT
// guarantee comes from ctgrind and assembly ladder analysis in CI.  Bound
// will be set to the observed spread ceiling after the first hardware run.
const MAX_POSITIVE_SPREAD: u64 = 0;
const STACK_SAFE_ZONE: usize = 512;
const SUITE: &str = "krabipqc-mldsa44-sign";

#[derive(Clone)]
struct SignCase {
    sk: [u8; ml_dsa_44::SK_BYTES],
    msg: [u8; 32],
    rnd: [u8; 32],
}

// Both cases share the same signing key; msg and rnd differ.
// Any timing spread between A and B reflects rejection-loop count and
// challenge-polynomial arithmetic variation — not a path switch gated on
// any secret value.
fn make_cases(xi: &[u8; 32]) -> (SignCase, SignCase) {
    let (_pk, sk) = ml_dsa_44::keygen_from_seed(&KeyGenSeed(*xi)).unwrap();
    let case_a = SignCase {
        sk,
        msg: [0x01; 32],
        rnd: [0xA1; 32],
    };
    let case_b = SignCase {
        sk: case_a.sk,
        msg: [0x02; 32],
        rnd: [0xA2; 32],
    };
    (case_a, case_b)
}

fn copy_case(case: &SignCase) -> SignCase {
    case.clone()
}

#[inline(never)]
fn sign_once(case: &SignCase) -> bool {
    let rnd = SigningRandomness(case.rnd);
    let mut sig = [0u8; ml_dsa_44::SIG_BYTES];
    if let Ok(s) = ml_dsa_44::sign(
        black_box(&case.sk),
        black_box(&case.msg),
        b"",
        black_box(&rnd),
    ) {
        sig = s;
    }
    let _ = black_box(sig);
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

    // Cases built before hardware init so keygen stack does not inflate
    // the painted region.
    let (case_a, case_b) = make_cases(&[0x11; 32]);

    let mut peripherals = cortex_m::Peripherals::take().unwrap();
    let device = pac::Peripherals::take().unwrap();
    // Derive hclk_hz from the HAL so the reported frequency matches configuration.
    let clocks = device.RCC.constrain().cfgr.sysclk(30.MHz()).freeze();
    let hclk_hz = clocks.hclk().raw() as u64;
    let mut platform =
        DwtMeasurementPlatform::enable(&mut peripherals.DCB, &mut peripherals.DWT, Some(hclk_hz))
            .unwrap();
    let stack_probe = paint_stack();

    let run_fields = [
        Field::token("parameter_set", "ml-dsa-44"),
        Field::token("clock_profile", "hsi-pll-30mhz-0ws"),
        Field::u64("hclk_hz", hclk_hz),
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
            frequency_hz: Some(hclk_hz),
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

    // A=sign(sk, m1, rnd1), B=sign(sk, m2, rnd2).  Same sk in both.
    suite
        .positive_prepared("mldsa44_sign", &case_a, &case_b, copy_case, sign_once)
        .unwrap();

    const SLOW: [u8; 64] = [0; 64];
    const FAST: [u8; 64] = [1; 64];
    suite
        .negative("negative_early_exit", &SLOW, &FAST, early_exit_once)
        .unwrap();

    // SAFETY: the single-threaded firmware exclusively owns its runtime stack.
    let stack = unsafe { stack_probe.measure() };
    suite
        .stack_measurement(stack, &[Field::token("parameter_set", "ml-dsa-44")])
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
