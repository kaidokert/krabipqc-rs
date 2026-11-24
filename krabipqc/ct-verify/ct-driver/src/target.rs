//! Per-target specifications and branch calibrations.
//!
//! Selectors match v0-mangled symbols: legacy mangling tells the
//! `mul_ntt_acc::<2>`/`<3>`/`<4>` monomorphizations apart only by hash, v0
//! spells out the const generic. Crate disambiguators (`Cs…_`) vary between
//! builds and are matched loosely.
//!
//! To recalibrate after a library or toolchain change, run
//! `cargo run --release -p ct-driver -- --target <triple>` with
//! `CARGO_PROFILE_RELEASE_OPT_LEVEL` set to each level, review the branch
//! evidence the failing checks print, and copy the `seen` counts into the
//! table below.

use krabi_caliper::host::ct_asm::{CalibratedSymbolsTarget, SymbolCalibration};
use krabi_caliper::host::isa as mnemonics;

/// Fixture builds need v0 mangling for the selectors below.
const V0_MANGLING: &[&str] = &[
    "--config",
    r#"build.rustflags=["-Csymbol-mangling-version=v0"]"#,
];

macro_rules! krabipqc {
    ($path:literal) => {
        concat!("8krabipqc", $path, "$")
    };
}
/// A `krabipqc` function generic over the `Ct` personality.
macro_rules! krabipqc_ct {
    ($path:literal) => {
        concat!(
            "8krabipqc",
            $path,
            r"NtNtCs\w+_16const_num_traits11personality2CtE"
        )
    };
}
/// A `modmath::montgomery::basic_mont` function instantiated at `u32`.
macro_rules! basic_mont {
    ($name:literal) => {
        concat!(
            "7modmath10montgomery10basic_mont",
            $name,
            r"mECs\w+_8krabipqc$"
        )
    };
}

/// Present at both opt-levels, in this order at the head of each list.
#[rustfmt::skip]
const COMMON: &[(&str, &str)] = &[
    ("fixture", r"^_?ct_fix__mlkem_decaps__512$"),
    ("ml_kem_512::decaps", krabipqc!("6ml_kem10ml_kem_5126decaps")),
    ("blinding::derive_pair<Ct>", krabipqc_ct!("8blinding11derive_pair")),
    ("hashing::sha3_512", krabipqc!("7hashing8sha3_512")),
    ("Shake128Stream::new", r"8krabipqc7hashingNt\w*_14Shake128Stream3new$"),
    ("Shake128Stream::squeeze", r"8krabipqc7hashingNt\w*_14Shake128Stream7squeeze$"),
    ("Shake256Stream::new", r"8krabipqc7hashingNt\w*_14Shake256Stream3new$"),
    ("Shake256Stream::squeeze", r"8krabipqc7hashingNt\w*_14Shake256Stream7squeeze$"),
    ("encoding::byte_decode", krabipqc!("5mlkem8encoding11byte_decode")),
    ("encoding::byte_encode", krabipqc!("5mlkem8encoding11byte_encode")),
    ("ntt::ntt<Ct>", krabipqc_ct!("5mlkem3ntt3ntt")),
    ("ntt::inv_ntt<Ct>", krabipqc_ct!("5mlkem3ntt7inv_ntt")),
    ("ntt::mul_ntt<Ct>", krabipqc_ct!("5mlkem3ntt7mul_ntt")),
    ("ntt::mul_ntt_acc<2, Ct>", r"8krabipqc5mlkem3ntt11mul_ntt_accKj2_NtNtCs\w+_16const_num_traits11personality2CtE"),
    ("sampling::sample_cbd_from_seed", krabipqc!("5mlkem8sampling20sample_cbd_from_seed")),
    ("sampling::sample_ntt", krabipqc!("5mlkem8sampling10sample_ntt")),
    ("sampling::sample_re_y_e2<2>", r"8krabipqc5mlkem8sampling14sample_re_y_e2Kj2_E"),
    ("basic_mont::wide_redc_ct", basic_mont!("12wide_redc_ct")),
    ("basic_mont::wide_montgomery_mul_acc_ct", basic_mont!("26wide_montgomery_mul_acc_ct")),
    ("basic_mont::accumulate_high_half_carry_ct", basic_mont!("29accumulate_high_half_carry_ct")),
    ("keccak::p1600", r"6keccak5p1600$"),
    ("keccak::keccak_p<u64>", r"6keccak8keccak_pyE"),
    ("subtle::black_box<u8>", r"6subtle9black_boxhECs\w+_8krabipqc$"),
];

/// Kept out of line at "z" only; inlined into the `COMMON` symbols at "s".
#[rustfmt::skip]
const Z_ONLY: &[(&str, &str)] = &[
    ("blinding::scale_mont<Ct>", krabipqc_ct!("8blinding10scale_mont")),
    ("hashing::shake256", krabipqc!("7hashing8shake256")),
    ("encoding::compress_poly", krabipqc!("5mlkem8encoding13compress_poly")),
    ("encoding::decompress_poly", krabipqc!("5mlkem8encoding15decompress_poly")),
    ("ntt::add_mont<Ct>", krabipqc_ct!("5mlkem3ntt8add_mont")),
    ("ntt::sub_mont<Ct>", krabipqc_ct!("5mlkem3ntt8sub_mont")),
    ("ntt::mul_mont_p<Ct>", krabipqc_ct!("5mlkem3ntt10mul_mont_p")),
    ("FieldExt<Ct>::add_mont", r"8krabipqc9field_ext8FieldExtB\w*_E8add_mont"),
    ("FieldExt<Ct>::sub_mont", r"8krabipqc9field_ext8FieldExtB\w*_E8sub_mont"),
    ("sampling::sample_e1_row<2>", r"8krabipqc5mlkem8sampling13sample_e1_rowKj2_E"),
    ("Poly<u32>::zero", r"8krabipqc4polyINtB\w*_4PolymE4zero"),
    ("[Poly<u32>; 2]::each_ref", r"8krabipqc4poly4PolymEj2_8each_ref"),
    ("PolyVec<u32, 2>::zero", r"8krabipqc7polyvecINtB\w*_7PolyVecmKj2_E4zero"),
    ("PolyVec<u32, 2>::zeroize", r"8krabipqc7polyvecINtB\w*_7PolyVecmKj2_ENtCs\w+_7zeroize7Zeroize7zeroize"),
    ("basic_mont::wide_montgomery_mul_ct", basic_mont!("22wide_montgomery_mul_ct")),
    // Public-only: the matrix-A expansion in `sample_ntt` multiplies by
    // the variable-time path.
    ("basic_mont::wide_montgomery_mul", basic_mont!("19wide_montgomery_mul")),
    ("basic_mont::wide_redc", basic_mont!("9wide_redc")),
    ("subtle::ct_lt<u32>", r"6subtle16ConstantTimeLess5ct_ltCs\w+_8krabipqc$"),
    ("subtle::ct_eq<u32>", r"6subtlemNtB\w*_14ConstantTimeEq5ct_eq$"),
    ("subtle::Choice::not", r"6subtleNtB\w*_6ChoiceNtNtNtCs\w+_4core3ops3bit3Not3not$"),
];

/// Negative controls, last in each list; a count of zero means the gate
/// stopped seeing the secret branch.
const NEGATIVE: &[(&str, &str)] = &[
    ("neg: secret_branch", r"^_?nct_fix__neg__secret_branch$"),
    ("neg: vartime_cmp", r"^_?nct_fix__neg__vartime_cmp$"),
];

struct Target {
    triple: &'static str,
    priority: u8,
    forbidden: &'static [&'static str],
    allowed_cmov: &'static [&'static str],
    /// `COMMON` then `NEGATIVE`.
    s: &'static [usize],
    /// `COMMON`, `Z_ONLY`, then `NEGATIVE`.
    z: &'static [usize],
}

/// Branch counts, classified from the thumbv7m disassembly at "s":
/// - back edges and guards of loops over the ML-KEM size constants (256
///   coefficients, 32/64/320/1024/2048-byte buffers, K = 2), including the
///   FO re-encryption compare, which XOR-ORs a fixed 320-byte row into an
///   accumulator and never branches on it;
/// - the flag of the unrolled K = 2 outer loops (1 on entry, then 0);
/// - `Result` discriminants of the internal decoding and sampling calls;
/// - public lengths in the sponge (`Shake*Stream`, `sha3_512`, `keccak_p`);
/// - rejection sampling of matrix A in `sample_ntt` from the public seed ρ;
/// - `subtle`'s `ct_lt` bit-smearing loop (counter seeded at 1, doubling to
///   the constant 32), inlined into `wide_redc_ct` and
///   `wide_montgomery_mul_acc_ct` at "s" and out of line at "z".
#[rustfmt::skip]
const TARGETS: &[Target] = &[
    Target {
        triple: "thumbv7em-none-eabi",
        priority: 1,
        forbidden: mnemonics::THUMB_FORBIDDEN,
        allowed_cmov: mnemonics::THUMB_ALLOWED,
        s: &[1, 64, 2, 17, 16, 3, 17, 9, 4, 7, 6, 6, 5, 10, 6, 4, 3, 6, 2, 0, 0, 3, 0, 2, 2],
        z: &[1, 28, 2, 9, 7, 3, 7, 5, 3, 6, 5, 5, 5, 8, 5, 4, 3, 0, 0, 0, 0, 3, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 2, 1, 1, 0, 0, 4, 2, 0, 0, 2, 2],
    },
    Target {
        triple: "thumbv7m-none-eabi",
        priority: 1,
        forbidden: mnemonics::THUMB_FORBIDDEN,
        allowed_cmov: mnemonics::THUMB_ALLOWED,
        s: &[1, 64, 2, 17, 16, 3, 17, 9, 4, 7, 6, 6, 5, 10, 6, 4, 3, 6, 2, 0, 0, 3, 0, 2, 2],
        z: &[1, 28, 2, 9, 7, 3, 7, 5, 3, 6, 5, 5, 5, 8, 5, 4, 3, 0, 0, 0, 0, 3, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 2, 1, 1, 0, 0, 4, 2, 0, 0, 2, 2],
    },
    Target {
        triple: "thumbv6m-none-eabi",
        priority: 2,
        forbidden: mnemonics::THUMB_FORBIDDEN,
        allowed_cmov: mnemonics::THUMB_ALLOWED,
        s: &[1, 71, 2, 17, 15, 5, 16, 11, 6, 8, 10, 10, 14, 20, 9, 7, 3, 6, 2, 0, 0, 3, 0, 2, 2],
        z: &[1, 36, 2, 10, 7, 3, 7, 5, 3, 6, 6, 6, 13, 16, 8, 5, 3, 0, 0, 0, 0, 3, 0, 1, 0, 1, 1, 0, 0, 0, 1, 1, 0, 1, 2, 1, 1, 0, 0, 3, 2, 0, 0, 2, 2],
    },
    Target {
        triple: "riscv32imc-unknown-none-elf",
        priority: 3,
        forbidden: mnemonics::RISCV_FORBIDDEN,
        allowed_cmov: &[],
        s: &[1, 65, 2, 17, 15, 5, 16, 11, 7, 9, 8, 8, 7, 14, 7, 5, 3, 6, 2, 0, 0, 3, 0, 2, 2],
        z: &[1, 43, 3, 10, 9, 3, 9, 5, 5, 9, 8, 8, 8, 12, 8, 5, 3, 0, 0, 0, 0, 4, 0, 2, 0, 2, 2, 0, 0, 0, 0, 0, 0, 2, 4, 2, 2, 0, 0, 3, 4, 0, 0, 3, 2],
    },
    Target {
        triple: "riscv32imac-unknown-none-elf",
        priority: 3,
        forbidden: mnemonics::RISCV_FORBIDDEN,
        allowed_cmov: &[],
        s: &[1, 65, 2, 17, 15, 5, 16, 11, 7, 9, 8, 8, 7, 14, 7, 5, 3, 6, 2, 0, 0, 3, 0, 2, 2],
        z: &[1, 43, 3, 10, 9, 3, 9, 5, 5, 9, 8, 8, 8, 12, 8, 5, 3, 0, 0, 0, 0, 4, 0, 2, 0, 2, 2, 0, 0, 0, 0, 0, 0, 2, 4, 2, 2, 0, 0, 3, 4, 0, 0, 3, 2],
    },
];

/// Calibrated targets for `opt_level`; levels without a calibration are an
/// error rather than a fallback to another level's numbers.
pub fn targets(opt_level: &str) -> Result<Vec<CalibratedSymbolsTarget>, String> {
    let symbols: Vec<(&str, &str)> = match opt_level {
        "s" => COMMON.iter().chain(NEGATIVE).copied().collect(),
        "z" => COMMON
            .iter()
            .chain(Z_ONLY)
            .chain(NEGATIVE)
            .copied()
            .collect(),
        other => return Err(format!("no branch calibration for opt-level {other:?}")),
    };
    TARGETS
        .iter()
        .map(|target| {
            let counts = if opt_level == "s" { target.s } else { target.z };
            if counts.len() != symbols.len() {
                return Err(format!(
                    "{}: {} counts for {} symbols at opt-level {opt_level:?}",
                    target.triple,
                    counts.len(),
                    symbols.len()
                ));
            }
            let calibrations: Vec<SymbolCalibration> = symbols
                .iter()
                .zip(counts)
                .map(
                    |(&(display_name, selector), &expected_branches)| SymbolCalibration {
                        display_name,
                        selector,
                        expected_branches,
                    },
                )
                .collect();
            Ok(CalibratedSymbolsTarget {
                triple: target.triple,
                priority: target.priority,
                toolchain: "1.88.0",
                forbidden: target.forbidden,
                allowed_cmov: target.allowed_cmov,
                calibrations: Vec::leak(calibrations),
                extra_cargo_args: V0_MANGLING,
            })
        })
        .collect()
}
