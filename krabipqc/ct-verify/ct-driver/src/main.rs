//! ML-KEM-512 decaps assembly gate.
//!
//! The fixture symbols only copy their inputs and call into the library, so
//! the gate pins the functions decaps actually runs: every `krabipqc`,
//! `modmath`, `subtle` and `keccak` symbol reachable from
//! `ct_fix__mlkem_decaps__512`. Each must match exactly one symbol and carry
//! exactly its calibrated number of conditional branches.
//!
//! Which functions stay out of line depends on the opt-level ("s" inlines
//! the field and subtle helpers that "z" keeps separate), so the symbol set
//! is chosen per opt-level and the counts per target and opt-level. CI sets
//! the level through `CARGO_PROFILE_RELEASE_OPT_LEVEL`; unset means the
//! workspace profile's "z".
//!
//! An exact count is a codegen-drift detector, not a constant-time proof:
//! the counted branches are loop control over public bounds and the public
//! rejection sampling of matrix A. ctgrind is the semantic gate; this one
//! covers the targets Valgrind can't run.

mod target;

use std::path::Path;
use std::process::ExitCode;

use krabi_caliper::host::ct_asm::{
    CalibratedSymbolsConfig, CalibratedSymbolsTarget, DriverConfig, run_calibrated_symbols,
};

fn main() -> ExitCode {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("ct-verify workspace");
    let opt_level =
        std::env::var("CARGO_PROFILE_RELEASE_OPT_LEVEL").unwrap_or_else(|_| "z".to_string());
    let opt_level = opt_level.trim_matches('"');
    let targets: Vec<CalibratedSymbolsTarget> = match target::targets(opt_level) {
        Ok(targets) => targets,
        Err(message) => {
            eprintln!("error: {message}");
            return ExitCode::from(2);
        }
    };
    run_calibrated_symbols(
        &targets,
        CalibratedSymbolsConfig {
            driver: DriverConfig {
                workspace,
                fixture_package: "ct-fixtures",
                fixture_features: &["panic-handler"],
            },
        },
    )
}
