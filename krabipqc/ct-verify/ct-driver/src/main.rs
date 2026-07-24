//! ML-KEM decaps CT assembly gate.
//!
//! Checks that the ML-KEM decaps fixtures — each containing the full
//! FO-transform re-encrypt, CT equality mask, and implicit-rejection select —
//! contain at most `ladder_allowed_branches` conditional branches per target.
//!
//! `default_ladder` matches all `ct_fix__*` symbols, so `matched` equals
//! `positives` by construction. The branch ceiling is intentionally generous
//! to admit known-public branches (loop control on polynomial dimensions,
//! buffer-size guards), while still gating against regressions that add
//! secret-dependent branches.
//!
//! Calibration: run `cargo run -p ct-driver -- --target <triple>` on a
//! fresh build and note the `branches seen` count. Tighten each target's
//! `ladder_allowed_branches` to that count + a small margin once the CI
//! baseline is established.

mod target;

use std::path::Path;
use std::process::ExitCode;

use krabi_caliper::host::ct_asm::{DriverConfig, LadderConfig, run_ladder};

fn main() -> ExitCode {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("ct-verify workspace");
    run_ladder(
        target::TARGETS,
        LadderConfig {
            driver: DriverConfig {
                workspace,
                fixture_package: "ct-fixtures",
                fixture_features: &["panic-handler"],
            },
            // Matches all ct_fix__* positive fixtures so ladder_symbols_matched
            // == positives without needing --expect-ladder.
            default_ladder: r"^ct_fix__",
        },
    )
}
