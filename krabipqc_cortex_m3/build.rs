use std::env;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

fn main() {
    let target = env::var("TARGET").unwrap_or_else(|_| "thumbv7m-none-eabi".to_string());

    let include_bytes = include_bytes!("memory_cm3.x").as_slice();
    if !target.starts_with("thumbv7m") {
        // Single-target crate: we only support cortex-m3.
        panic!(
            "krabipqc_cortex_m3 supports only thumbv7m-none-eabi (got {})",
            target
        );
    }

    // Drop memory.x next to the linker script and tell rustc where to find it.
    let out = &PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR not set"));
    File::create(out.join("memory.x"))
        .expect("Failed to create memory.x")
        .write_all(include_bytes)
        .expect("Failed to write memory.x");
    println!("cargo:rustc-link-search={}", out.display());
    println!("cargo:rerun-if-changed=memory_cm3.x");

    println!("cargo:rustc-link-arg=--nmagic");
    println!("cargo:rustc-link-arg=-Tlink.x");
    println!("cargo:rustc-cfg=thumbv7m");
}
