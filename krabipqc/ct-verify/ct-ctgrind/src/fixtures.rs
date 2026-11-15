//! Taint wrappers, one per `ct-fixtures` symbol.
//!
//! Taint model: the secret parts of `dk` are tainted — specifically `dk_PKE`
//! (the private polynomial `s`, the first `DK_BYTES - EK_BYTES - 64` bytes)
//! and `z` (the last 32 bytes, the implicit rejection seed). The embedded `ek`
//! and `H(ek)` are public and left untainted; tainting them would falsely
//! poison `sample_ntt` during the FO re-encryption step, which branches on
//! the rejection-sampling output of the public seed `ρ`. A secret-dependent
//! branch anywhere in the reachable decaps path trips memcheck, while the many
//! legitimate branches on public data (loop bounds, buffer sizes, `sample_ntt`
//! rejection sampling) pass by construction.
//!
//! The shared-secret output is untainted before `black_box`: a KEM shared
//! secret is secret-*derived* but is what the caller uses as key material, so
//! reads of it downstream are not leaks.
//!
//! Secrets reach the fixtures through a `black_box`'d pointer. `taint` sets
//! Valgrind metadata, not memory, and fat LTO inlines the fixtures into
//! these wrappers, so a plain reference to a local lets the optimizer use
//! the known value and the taint never reaches the code under test.
//!
//! Memcheck reports branches on tainted data, not conditional selects: a
//! secret `if` that LLVM turns into `csel` on a pointer passes here (seen
//! at opt-level "s" on aarch64, where "z" kept the branch).

use core::hint::black_box;
use krabi_caliper::ctgrind_fixture;

krabi_caliper::ctgrind_standard_controls!();
use krabi_caliper::host::ctgrind::{taint, taint_val, untaint_val};

/// Taint `value` and return a pointer the optimizer cannot trace back to it.
fn taint_ptr<T>(value: &T) -> *const T {
    taint_val(value);
    black_box(value as *const T)
}

// ---------------------------------------------------------------------------
// ML-KEM decaps positives
// ---------------------------------------------------------------------------

unsafe extern "C" {
    fn ct_fix__mlkem_decaps__512(
        dk_ptr: *const [u8; krabipqc::ml_kem_512::DK_BYTES],
        ct_ptr: *const [u8; krabipqc::ml_kem_512::CT_BYTES],
        out_ptr: *mut [u8; 32],
    );
}
ctgrind_fixture!(ct_fix__mlkem_decaps__512, {
    use krabipqc::ml_kem_512::{DK_BYTES, EK_BYTES};
    // dk = dk_PKE || ek || H(ek)(32) || z(32). Secret: dk_PKE and z.
    const DK_PKE: usize = DK_BYTES - EK_BYTES - 64;
    let d = [0x11u8; 32];
    let z = [0x22u8; 32];
    let m = [0x33u8; 32];
    let (ek, dk) = krabipqc::ml_kem_512::keygen_from_seed(&d, &z).unwrap();
    let (_ss_enc, ct) = krabipqc::ml_kem_512::encaps_from_seed(&ek, &m).unwrap();
    let mut out = [0u8; 32];
    taint::<u8>(&dk[..DK_PKE]);
    taint::<u8>(&dk[DK_BYTES - 32..]);
    let dk = black_box(&raw const dk);
    unsafe { ct_fix__mlkem_decaps__512(dk, &ct, &mut out) }
    untaint_val(&out);
    let _ = black_box(out);
});

unsafe extern "C" {
    fn ct_fix__mlkem_decaps__768(
        dk_ptr: *const [u8; krabipqc::ml_kem_768::DK_BYTES],
        ct_ptr: *const [u8; krabipqc::ml_kem_768::CT_BYTES],
        out_ptr: *mut [u8; 32],
    );
}
ctgrind_fixture!(ct_fix__mlkem_decaps__768, {
    use krabipqc::ml_kem_768::{DK_BYTES, EK_BYTES};
    const DK_PKE: usize = DK_BYTES - EK_BYTES - 64;
    let d = [0x11u8; 32];
    let z = [0x22u8; 32];
    let m = [0x33u8; 32];
    let (ek, dk) = krabipqc::ml_kem_768::keygen_from_seed(&d, &z).unwrap();
    let (_ss_enc, ct) = krabipqc::ml_kem_768::encaps_from_seed(&ek, &m).unwrap();
    let mut out = [0u8; 32];
    taint::<u8>(&dk[..DK_PKE]);
    taint::<u8>(&dk[DK_BYTES - 32..]);
    let dk = black_box(&raw const dk);
    unsafe { ct_fix__mlkem_decaps__768(dk, &ct, &mut out) }
    untaint_val(&out);
    let _ = black_box(out);
});

unsafe extern "C" {
    fn ct_fix__mlkem_decaps__1024(
        dk_ptr: *const [u8; krabipqc::ml_kem_1024::DK_BYTES],
        ct_ptr: *const [u8; krabipqc::ml_kem_1024::CT_BYTES],
        out_ptr: *mut [u8; 32],
    );
}
ctgrind_fixture!(ct_fix__mlkem_decaps__1024, {
    use krabipqc::ml_kem_1024::{DK_BYTES, EK_BYTES};
    const DK_PKE: usize = DK_BYTES - EK_BYTES - 64;
    let d = [0x11u8; 32];
    let z = [0x22u8; 32];
    let m = [0x33u8; 32];
    let (ek, dk) = krabipqc::ml_kem_1024::keygen_from_seed(&d, &z).unwrap();
    let (_ss_enc, ct) = krabipqc::ml_kem_1024::encaps_from_seed(&ek, &m).unwrap();
    let mut out = [0u8; 32];
    taint::<u8>(&dk[..DK_PKE]);
    taint::<u8>(&dk[DK_BYTES - 32..]);
    let dk = black_box(&raw const dk);
    unsafe { ct_fix__mlkem_decaps__1024(dk, &ct, &mut out) }
    untaint_val(&out);
    let _ = black_box(out);
});

// ---------------------------------------------------------------------------
// Negative controls: secret-dependent early-exit. MUST trip.
// ---------------------------------------------------------------------------

unsafe extern "C" {
    fn nct_fix__neg__secret_branch(s_ptr: *const [u8; 64], out_ptr: *mut u8);
}
ctgrind_fixture!(nct_fix__neg__secret_branch, {
    let s = [0u8; 64];
    let mut out = 0u8;
    let s = taint_ptr(&s);
    unsafe { nct_fix__neg__secret_branch(s, &mut out) }
    untaint_val(&out);
    let _ = black_box(out);
});

unsafe extern "C" {
    fn nct_fix__neg__vartime_cmp(s_ptr: *const [u8; 64], out_ptr: *mut u8);
}
ctgrind_fixture!(nct_fix__neg__vartime_cmp, {
    let s = [0u8; 64];
    let mut out = 0u8;
    let s = taint_ptr(&s);
    unsafe { nct_fix__neg__vartime_cmp(s, &mut out) }
    untaint_val(&out);
    let _ = black_box(out);
});

unsafe extern "C" {
    fn nct_fix__neg__value_loop(a_ptr: *const [u32; 4]) -> u32;
}
ctgrind_fixture!(nct_fix__neg__value_loop, {
    let a = [0u32; 4];
    let r = unsafe { nct_fix__neg__value_loop(taint_ptr(&a)) };
    untaint_val(&r);
    let _ = black_box(r);
});

unsafe extern "C" {
    fn nct_fix__neg__secret_bound(n_ptr: *const u32) -> u32;
}
ctgrind_fixture!(nct_fix__neg__secret_bound, {
    let n = 0u32;
    let r = unsafe { nct_fix__neg__secret_bound(taint_ptr(&n)) };
    untaint_val(&r);
    let _ = black_box(r);
});
