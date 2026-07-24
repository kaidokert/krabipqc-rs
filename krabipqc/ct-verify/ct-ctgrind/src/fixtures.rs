//! Taint wrappers, one per `ct-fixtures` symbol.
//!
//! Taint model: the ML-KEM decapsulation key `dk` is the secret. The
//! encapsulation key `ek`, ciphertext `ct`, and all size parameters are
//! public (baked into the fixture via deterministic keygen + encaps), so
//! they are not tainted. A secret-dependent branch anywhere in the reachable
//! decaps path (including inlined NTT / blinding primitives) trips memcheck,
//! while the many legitimate branches on public loop bounds / buffer sizes
//! pass by construction.
//!
//! The shared-secret output is untainted before `black_box`: a KEM shared
//! secret is secret-*derived* but is what the caller uses as key material, so
//! reads of it downstream are not leaks.

use core::hint::black_box;
use krabi_caliper::ctgrind_fixture;

krabi_caliper::ctgrind_standard_controls!();
use krabi_caliper::host::ctgrind::{taint_val, untaint_val};

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
    let d = [0x11u8; 32];
    let z = [0x22u8; 32];
    let m = [0x33u8; 32];
    let (ek, dk) = krabipqc::ml_kem_512::keygen_from_seed(&d, &z).unwrap();
    let (_ss_enc, ct) = krabipqc::ml_kem_512::encaps_from_seed(&ek, &m).unwrap();
    let mut out = [0u8; 32];
    taint_val(&dk);
    unsafe { ct_fix__mlkem_decaps__512(&dk, &ct, &mut out) }
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
    let d = [0x11u8; 32];
    let z = [0x22u8; 32];
    let m = [0x33u8; 32];
    let (ek, dk) = krabipqc::ml_kem_768::keygen_from_seed(&d, &z).unwrap();
    let (_ss_enc, ct) = krabipqc::ml_kem_768::encaps_from_seed(&ek, &m).unwrap();
    let mut out = [0u8; 32];
    taint_val(&dk);
    unsafe { ct_fix__mlkem_decaps__768(&dk, &ct, &mut out) }
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
    let d = [0x11u8; 32];
    let z = [0x22u8; 32];
    let m = [0x33u8; 32];
    let (ek, dk) = krabipqc::ml_kem_1024::keygen_from_seed(&d, &z).unwrap();
    let (_ss_enc, ct) = krabipqc::ml_kem_1024::encaps_from_seed(&ek, &m).unwrap();
    let mut out = [0u8; 32];
    taint_val(&dk);
    unsafe { ct_fix__mlkem_decaps__1024(&dk, &ct, &mut out) }
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
    taint_val(&s);
    unsafe { nct_fix__neg__secret_branch(&s, &mut out) }
    untaint_val(&out);
    let _ = black_box(out);
});

unsafe extern "C" {
    fn nct_fix__neg__vartime_cmp(s_ptr: *const [u8; 64], out_ptr: *mut u8);
}
ctgrind_fixture!(nct_fix__neg__vartime_cmp, {
    let s = [0u8; 64];
    let mut out = 0u8;
    taint_val(&s);
    unsafe { nct_fix__neg__vartime_cmp(&s, &mut out) }
    untaint_val(&out);
    let _ = black_box(out);
});
