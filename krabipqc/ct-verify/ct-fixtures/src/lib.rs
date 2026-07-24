//! Constant-time verification fixtures for krabipqc.
//!
//! Each `#[no_mangle] pub unsafe extern "C"` symbol pins one CT path so the
//! driver (`ct-driver`) can disassemble it per target ISA and the taint
//! harness (`ct-ctgrind`) can run it under Valgrind with secrets marked
//! undefined.
//!
//! **Scope:** ML-KEM decaps is the fully-CT surface verified here — the
//! FO transform re-encrypt and the implicit-rejection select are branchless
//! on the decapsulation key `dk`. ML-DSA sign has a known non-CT path (the
//! rejection-sampling norm checks branch on secret-derived `z` and `r0`);
//! DSA fixtures are excluded until that loop is hardened.
//!
//! Naming contract:
//! - `ct_fix__<op>__<params>` — positive; emitted code must be branch-free
//!   on the tainted secret input.
//! - `nct_fix__neg__<op>` — negative control; MUST trip each gate.
//!
//! Every secret input and output is wrapped in [`core::hint::black_box`] so
//! fat-LTO `opt-level="z"` cannot fold the body into an ABI stub.

#![cfg_attr(feature = "panic-handler", no_std)]

#[cfg(feature = "panic-handler")]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

use core::hint::black_box;
use krabipqc::{ml_kem_512, ml_kem_768, ml_kem_1024};

// ---------------------------------------------------------------------------
// Positive fixtures — ML-KEM decaps
// ---------------------------------------------------------------------------

/// Positive: ML-KEM-512 Decaps. `dk` is the secret decapsulation key
/// (1632 bytes); `ct` is the adversary-controlled ciphertext (768 bytes,
/// public); `out` receives the 32-byte shared secret.
///
/// The implicit-rejection select (`ss = (k' & eq) | (k_bar & !eq)`) and the
/// CT equality mask in `encrypt_compare_impl` must be branchless on `dk`.
///
/// # Safety
/// `dk_ptr`, `ct_ptr`, and `out_ptr` must be valid, aligned pointers to
/// arrays of the declared sizes.
#[no_mangle]
pub unsafe extern "C" fn ct_fix__mlkem_decaps__512(
    dk_ptr: *const [u8; ml_kem_512::DK_BYTES],
    ct_ptr: *const [u8; ml_kem_512::CT_BYTES],
    out_ptr: *mut [u8; 32],
) {
    let dk = black_box(unsafe { *dk_ptr });
    let ct = black_box(unsafe { *ct_ptr });
    let ss = ml_kem_512::decaps(&dk, &ct).unwrap_or([0u8; 32]);
    unsafe { *out_ptr = black_box(ss) }
}

/// Positive: ML-KEM-768 Decaps. Same CT contract as the 512 variant.
///
/// # Safety
/// `dk_ptr` (2400 B), `ct_ptr` (1088 B), `out_ptr` (32 B) must be valid.
#[no_mangle]
pub unsafe extern "C" fn ct_fix__mlkem_decaps__768(
    dk_ptr: *const [u8; ml_kem_768::DK_BYTES],
    ct_ptr: *const [u8; ml_kem_768::CT_BYTES],
    out_ptr: *mut [u8; 32],
) {
    let dk = black_box(unsafe { *dk_ptr });
    let ct = black_box(unsafe { *ct_ptr });
    let ss = ml_kem_768::decaps(&dk, &ct).unwrap_or([0u8; 32]);
    unsafe { *out_ptr = black_box(ss) }
}

/// Positive: ML-KEM-1024 Decaps. Same CT contract as the 512 variant.
///
/// # Safety
/// `dk_ptr` (3168 B), `ct_ptr` (1568 B), `out_ptr` (32 B) must be valid.
#[no_mangle]
pub unsafe extern "C" fn ct_fix__mlkem_decaps__1024(
    dk_ptr: *const [u8; ml_kem_1024::DK_BYTES],
    ct_ptr: *const [u8; ml_kem_1024::CT_BYTES],
    out_ptr: *mut [u8; 32],
) {
    let dk = black_box(unsafe { *dk_ptr });
    let ct = black_box(unsafe { *ct_ptr });
    let ss = ml_kem_1024::decaps(&dk, &ct).unwrap_or([0u8; 32]);
    unsafe { *out_ptr = black_box(ss) }
}

// ---------------------------------------------------------------------------
// Negative controls — MUST trip every gate
// ---------------------------------------------------------------------------

/// Negative: data-dependent early-exit loop on the secret bytes. The `break`
/// on a tainted byte is a conditional jump — memcheck sees the branch and the
/// assembly gate counts it. A clean pass here means the harness is broken.
///
/// # Safety
/// `s_ptr` (64 B) and `out_ptr` (1 B) must be valid.
#[no_mangle]
pub unsafe extern "C" fn nct_fix__neg__secret_branch(s_ptr: *const [u8; 64], out_ptr: *mut u8) {
    let s = black_box(unsafe { *s_ptr });
    let mut n = 0u8;
    for &b in s.iter() {
        if b != 0 {
            break;
        }
        n = n.wrapping_add(1);
    }
    unsafe { *out_ptr = black_box(n) }
}

/// Negative: non-constant-time (early-exit) comparison. MUST trip.
///
/// # Safety
/// `s_ptr` (64 B) and `out_ptr` (1 B) must be valid.
#[no_mangle]
pub unsafe extern "C" fn nct_fix__neg__vartime_cmp(s_ptr: *const [u8; 64], out_ptr: *mut u8) {
    let s = black_box(unsafe { *s_ptr });
    let reference = [0u8; 64];
    let mut equal = 1u8;
    for i in 0..64 {
        if s[i] != reference[i] {
            equal = 0;
            break;
        }
    }
    unsafe { *out_ptr = black_box(equal) }
}

/// No-op that forces this rlib onto a consumer's link line. Without a
/// referenced Rust item the linker may drop the rlib entirely (and with it
/// every fixture symbol).
pub fn link_anchor() {}
