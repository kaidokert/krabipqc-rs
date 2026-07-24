//! Linker-DCE audit for the krabipqc ML-KEM decaps path.
//!
//! Each `#[no_mangle] pub extern "C"` symbol exercises one ML-KEM decaps
//! the way a deployed consumer would: fallible key construction handled with
//! `if let Ok` (a `match`, never a panicking `unwrap`), and the decaps
//! `Result` observed through `black_box` rather than extracted. After
//! cross-building with the workspace release profile, krabi-caliper asserts
//! the archive contains no `core::panicking` machinery — for a KEM a
//! reachable panic is both a DoS edge and a timing oracle (the
//! panic-formatting path's cost depends on the values being formatted).

#![cfg_attr(feature = "panic-handler", no_std)]

#[cfg(feature = "panic-handler")]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

use core::hint::black_box;
use krabipqc::{ml_kem_512, ml_kem_768, ml_kem_1024};

/// Audit: ML-KEM-512 Decaps. Exercises the full `dk`-decoded decaps path.
///
/// # Safety
/// `dk_ptr` (1632 B), `ct_ptr` (768 B), `out_ptr` (32 B) must be valid.
#[no_mangle]
pub unsafe extern "C" fn audit__mlkem_decaps__512(
    dk_ptr: *const [u8; ml_kem_512::DK_BYTES],
    ct_ptr: *const [u8; ml_kem_512::CT_BYTES],
    out_ptr: *mut [u8; 32],
) {
    let dk = black_box(unsafe { *dk_ptr });
    let ct = black_box(unsafe { *ct_ptr });
    if let Ok(ss) = ml_kem_512::decaps(&dk, &ct) {
        unsafe { *out_ptr = black_box(ss) }
    }
}

/// Audit: ML-KEM-768 Decaps.
///
/// # Safety
/// `dk_ptr` (2400 B), `ct_ptr` (1088 B), `out_ptr` (32 B) must be valid.
#[no_mangle]
pub unsafe extern "C" fn audit__mlkem_decaps__768(
    dk_ptr: *const [u8; ml_kem_768::DK_BYTES],
    ct_ptr: *const [u8; ml_kem_768::CT_BYTES],
    out_ptr: *mut [u8; 32],
) {
    let dk = black_box(unsafe { *dk_ptr });
    let ct = black_box(unsafe { *ct_ptr });
    if let Ok(ss) = ml_kem_768::decaps(&dk, &ct) {
        unsafe { *out_ptr = black_box(ss) }
    }
}

/// Audit: ML-KEM-1024 Decaps.
///
/// # Safety
/// `dk_ptr` (3168 B), `ct_ptr` (1568 B), `out_ptr` (32 B) must be valid.
#[no_mangle]
pub unsafe extern "C" fn audit__mlkem_decaps__1024(
    dk_ptr: *const [u8; ml_kem_1024::DK_BYTES],
    ct_ptr: *const [u8; ml_kem_1024::CT_BYTES],
    out_ptr: *mut [u8; 32],
) {
    let dk = black_box(unsafe { *dk_ptr });
    let ct = black_box(unsafe { *ct_ptr });
    if let Ok(ss) = ml_kem_1024::decaps(&dk, &ct) {
        unsafe { *out_ptr = black_box(ss) }
    }
}
