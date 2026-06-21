//! ML-KEM-512 key encapsulation via the RustCrypto trait API.
//!
//! Run with: `cargo run --example ml_kem`

use kem::{Decapsulator, Encapsulate, Generate, TryDecapsulate};
use krabipqc::{Dk, Ek, MlKem512};

fn main() {
    // Key generation (decapsulation side).
    let dk: Dk<MlKem512> = Dk::generate();
    let ek: Ek<MlKem512> = dk.encapsulation_key().clone();

    // Encapsulate (sender): produces ciphertext + shared secret.
    let (ct, ss_send) = ek.encapsulate();

    // Decapsulate (recipient): recovers the same shared secret.
    let ss_recv = dk.try_decapsulate(&ct).unwrap();

    assert_eq!(ss_send, ss_recv);
    println!(
        "ML-KEM-512: encaps + decaps ok ({} byte shared secret)",
        ss_send.len()
    );
}
