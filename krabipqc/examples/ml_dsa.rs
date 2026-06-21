//! ML-DSA-44 sign / verify via the RustCrypto trait API.
//!
//! Run with: `cargo run --example ml_dsa`

use kem::common::Generate;
use krabipqc::{MlDsa44, MlDsaSigner, MlDsaVerifier};
use signature::{Keypair, RandomizedSigner, Verifier};

fn main() {
    // Key generation via OS RNG.
    let signer: MlDsaSigner<MlDsa44> = MlDsaSigner::generate();
    let verifier: MlDsaVerifier<MlDsa44> = signer.verifying_key();

    // Sign with OS randomness.
    let msg = b"hello ML-DSA-44";
    let sig = signer
        .try_sign_with_rng(&mut getrandom::SysRng, msg)
        .expect("sign");

    // Verify — success and reject.
    verifier.verify(msg, &sig).expect("signature valid");
    verifier
        .verify(b"tampered", &sig)
        .expect_err("must reject wrong message");

    println!(
        "ML-DSA-44: sign + verify ok ({} byte signature)",
        sig.as_ref().len()
    );
}
