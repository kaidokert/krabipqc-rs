//! Print deterministic test vectors for embedding in downstream
//! integration tests (e.g. a cortex-m3 stack-profile harness). Covers
//! ML-DSA-44/65/87 (verify + sign) and ML-KEM-512/768/1024
//! (encaps + decaps).
//!
//! Run with: `cargo run --release --example print_vector`.

use krabipqc::{ml_dsa_44, ml_dsa_65, ml_dsa_87, ml_kem_512, ml_kem_768, ml_kem_1024};

fn main() {
    // FIPS 204 M' for pure ML-DSA, ctx = "":
    //   M' = 0x00 || 0x00 || message
    let mut mp = vec![0u8, 0u8];
    mp.extend_from_slice(MESSAGE);

    let (pk, sk) = ml_dsa_44::keygen_from_seed(&XI).unwrap();
    let sig = ml_dsa_44::sign_msg_repr(&sk, &mp, &RND).unwrap();
    assert!(ml_dsa_44::verify_msg_repr(&pk, &mp, &sig));

    println!("// xi (keygen seed):");
    print_arr("XI", &XI);
    println!("// rnd (sign randomness, all zeros for determinism):");
    print_arr("RND", &RND);
    // Emit MESSAGE as a `&[u8]` byte-array literal so the generator
    // stays correct even for non-UTF-8 / quote-containing bytes, and
    // the resulting `&[u8]` type matches the downstream consumer's
    // `copy_from_slice(MESSAGE)` / `MESSAGE.len()` call sites.
    println!("// raw message (M' = 0x00 || 0x00 || MESSAGE):");
    println!("pub const MESSAGE: &[u8] = &[");
    for chunk in MESSAGE.chunks(12) {
        let s: Vec<_> = chunk.iter().map(|b| format!("0x{:02x}", b)).collect();
        println!("    {},", s.join(", "));
    }
    println!("];");
    println!("// pk:");
    print_arr("PK", &pk);
    println!("// sk:");
    print_arr("SK", &sk);
    println!("// sig:");
    print_arr("SIG", &sig);

    // ML-KEM-512 test vector. Deterministic from fixed (d, z, m).
    let (ek, dk) = ml_kem_512::keygen_from_seed(&KEM_D, &KEM_Z).unwrap();
    let (ss_encaps, ct) = ml_kem_512::encaps_from_seed(&ek, &KEM_M).unwrap();
    let ss_decaps = ml_kem_512::decaps(&dk, &ct).unwrap();
    assert_eq!(ss_encaps, ss_decaps);

    println!("// ML-KEM-512 keygen `d` seed:");
    print_arr("KEM_D", &KEM_D);
    println!("// ML-KEM-512 keygen `z` seed:");
    print_arr("KEM_Z", &KEM_Z);
    println!("// ML-KEM-512 encaps `m` randomness:");
    print_arr("KEM_M", &KEM_M);
    println!("// ML-KEM-512 ek (encapsulation key):");
    print_arr("KEM_EK", &ek);
    println!("// ML-KEM-512 dk (decapsulation key):");
    print_arr("KEM_DK", &dk);
    println!("// ML-KEM-512 ct (ciphertext):");
    print_arr("KEM_CT", &ct);
    println!("// ML-KEM-512 ss (expected shared secret):");
    print_arr("KEM_SS", &ss_encaps);

    // ML-DSA-65 deterministic vector.
    let (pk_65, sk_65) = ml_dsa_65::keygen_from_seed(&XI).unwrap();
    let sig_65 = ml_dsa_65::sign_msg_repr(&sk_65, &mp, &RND).unwrap();
    assert!(ml_dsa_65::verify_msg_repr(&pk_65, &mp, &sig_65));
    println!("// ML-DSA-65 pk:");
    print_arr("PK_65", &pk_65);
    println!("// ML-DSA-65 sk:");
    print_arr("SK_65", &sk_65);
    println!("// ML-DSA-65 sig:");
    print_arr("SIG_65", &sig_65);

    // ML-DSA-87 deterministic vector.
    let (pk_87, sk_87) = ml_dsa_87::keygen_from_seed(&XI).unwrap();
    let sig_87 = ml_dsa_87::sign_msg_repr(&sk_87, &mp, &RND).unwrap();
    assert!(ml_dsa_87::verify_msg_repr(&pk_87, &mp, &sig_87));
    println!("// ML-DSA-87 pk:");
    print_arr("PK_87", &pk_87);
    println!("// ML-DSA-87 sk:");
    print_arr("SK_87", &sk_87);
    println!("// ML-DSA-87 sig:");
    print_arr("SIG_87", &sig_87);

    // ML-KEM-768 deterministic vector.
    let (ek_768, dk_768) = ml_kem_768::keygen_from_seed(&KEM_D, &KEM_Z).unwrap();
    let (ss_768, ct_768) = ml_kem_768::encaps_from_seed(&ek_768, &KEM_M).unwrap();
    assert_eq!(ml_kem_768::decaps(&dk_768, &ct_768).unwrap(), ss_768);
    println!("// ML-KEM-768 ek:");
    print_arr("KEM768_EK", &ek_768);
    println!("// ML-KEM-768 dk:");
    print_arr("KEM768_DK", &dk_768);
    println!("// ML-KEM-768 ct:");
    print_arr("KEM768_CT", &ct_768);
    println!("// ML-KEM-768 ss:");
    print_arr("KEM768_SS", &ss_768);

    // ML-KEM-1024 deterministic vector.
    let (ek_1024, dk_1024) = ml_kem_1024::keygen_from_seed(&KEM_D, &KEM_Z).unwrap();
    let (ss_1024, ct_1024) = ml_kem_1024::encaps_from_seed(&ek_1024, &KEM_M).unwrap();
    assert_eq!(ml_kem_1024::decaps(&dk_1024, &ct_1024).unwrap(), ss_1024);
    println!("// ML-KEM-1024 ek:");
    print_arr("KEM1024_EK", &ek_1024);
    println!("// ML-KEM-1024 dk:");
    print_arr("KEM1024_DK", &dk_1024);
    println!("// ML-KEM-1024 ct:");
    print_arr("KEM1024_CT", &ct_1024);
    println!("// ML-KEM-1024 ss:");
    print_arr("KEM1024_SS", &ss_1024);
}

const XI: [u8; 32] = [0x42; 32];
const RND: [u8; 32] = [0x00; 32];
const MESSAGE: &[u8] = b"Hello, cortex-m3 ML-DSA-44!";

const KEM_D: [u8; 32] = [0x51; 32];
const KEM_Z: [u8; 32] = [0x52; 32];
const KEM_M: [u8; 32] = [0x53; 32];

fn print_arr(name: &str, data: &[u8]) {
    println!("pub const {}: [u8; {}] = [", name, data.len());
    for chunk in data.chunks(12) {
        let s: Vec<_> = chunk.iter().map(|b| format!("0x{:02x}", b)).collect();
        println!("    {},", s.join(", "));
    }
    println!("];");
}
