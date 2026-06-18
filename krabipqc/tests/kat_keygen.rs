//! ACVP KAT for ML-DSA-44/65/87 KeyGen_internal.
//!
//! Vector source: NIST ACVP-Server
//!   gen-val/json-files/ML-DSA-keyGen-FIPS204/{prompt,expectedResults}.json
//! Group 1 (ML-DSA-44) tcId=1; Group 2 (ML-DSA-65) tcId=26; Group 3
//! (ML-DSA-87) tcId=51.
//!
//! For 44 we keep the seed/pk/sk inline; for 65 and 87 we read three-line
//! `seed/pk/sk` text files to keep the source file readable.

use krabipqc::{ml_dsa_44, ml_dsa_65, ml_dsa_87};

fn from_hex(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    hex::decode(&s).expect("bad hex")
}

fn parse_triple(text: &str) -> ([u8; 32], Vec<u8>, Vec<u8>) {
    let mut lines = text.lines().filter(|l| !l.trim().is_empty());
    let seed = from_hex(lines.next().expect("seed"));
    let pk = from_hex(lines.next().expect("pk"));
    let sk = from_hex(lines.next().expect("sk"));
    assert_eq!(seed.len(), 32);
    let mut xi = [0u8; 32];
    xi.copy_from_slice(&seed);
    (xi, pk, sk)
}

fn compare(label: &str, got: &[u8], want: &[u8]) {
    assert_eq!(got.len(), want.len(), "{} length", label);
    if got != want {
        for (i, (a, b)) in got.iter().zip(want).enumerate() {
            if a != b {
                panic!(
                    "{} differs at byte {}: got 0x{:02X}, want 0x{:02X}",
                    label, i, a, b
                );
            }
        }
    }
}

#[test]
fn acvp_ml_dsa_44_keygen_tc1() {
    let text = include_str!("kat_keygen_mldsa44_tc1.txt");
    let (xi, pk_exp, sk_exp) = parse_triple(text);
    let (pk, sk) = ml_dsa_44::keygen_internal(&xi).unwrap();
    compare("pk", &pk, &pk_exp);
    compare("sk", &sk, &sk_exp);
}

#[test]
fn acvp_ml_dsa_65_keygen_tc26() {
    let text = include_str!("kat_keygen_mldsa65_tc26.txt");
    let (xi, pk_exp, sk_exp) = parse_triple(text);
    let (pk, sk) = ml_dsa_65::keygen_internal(&xi).unwrap();
    compare("pk", &pk, &pk_exp);
    compare("sk", &sk, &sk_exp);
}

#[test]
fn acvp_ml_dsa_87_keygen_tc51() {
    let text = include_str!("kat_keygen_mldsa87_tc51.txt");
    let (xi, pk_exp, sk_exp) = parse_triple(text);
    let (pk, sk) = ml_dsa_87::keygen_internal(&xi).unwrap();
    compare("pk", &pk, &pk_exp);
    compare("sk", &sk, &sk_exp);
}
