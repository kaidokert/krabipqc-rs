//! ACVP KAT for ML-KEM-512/768/1024 KeyGen_internal.
//!
//! Vector source: NIST ACVP-Server
//!   gen-val/json-files/ML-KEM-keyGen-FIPS203/{prompt,expectedResults}.json
//! Group 1 (ML-KEM-512) tcId=1; Group 2 (ML-KEM-768) tcId=26; Group 3
//! (ML-KEM-1024) tcId=51.
//!
//! Each `tests/kat_mlkem{nnn}_keygen_tc{N}.txt` file is four hex lines:
//!   z (32 bytes), d (32 bytes), expected ek, expected dk.

use krabipqc::{ml_kem_512, ml_kem_768, ml_kem_1024};

fn from_hex(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    hex::decode(&s).expect("bad hex")
}

fn parse_quad(text: &str) -> ([u8; 32], [u8; 32], Vec<u8>, Vec<u8>) {
    let mut lines = text.lines().filter(|l| !l.trim().is_empty());
    let z = from_hex(lines.next().expect("z"));
    let d = from_hex(lines.next().expect("d"));
    let ek = from_hex(lines.next().expect("ek"));
    let dk = from_hex(lines.next().expect("dk"));
    assert!(
        lines.next().is_none(),
        "unexpected trailing lines in keygen KAT"
    );
    assert_eq!(z.len(), 32);
    assert_eq!(d.len(), 32);
    let mut z_arr = [0u8; 32];
    let mut d_arr = [0u8; 32];
    z_arr.copy_from_slice(&z);
    d_arr.copy_from_slice(&d);
    (z_arr, d_arr, ek, dk)
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
fn acvp_ml_kem_512_keygen_tc1() {
    let (z, d, ek_exp, dk_exp) = parse_quad(include_str!("kat_mlkem512_keygen_tc1.txt"));
    let (ek, dk) = ml_kem_512::keygen_internal(&d, &z).unwrap();
    compare("ek", &ek, &ek_exp);
    compare("dk", &dk, &dk_exp);
}

#[test]
fn acvp_ml_kem_768_keygen_tc26() {
    let (z, d, ek_exp, dk_exp) = parse_quad(include_str!("kat_mlkem768_keygen_tc26.txt"));
    let (ek, dk) = ml_kem_768::keygen_internal(&d, &z).unwrap();
    compare("ek", &ek, &ek_exp);
    compare("dk", &dk, &dk_exp);
}

#[test]
fn acvp_ml_kem_1024_keygen_tc51() {
    let (z, d, ek_exp, dk_exp) = parse_quad(include_str!("kat_mlkem1024_keygen_tc51.txt"));
    let (ek, dk) = ml_kem_1024::keygen_internal(&d, &z).unwrap();
    compare("ek", &ek, &ek_exp);
    compare("dk", &dk, &dk_exp);
}
