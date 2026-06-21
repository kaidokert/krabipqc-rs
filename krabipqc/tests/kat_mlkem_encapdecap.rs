//! ACVP KAT for ML-KEM encaps_from_seed / decaps across all three
//! parameter sets.
//!
//! Vector source: NIST ACVP-Server
//!   gen-val/json-files/ML-KEM-encapDecap-FIPS203/{prompt,expectedResults}.json
//! Encapsulation groups 1/2/3, decapsulation groups 4/5/6.
//!
//! Each `tests/kat_mlkem{nnn}_encaps_*.txt` is four hex lines: ek, m, c, k.
//! Each `tests/kat_mlkem{nnn}_decaps_*.txt` is three hex lines: dk, c, k.

use krabipqc::{ml_kem_512, ml_kem_768, ml_kem_1024};

fn from_hex(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    hex::decode(&s).expect("bad hex")
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

fn parse_encaps(text: &str) -> (Vec<u8>, [u8; 32], Vec<u8>, Vec<u8>) {
    let mut lines = text.lines().filter(|l| !l.trim().is_empty());
    let ek = from_hex(lines.next().expect("ek"));
    let m_v = from_hex(lines.next().expect("m"));
    let c_exp = from_hex(lines.next().expect("c"));
    let k_exp = from_hex(lines.next().expect("k"));
    assert!(
        lines.next().is_none(),
        "unexpected trailing lines in encaps KAT"
    );
    assert_eq!(m_v.len(), 32);
    let mut m = [0u8; 32];
    m.copy_from_slice(&m_v);
    (ek, m, c_exp, k_exp)
}

fn parse_decaps(text: &str) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let mut lines = text.lines().filter(|l| !l.trim().is_empty());
    let dk = from_hex(lines.next().expect("dk"));
    let ct = from_hex(lines.next().expect("c"));
    let k_exp = from_hex(lines.next().expect("k"));
    assert!(
        lines.next().is_none(),
        "unexpected trailing lines in decaps KAT"
    );
    (dk, ct, k_exp)
}

#[test]
fn acvp_ml_kem_512_encaps_tc1() {
    let (ek_v, m, c_exp, k_exp) = parse_encaps(include_str!("kat_mlkem512_encaps_tc1.txt"));
    let mut ek = [0u8; ml_kem_512::EK_BYTES];
    ek.copy_from_slice(&ek_v);
    let (ss, ct) = ml_kem_512::encaps_from_seed(&ek, &m).unwrap();
    compare("c", &ct, &c_exp);
    compare("k", &ss, &k_exp);
}
#[test]
fn acvp_ml_kem_768_encaps_tc26() {
    let (ek_v, m, c_exp, k_exp) = parse_encaps(include_str!("kat_mlkem768_encaps_tc26.txt"));
    let mut ek = [0u8; ml_kem_768::EK_BYTES];
    ek.copy_from_slice(&ek_v);
    let (ss, ct) = ml_kem_768::encaps_from_seed(&ek, &m).unwrap();
    compare("c", &ct, &c_exp);
    compare("k", &ss, &k_exp);
}
#[test]
fn acvp_ml_kem_1024_encaps_tc51() {
    let (ek_v, m, c_exp, k_exp) = parse_encaps(include_str!("kat_mlkem1024_encaps_tc51.txt"));
    let mut ek = [0u8; ml_kem_1024::EK_BYTES];
    ek.copy_from_slice(&ek_v);
    let (ss, ct) = ml_kem_1024::encaps_from_seed(&ek, &m).unwrap();
    compare("c", &ct, &c_exp);
    compare("k", &ss, &k_exp);
}

#[test]
fn acvp_ml_kem_512_decaps_tc76() {
    let (dk_v, ct_v, k_exp) = parse_decaps(include_str!("kat_mlkem512_decaps_tc76.txt"));
    let mut dk = [0u8; ml_kem_512::DK_BYTES];
    dk.copy_from_slice(&dk_v);
    let mut ct = [0u8; ml_kem_512::CT_BYTES];
    ct.copy_from_slice(&ct_v);
    let ss = ml_kem_512::decaps(&dk, &ct).unwrap();
    compare("k", &ss, &k_exp);
}
#[test]
fn acvp_ml_kem_768_decaps_tc86() {
    let (dk_v, ct_v, k_exp) = parse_decaps(include_str!("kat_mlkem768_decaps_tc86.txt"));
    let mut dk = [0u8; ml_kem_768::DK_BYTES];
    dk.copy_from_slice(&dk_v);
    let mut ct = [0u8; ml_kem_768::CT_BYTES];
    ct.copy_from_slice(&ct_v);
    let ss = ml_kem_768::decaps(&dk, &ct).unwrap();
    compare("k", &ss, &k_exp);
}
#[test]
fn acvp_ml_kem_1024_decaps_tc96() {
    let (dk_v, ct_v, k_exp) = parse_decaps(include_str!("kat_mlkem1024_decaps_tc96.txt"));
    let mut dk = [0u8; ml_kem_1024::DK_BYTES];
    dk.copy_from_slice(&dk_v);
    let mut ct = [0u8; ml_kem_1024::CT_BYTES];
    ct.copy_from_slice(&ct_v);
    let ss = ml_kem_1024::decaps(&dk, &ct).unwrap();
    compare("k", &ss, &k_exp);
}
