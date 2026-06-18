//! ACVP KAT for ML-DSA-{44,65,87} Sign_internal.
//!
//! Vector source: NIST ACVP-Server ML-DSA-sigGen-FIPS204
//!   - group tgId=8  : ML-DSA-44 internal, deterministic, externalMu=false
//!   - group tgId=10 : ML-DSA-65 internal, deterministic, externalMu=false
//!   - group tgId=12 : ML-DSA-87 internal, deterministic, externalMu=false
//!
//! Each shipped JSON contains the three smallest-message tests from the
//! corresponding group.

use krabipqc::{ml_dsa_44, ml_dsa_65, ml_dsa_87};
use serde::Deserialize;

#[derive(Deserialize)]
struct PromptFile {
    #[serde(rename = "testGroups")]
    test_groups: Vec<PromptGroup>,
}
#[derive(Deserialize)]
struct PromptGroup {
    #[serde(rename = "tgId")]
    tg_id: u32,
    tests: Vec<PromptTest>,
}
#[derive(Deserialize)]
struct PromptTest {
    #[serde(rename = "tcId")]
    tc_id: u32,
    message: String,
    sk: String,
}
#[derive(Deserialize)]
struct ExpectedFile {
    #[serde(rename = "testGroups")]
    test_groups: Vec<ExpectedGroup>,
}
#[derive(Deserialize)]
struct ExpectedGroup {
    #[serde(rename = "tgId")]
    tg_id: u32,
    tests: Vec<ExpectedTest>,
}
#[derive(Deserialize)]
struct ExpectedTest {
    #[serde(rename = "tcId")]
    tc_id: u32,
    signature: String,
}

fn from_hex(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap_or_else(|e| panic!("bad hex: {}", e))
}

fn run_kat<F>(
    prompt_text: &str,
    expected_text: &str,
    sk_bytes: usize,
    sig_bytes: usize,
    mut sign: F,
) where
    F: FnMut(&[u8], &[u8]) -> Vec<u8>,
{
    let prompt: PromptFile = serde_json::from_str(prompt_text).expect("prompt json");
    let expected: ExpectedFile = serde_json::from_str(expected_text).expect("expected json");
    for group in &prompt.test_groups {
        let exp_group = expected
            .test_groups
            .iter()
            .find(|g| g.tg_id == group.tg_id)
            .expect("expected group");
        for tc in &group.tests {
            let exp_tc = exp_group
                .tests
                .iter()
                .find(|t| t.tc_id == tc.tc_id)
                .expect("expected test");
            let sk = from_hex(&tc.sk);
            assert_eq!(sk.len(), sk_bytes, "sk len");
            let msg = from_hex(&tc.message);
            let want = from_hex(&exp_tc.signature);
            assert_eq!(want.len(), sig_bytes, "sig len");
            let got = sign(&sk, &msg);
            assert_eq!(got.len(), want.len(), "tcId {} sig length", tc.tc_id);
            if got != want {
                for (i, (a, b)) in got.iter().zip(&want).enumerate() {
                    if a != b {
                        panic!(
                            "tcId {} sig byte {}: got 0x{:02X}, want 0x{:02X}",
                            tc.tc_id, i, a, b
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn acvp_ml_dsa_44_siggen_internal_deterministic() {
    run_kat(
        include_str!("kat_siggen_mldsa44_prompt.json"),
        include_str!("kat_siggen_mldsa44_expected.json"),
        ml_dsa_44::SK_BYTES,
        ml_dsa_44::SIG_BYTES,
        |sk_bytes, msg| {
            let mut sk = [0u8; ml_dsa_44::SK_BYTES];
            sk.copy_from_slice(sk_bytes);
            ml_dsa_44::sign_internal(&sk, msg, &[0u8; 32])
                .unwrap()
                .to_vec()
        },
    );
}

#[test]
fn acvp_ml_dsa_65_siggen_internal_deterministic() {
    run_kat(
        include_str!("kat_siggen_mldsa65_prompt.json"),
        include_str!("kat_siggen_mldsa65_expected.json"),
        ml_dsa_65::SK_BYTES,
        ml_dsa_65::SIG_BYTES,
        |sk_bytes, msg| {
            let mut sk = [0u8; ml_dsa_65::SK_BYTES];
            sk.copy_from_slice(sk_bytes);
            ml_dsa_65::sign_internal(&sk, msg, &[0u8; 32])
                .unwrap()
                .to_vec()
        },
    );
}

#[test]
fn acvp_ml_dsa_87_siggen_internal_deterministic() {
    run_kat(
        include_str!("kat_siggen_mldsa87_prompt.json"),
        include_str!("kat_siggen_mldsa87_expected.json"),
        ml_dsa_87::SK_BYTES,
        ml_dsa_87::SIG_BYTES,
        |sk_bytes, msg| {
            let mut sk = [0u8; ml_dsa_87::SK_BYTES];
            sk.copy_from_slice(sk_bytes);
            ml_dsa_87::sign_internal(&sk, msg, &[0u8; 32])
                .unwrap()
                .to_vec()
        },
    );
}
