#![cfg(feature = "acvp")]
//! ACVP KAT for ML-DSA-{44,65,87} verify_msg_repr (message representative).
//!
//! Vector source: NIST ACVP-Server ML-DSA-sigVer-FIPS204
//!   - group tgId=8  : ML-DSA-44 internal, externalMu=false
//!   - group tgId=10 : ML-DSA-65 internal, externalMu=false
//!   - group tgId=12 : ML-DSA-87 internal, externalMu=false
//!
//! Each shipped JSON contains two PASS and three FAIL cases (smallest
//! message in each category).

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
    pk: String,
    message: String,
    signature: String,
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
    #[serde(rename = "testPassed")]
    test_passed: bool,
}

fn from_hex(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap_or_else(|e| panic!("bad hex: {}", e))
}

fn run_kat<F>(prompt_text: &str, expected_text: &str, pk_bytes: usize, sig_bytes: usize, mut vfy: F)
where
    F: FnMut(&[u8], &[u8], &[u8]) -> bool,
{
    let prompt: PromptFile = serde_json::from_str(prompt_text).expect("prompt json");
    let expected: ExpectedFile = serde_json::from_str(expected_text).expect("expected json");
    assert_eq!(
        expected.test_groups.len(),
        prompt.test_groups.len(),
        "prompt/expected group count mismatch"
    );
    for group in &prompt.test_groups {
        let exp_group = expected
            .test_groups
            .iter()
            .find(|g| g.tg_id == group.tg_id)
            .expect("expected group");
        assert_eq!(
            exp_group.tests.len(),
            group.tests.len(),
            "tgId {}: prompt/expected test count mismatch",
            group.tg_id
        );
        for tc in &group.tests {
            let exp_tc = exp_group
                .tests
                .iter()
                .find(|t| t.tc_id == tc.tc_id)
                .expect("expected test");
            let pk = from_hex(&tc.pk);
            assert_eq!(pk.len(), pk_bytes, "pk len");
            let sig = from_hex(&tc.signature);
            if sig.len() != sig_bytes {
                assert!(
                    !exp_tc.test_passed,
                    "tcId {}: sig len {} != {} but expected to verify",
                    tc.tc_id,
                    sig.len(),
                    sig_bytes,
                );
                continue;
            }
            let msg = from_hex(&tc.message);
            let got = vfy(&pk, &msg, &sig);
            assert_eq!(
                got, exp_tc.test_passed,
                "tcId {} verify mismatch: got {}, want {}",
                tc.tc_id, got, exp_tc.test_passed
            );
        }
    }
}

#[test]
fn acvp_ml_dsa_44_sigver() {
    run_kat(
        include_str!("kat_sigver_mldsa44_prompt.json"),
        include_str!("kat_sigver_mldsa44_expected.json"),
        ml_dsa_44::PK_BYTES,
        ml_dsa_44::SIG_BYTES,
        |pk_bytes, msg, sig_bytes| {
            let mut pk = [0u8; ml_dsa_44::PK_BYTES];
            pk.copy_from_slice(pk_bytes);
            let mut sig = [0u8; ml_dsa_44::SIG_BYTES];
            sig.copy_from_slice(sig_bytes);
            ml_dsa_44::verify_msg_repr(&pk, msg, &sig)
        },
    );
}

#[test]
fn acvp_ml_dsa_65_sigver() {
    run_kat(
        include_str!("kat_sigver_mldsa65_prompt.json"),
        include_str!("kat_sigver_mldsa65_expected.json"),
        ml_dsa_65::PK_BYTES,
        ml_dsa_65::SIG_BYTES,
        |pk_bytes, msg, sig_bytes| {
            let mut pk = [0u8; ml_dsa_65::PK_BYTES];
            pk.copy_from_slice(pk_bytes);
            let mut sig = [0u8; ml_dsa_65::SIG_BYTES];
            sig.copy_from_slice(sig_bytes);
            ml_dsa_65::verify_msg_repr(&pk, msg, &sig)
        },
    );
}

#[test]
fn acvp_ml_dsa_87_sigver() {
    run_kat(
        include_str!("kat_sigver_mldsa87_prompt.json"),
        include_str!("kat_sigver_mldsa87_expected.json"),
        ml_dsa_87::PK_BYTES,
        ml_dsa_87::SIG_BYTES,
        |pk_bytes, msg, sig_bytes| {
            let mut pk = [0u8; ml_dsa_87::PK_BYTES];
            pk.copy_from_slice(pk_bytes);
            let mut sig = [0u8; ml_dsa_87::SIG_BYTES];
            sig.copy_from_slice(sig_bytes);
            ml_dsa_87::verify_msg_repr(&pk, msg, &sig)
        },
    );
}
