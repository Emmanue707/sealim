mod vector_common;

use std::fs;
use std::path::PathBuf;

use sealim_core::{verify, TrustStore};
use serde::Deserialize;

use vector_common::*;

#[derive(Debug, Deserialize)]
struct VectorFile {
    description: String,
    trust: serde_json::Value,
    qr_text: String,
    file_hex: Option<String>,
    registry_status: Option<serde_json::Value>,
    expected_code: String,
    expected_claims: Vec<(String, String)>,
}

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testvectors")
}

#[test]
fn load_all_test_vectors() {
    let dir = vectors_dir();
    let mut count = 0usize;
    for entry in fs::read_dir(&dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let text = fs::read_to_string(&path).unwrap();
        let v: VectorFile = serde_json::from_str(&text).unwrap();
        let trust = TrustStore::from_file_json(&serde_json::to_string(&v.trust).unwrap()).unwrap();
        let file_bytes = v.file_hex.as_ref().map(|h| hex::decode(h).unwrap());
        let reg = v.registry_status.as_ref().and_then(registry_from_json);
        let result = verify(&v.qr_text, file_bytes.as_deref(), &trust, reg);
        assert_eq!(
            result.code,
            code_from_str(&v.expected_code),
            "{} ({})",
            path.display(),
            v.description
        );
        if !v.expected_claims.is_empty() {
            assert_eq!(result.claims, v.expected_claims);
        }
        count += 1;
    }
    assert!(
        count >= 19,
        "expected at least 19 vector files, got {count}"
    );
}
