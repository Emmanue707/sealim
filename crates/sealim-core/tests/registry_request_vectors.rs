use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::Signature;
use sealim_core::{request_message, sign_request, test_signing_key_for_tests};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;

#[derive(Deserialize)]
struct RegistryRequestVector {
    method: String,
    path: String,
    timestamp: u64,
    body: String,
    public_key_b64url: String,
    signature_b64url: String,
    body_sha256_hex: String,
    message_hex: String,
}

fn load(name: &str) -> RegistryRequestVector {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testvectors")
        .join(name);
    let json = fs::read_to_string(path).expect("vector file");
    serde_json::from_str(&json).unwrap()
}

#[test]
fn registry_request_valid_vector() {
    let v = load("registry_request_valid.json");
    let body = v.body.as_bytes();
    let digest = hex::encode(Sha256::digest(body));
    assert_eq!(digest, v.body_sha256_hex);

    let ts = v.timestamp.to_string();
    let msg = request_message(&v.method, &v.path, &ts, body);
    assert_eq!(hex::encode(&msg), v.message_hex);

    let pk = URL_SAFE_NO_PAD
        .decode(v.public_key_b64url.as_bytes())
        .unwrap();
    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&pk);
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&pk_arr).unwrap();

    let sig_bytes = URL_SAFE_NO_PAD
        .decode(v.signature_b64url.as_bytes())
        .unwrap();
    let sig = Signature::from_bytes(&sig_bytes.try_into().unwrap());
    vk.verify_strict(&msg, &sig)
        .expect("valid vector signature");

    let sk = test_signing_key_for_tests();
    let ours = sign_request(&sk, &v.method, &v.path, v.timestamp, body);
    assert_eq!(ours, v.signature_b64url);
}

#[test]
fn registry_request_bad_signature_vector() {
    let v = load("registry_request_bad_signature.json");
    let body = v.body.as_bytes();
    let ts = v.timestamp.to_string();
    let msg = request_message(&v.method, &v.path, &ts, body);
    let pk = URL_SAFE_NO_PAD
        .decode(v.public_key_b64url.as_bytes())
        .unwrap();
    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&pk);
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&pk_arr).unwrap();
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(v.signature_b64url.as_bytes())
        .unwrap();
    let sig = Signature::from_bytes(&sig_bytes.try_into().unwrap());
    assert!(vk.verify_strict(&msg, &sig).is_err());
}
