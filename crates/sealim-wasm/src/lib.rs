//! WebAssembly bindings for offline Sealim verification.

use js_sys::{Array, Object, Reflect};
use sealim_core::{
    from_qr_text, verify as core_verify, RegistryStatus, TrustStore, Verification, FLAG_REGISTRY,
    PAYLOAD_VERSION,
};
use wasm_bindgen::prelude::*;

/// Returns the supported binary payload version byte.
#[wasm_bindgen]
pub fn payload_version() -> u8 {
    PAYLOAD_VERSION
}

/// When the payload registry flag is set, returns lowercase hex `doc_id` for status lookup.
#[wasm_bindgen]
pub fn registry_doc_id(qr_text: &str) -> Option<String> {
    let payload = from_qr_text(qr_text).ok()?;
    if payload.flags & FLAG_REGISTRY == 0 {
        return None;
    }
    Some(hex::encode(payload.doc_id))
}

fn parse_registry_status(s: &str) -> Option<RegistryStatus> {
    match s {
        "valid" => Some(RegistryStatus::Valid),
        "revoked" => Some(RegistryStatus::Revoked),
        "superseded" => Some(RegistryStatus::Superseded),
        "unreachable" => Some(RegistryStatus::Unreachable),
        _ => None,
    }
}

#[wasm_bindgen(js_name = verify)]
pub fn verify_wasm(
    qr_text: &str,
    file_bytes: Option<Vec<u8>>,
    trust_json: &str,
    registry_status: Option<String>,
) -> Result<JsValue, JsValue> {
    let trust = TrustStore::from_file_json(trust_json)
        .map_err(|_| JsValue::from_str("invalid or unsupported trust file"))?;
    let reg = registry_status.as_deref().and_then(parse_registry_status);
    let v = sealim_core::verify(qr_text, file_bytes.as_deref(), &trust, reg);
    Ok(verification_to_js(&v))
}

pub fn verify_native(
    qr_text: &str,
    file_bytes: Option<&[u8]>,
    trust_json: &str,
    registry_status: Option<&str>,
) -> Result<Verification, &'static str> {
    let trust =
        TrustStore::from_file_json(trust_json).map_err(|_| "invalid or unsupported trust file")?;
    let reg = registry_status.and_then(parse_registry_status);
    Ok(core_verify(qr_text, file_bytes, &trust, reg))
}

fn verification_to_js(v: &Verification) -> JsValue {
    let obj = Object::new();
    let _ = Reflect::set(&obj, &"code".into(), &v.code.as_str().into());
    let issuer = match &v.issuer {
        Some(i) => i.name.clone().into(),
        None => JsValue::NULL,
    };
    let _ = Reflect::set(&obj, &"issuer".into(), &issuer);

    let claims = Array::new();
    for (k, val) in &v.claims {
        let pair = Object::new();
        let _ = Reflect::set(&pair, &"key".into(), &k.clone().into());
        let _ = Reflect::set(&pair, &"value".into(), &val.clone().into());
        claims.push(&pair);
    }
    let _ = Reflect::set(&obj, &"claims".into(), &claims);

    let (doc_id, key_id, doc_hash, issued_at) = match &v.payload {
        Some(p) => (
            hex::encode(p.doc_id).into(),
            hex::encode(p.key_id).into(),
            hex::encode(p.doc_hash).into(),
            JsValue::from(p.issued_at),
        ),
        None => (JsValue::NULL, JsValue::NULL, JsValue::NULL, JsValue::NULL),
    };
    let _ = Reflect::set(&obj, &"doc_id".into(), &doc_id);
    let _ = Reflect::set(&obj, &"key_id".into(), &key_id);
    let _ = Reflect::set(&obj, &"doc_hash".into(), &doc_hash);
    let _ = Reflect::set(&obj, &"issued_at".into(), &issued_at);

    let detail = match &v.detail {
        Some(d) => d.clone().into(),
        None => JsValue::NULL,
    };
    let _ = Reflect::set(&obj, &"detail".into(), &detail);

    obj.into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sealim_core::ResultCode;
    use serde::Deserialize;
    use std::fs;
    use std::path::PathBuf;

    #[derive(Debug, Deserialize)]
    struct VectorFile {
        qr_text: String,
        file_hex: Option<String>,
        expected_code: String,
        trust: serde_json::Value,
    }

    fn vectors_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testvectors")
    }

    fn load_vector(name: &str) -> VectorFile {
        let path = vectors_dir().join(format!("{name}.json"));
        let text = fs::read_to_string(&path).unwrap();
        serde_json::from_str(&text).unwrap()
    }

    fn code_from_str(s: &str) -> ResultCode {
        match s {
            "VALID" => ResultCode::Valid,
            "VALID_CLAIMS_ONLY" => ResultCode::ValidClaimsOnly,
            "STATUS_UNKNOWN" => ResultCode::StatusUnknown,
            "HASH_MISMATCH" => ResultCode::HashMismatch,
            "BAD_SIGNATURE" => ResultCode::BadSignature,
            "UNKNOWN_ISSUER" => ResultCode::UnknownIssuer,
            "KEY_NOT_VALID_AT_ISSUE" => ResultCode::KeyNotValidAtIssue,
            "REVOKED" => ResultCode::Revoked,
            "SUPERSEDED" => ResultCode::Superseded,
            "MALFORMED" => ResultCode::Malformed,
            "UNSUPPORTED_VERSION" => ResultCode::UnsupportedVersion,
            other => panic!("unknown expected_code {other}"),
        }
    }

    fn run_vector(name: &str) -> Verification {
        let v = load_vector(name);
        let trust_json = serde_json::to_string(&v.trust).unwrap();
        let file_bytes = v.file_hex.as_ref().map(|h| hex::decode(h).unwrap());
        let out = verify_native(&v.qr_text, file_bytes.as_deref(), &trust_json, None).unwrap();
        assert_eq!(out.code, code_from_str(&v.expected_code));
        out
    }

    #[test]
    fn valid_with_file_vector() {
        let v = run_vector("valid_with_file");
        assert_eq!(v.code, ResultCode::Valid);
        assert_eq!(v.issuer.unwrap().name, "University of Waghi");
    }

    #[test]
    fn valid_claims_only_vector() {
        let v = run_vector("valid_claims_only");
        assert_eq!(v.code, ResultCode::ValidClaimsOnly);
    }

    #[test]
    fn hash_mismatch_vector() {
        let v = run_vector("hash_mismatch");
        assert_eq!(v.code, ResultCode::HashMismatch);
    }

    #[test]
    fn malformed_qr_vector() {
        let v = run_vector("malformed_prefix");
        assert_eq!(v.code, ResultCode::Malformed);
    }

    #[test]
    fn bad_trust_json() {
        let v = load_vector("valid_with_file");
        let err = verify_native(&v.qr_text, None, "not json", None).unwrap_err();
        assert_eq!(err, "invalid or unsupported trust file");
    }

    #[test]
    fn reexports_payload_version() {
        assert_eq!(payload_version(), 1);
    }
}
