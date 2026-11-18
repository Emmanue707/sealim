//! Registry issuer request signing (SPEC section 7.1).

use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};

/// UTF-8 message bytes covered by `Sealim-Signature` on registry POST requests.
pub fn request_message(method: &str, path: &str, timestamp: &str, body: &[u8]) -> Vec<u8> {
    let body_hash = hex::encode(Sha256::digest(body));
    let mut msg =
        Vec::with_capacity(32 + method.len() + path.len() + timestamp.len() + body_hash.len());
    msg.extend_from_slice(b"SEALIM-REQ-v1\n");
    msg.extend_from_slice(method.as_bytes());
    msg.push(b'\n');
    msg.extend_from_slice(path.as_bytes());
    msg.push(b'\n');
    msg.extend_from_slice(timestamp.as_bytes());
    msg.push(b'\n');
    msg.extend_from_slice(body_hash.as_bytes());
    msg
}

/// Sign a registry POST request; returns base64url-no-pad signature.
pub fn sign_request(
    signing_key: &SigningKey,
    method: &str,
    path: &str,
    timestamp: u64,
    body: &[u8],
) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    let ts = timestamp.to_string();
    let msg = request_message(method, path, &ts, body);
    let sig = signing_key.sign(&msg);
    URL_SAFE_NO_PAD.encode(sig.to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sign::test_signing_key_for_tests;
    use base64::Engine;

    #[test]
    fn request_vector_matches_go() {
        let sk = test_signing_key_for_tests();
        let vk = sk.verifying_key();
        let key_id_hex = hex::encode(crate::sign::key_id(&vk));
        let body = format!(
            r#"{{"doc_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","doc_hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","key_id":"{key_id_hex}","issued_at":1735689600}}"#
        );
        let body_bytes = body.as_bytes();
        let ts = 1735689600u64;
        let sig_b64 = sign_request(&sk, "POST", "/v1/documents", ts, body_bytes);
        let ts_str = ts.to_string();
        let msg = request_message("POST", "/v1/documents", &ts_str, body_bytes);
        let sig_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(sig_b64.as_bytes())
            .unwrap();
        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes.try_into().unwrap());
        vk.verify_strict(&msg, &sig)
            .expect("vector signature verifies");
    }
}
