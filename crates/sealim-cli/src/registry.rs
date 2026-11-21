use std::time::Duration;

use sealim_core::{from_qr_text, RegistryStatus, FLAG_REGISTRY};

const MAX_BODY: usize = 4096;

pub fn registry_status_for_qr(qr_text: &str, base_url: Option<&str>) -> Option<RegistryStatus> {
    let payload = from_qr_text(qr_text).ok()?;
    if payload.flags & FLAG_REGISTRY == 0 {
        return None;
    }
    let Some(url) = base_url.filter(|s| !s.is_empty()) else {
        return Some(RegistryStatus::Unreachable);
    };
    let doc_id = hex::encode(payload.doc_id);
    query_document_status(url, &doc_id)
}

fn query_document_status(base: &str, doc_id_hex: &str) -> Option<RegistryStatus> {
    let url = join_url(base, doc_id_hex)?;
    let response = ureq::get(&url).timeout(Duration::from_secs(5)).call();
    let response = match response {
        Ok(r) => r,
        Err(_) => return Some(RegistryStatus::Unreachable),
    };
    if response.status() != 200 {
        return Some(RegistryStatus::Unreachable);
    }
    let mut body = Vec::new();
    let mut reader = response.into_reader();
    let mut buf = [0u8; 512];
    while body.len() < MAX_BODY {
        let n = match std::io::Read::read(&mut reader, &mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => return Some(RegistryStatus::Unreachable),
        };
        body.extend_from_slice(&buf[..n]);
    }
    let v: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return Some(RegistryStatus::Unreachable),
    };
    let status = v.get("status").and_then(|s| s.as_str())?;
    match status {
        "valid" => Some(RegistryStatus::Valid),
        "revoked" => Some(RegistryStatus::Revoked),
        "superseded" => Some(RegistryStatus::Superseded),
        _ => Some(RegistryStatus::Unreachable),
    }
}

fn join_url(base: &str, doc_id_hex: &str) -> Option<String> {
    let base = base.trim_end_matches('/');
    if base.is_empty() || !doc_id_hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some(format!("{base}/v1/documents/{doc_id_hex}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn maps_registry_json_status() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let body = r#"{"doc_id":"aa","status":"revoked","reason":"withdrawn","superseded_by":null,"updated_at":"2026-01-01T00:00:00Z"}"#;
        let base = format!("http://{}", addr);
        let client = thread::spawn(move || {
            query_document_status(&base, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        });
        let (mut stream, _) = listener.accept().expect("stub accept");
        let _ = write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        let mut discard = [0u8; 64];
        let _ = stream.read(&mut discard);
        let st = client.join().expect("client thread").expect("registry status");
        assert_eq!(st, RegistryStatus::Revoked);
    }
}
