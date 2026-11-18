//! Regenerate demo fixtures (TEST KEY ONLY — seed 0x01..0x20).

use std::fs;
use std::path::PathBuf;

use base64::Engine;
use image::Luma;
use qrcode::QrCode;
use sealim_core::{
    key_id, seal, test_signing_key_for_tests, to_qr_text, ClaimsBuilder, FLAG_CLAIMS_PRESENT,
};
use serde_json::json;

const ISSUED_AT: u64 = 1_768_435_200; // 2026-01-15T00:00:00Z
const DOC_ID: [u8; 16] = [
    0x20, 0x26, 0x01, 0x15, 0xaa, 0xbb, 0xcc, 0xdd, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
];

fn main() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let sk = test_signing_key_for_tests();
    let transcript = r#"University of Waghi — OFFICIAL TRANSCRIPT (DEMO)
==================================================

Holder: Jane Kila
Award: BSc Computing
Date: 2026-01-15

This document is synthetic fixture data for Sealim demos.
The signing key is a public test vector only (seed 0x01..0x20).
Do not use for real credentials.
"#;
    fs::write(dir.join("transcript.txt"), transcript).expect("write transcript");

    let mut claims = ClaimsBuilder::new();
    claims.insert("d", "2026-01-15").unwrap();
    claims.insert("n", "Jane Kila").unwrap();
    claims.insert("t", "BSc Computing").unwrap();
    let claims = claims.build().unwrap();

    let payload = seal(
        &sk,
        Some(transcript.as_bytes()),
        None,
        claims,
        DOC_ID,
        ISSUED_AT,
        FLAG_CLAIMS_PRESENT,
    )
    .expect("seal");
    let qr = to_qr_text(&payload).expect("qr text");

    fs::write(dir.join("qr.txt"), &qr).expect("write qr.txt");

    let code = QrCode::new(qr.as_bytes()).expect("qr encode");
    let img = code.render::<Luma<u8>>().min_dimensions(256, 256).build();
    img.save(dir.join("qr.png")).expect("write qr.png");

    let kid = key_id(&sk.verifying_key());
    let pk = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sk.verifying_key().as_bytes());
    let trust = json!({
        "format": "sealim-trust",
        "version": 1,
        "updated_at": "2026-01-01T00:00:00Z",
        "issuers": [{
            "name": "University of Waghi",
            "key_id": hex::encode(kid),
            "public_key": pk,
            "valid_from": "2020-01-01T00:00:00Z",
            "valid_until": null
        }]
    });
    fs::write(
        dir.join("trust.json"),
        serde_json::to_string_pretty(&trust).unwrap() + "\n",
    )
    .expect("write trust.json");
}