//! Regenerate JSON files under `testvectors/`. Run with:
//! `cargo test -p sealim-core --test generate_vectors write_vectors -- --ignored --nocapture`

mod vector_common;

use std::fs;
use std::path::PathBuf;

use sealim_core::{from_qr_text, to_qr_text, Claims, ClaimsBuilder, FLAG_CLAIMS_PRESENT};

use vector_common::*;

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testvectors")
}

fn fuzz_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fuzz/corpus")
}

fn write_fuzz_corpus(qr_valid: &str) {
    let seeds = [
        ("decode_qr_text", qr_valid.as_bytes()),
        ("decode_qr_text", b"SL1:%%%NOTBASE45" as &[u8]),
        (
            "parse_payload",
            &from_qr_text(qr_valid).unwrap().to_bytes().unwrap(),
        ),
        ("parse_payload", &[0x01, 0x00]),
        (
            "parse_claims",
            b"d=2026-01-15\x1Fn=Jane Kila\x1Ft=BSc Computing",
        ),
        ("parse_claims", b"n=bad\x07"),
    ];
    for (kind, data) in seeds {
        let dir = fuzz_dir().join(kind);
        fs::create_dir_all(&dir).unwrap();
        let name = format!("seed_{:02x}", data.first().copied().unwrap_or(0));
        fs::write(dir.join(name), data).unwrap();
    }
}

fn write_case(name: &str, body: serde_json::Value) {
    let path = vectors_dir().join(format!("{name}.json"));
    fs::write(path, serde_json::to_string_pretty(&body).unwrap() + "\n").unwrap();
}

fn case(
    description: &str,
    qr_text: &str,
    trust: serde_json::Value,
    file_hex: Option<&str>,
    registry_status: Option<&str>,
    expected_code: &str,
    expected_claims: serde_json::Value,
) -> serde_json::Value {
    let sk = test_signing_key();
    serde_json::json!({
        "description": description,
        "seed_hex": seed_hex(),
        "public_key_b64url": public_key_b64url(&sk),
        "trust": trust,
        "qr_text": qr_text,
        "file_hex": file_hex,
        "registry_status": registry_status,
        "expected_code": expected_code,
        "expected_claims": expected_claims,
    })
}

#[test]
#[ignore]
fn write_vectors() {
    let sk = test_signing_key();
    let trust = trust_json_for(&sk, "2020-01-01T00:00:00Z", None);
    let claims_json = serde_json::json!([
        ["d", "2026-01-15"],
        ["n", "Jane Kila"],
        ["t", "BSc Computing"]
    ]);

    let qr_valid = qr_for(&sk, standard_claims(), FLAG_CLAIMS_PRESENT);
    write_case(
        "valid_with_file",
        case(
            "Valid signature and matching file hash",
            &qr_valid,
            trust.clone(),
            Some(&hex::encode(FILE_BYTES)),
            None,
            "VALID",
            claims_json.clone(),
        ),
    );

    write_case(
        "valid_claims_only",
        case(
            "Valid signature without a supplied file",
            &qr_valid,
            trust.clone(),
            None,
            None,
            "VALID_CLAIMS_ONLY",
            claims_json.clone(),
        ),
    );

    let qr_no_claims = qr_for(&sk, Claims::new(), 0);
    write_case(
        "no_claims_valid",
        case(
            "Valid signature, no visible claims, with file",
            &qr_no_claims,
            trust.clone(),
            Some(&hex::encode(FILE_BYTES)),
            None,
            "VALID",
            serde_json::json!([]),
        ),
    );

    write_case(
        "hash_mismatch",
        case(
            "Wrong file bytes",
            &qr_valid,
            trust.clone(),
            Some("deadbeef"),
            None,
            "HASH_MISMATCH",
            claims_json.clone(),
        ),
    );

    let mut bad = seal_with(
        &sk,
        standard_claims(),
        FLAG_CLAIMS_PRESENT,
        Some(FILE_BYTES),
    );
    bad.signature[0] ^= 0xff;
    let qr_bad = to_qr_text(&bad).unwrap();
    write_case(
        "bad_signature",
        case(
            "Flipped signature byte",
            &qr_bad,
            trust.clone(),
            Some(&hex::encode(FILE_BYTES)),
            None,
            "BAD_SIGNATURE",
            serde_json::json!([]),
        ),
    );

    let empty_trust = serde_json::json!({
        "format": "sealim-trust",
        "version": 1,
        "updated_at": "2026-01-01T00:00:00Z",
        "issuers": []
    });
    write_case(
        "wrong_key_in_trust",
        case(
            "Issuer key_id not listed in trust file",
            &qr_valid,
            empty_trust,
            Some(&hex::encode(FILE_BYTES)),
            None,
            "UNKNOWN_ISSUER",
            serde_json::json!([]),
        ),
    );

    let future_trust = trust_json_for(&sk, "2035-01-01T00:00:00Z", None);
    write_case(
        "key_not_valid_at_issue",
        case(
            "issued_at before issuer valid_from",
            &qr_valid,
            future_trust,
            Some(&hex::encode(FILE_BYTES)),
            None,
            "KEY_NOT_VALID_AT_ISSUE",
            claims_json.clone(),
        ),
    );

    let qr_reg = qr_for(&sk, standard_claims(), FLAG_BOTH);
    write_case(
        "revoked",
        case(
            "Registry reports revoked",
            &qr_reg,
            trust.clone(),
            Some(&hex::encode(FILE_BYTES)),
            Some("revoked"),
            "REVOKED",
            claims_json.clone(),
        ),
    );
    write_case(
        "superseded",
        case(
            "Registry reports superseded",
            &qr_reg,
            trust.clone(),
            Some(&hex::encode(FILE_BYTES)),
            Some("superseded"),
            "SUPERSEDED",
            claims_json.clone(),
        ),
    );
    write_case(
        "status_unknown",
        case(
            "Registry flag set but registry unreachable",
            &qr_reg,
            trust.clone(),
            Some(&hex::encode(FILE_BYTES)),
            Some("unreachable"),
            "STATUS_UNKNOWN",
            claims_json.clone(),
        ),
    );

    write_case(
        "malformed_prefix",
        case(
            "Missing SL1: prefix",
            &qr_valid.replacen("SL1:", "SL9:", 1),
            trust.clone(),
            None,
            None,
            "MALFORMED",
            serde_json::json!([]),
        ),
    );
    write_case(
        "malformed_base45",
        case(
            "Invalid base45 alphabet",
            "SL1:???",
            trust.clone(),
            None,
            None,
            "MALFORMED",
            serde_json::json!([]),
        ),
    );

    let short = qr_valid[..qr_valid.len().saturating_sub(8)].to_string();
    write_case(
        "truncated",
        case(
            "Truncated QR text",
            &short,
            trust.clone(),
            None,
            None,
            "MALFORMED",
            serde_json::json!([]),
        ),
    );

    let unsorted_claims = b"n=Jane Kila\x1Fd=2026-01-15\x1Ft=BSc Computing";
    let mut bytes = unsigned_prefix(&sk, FLAG_CLAIMS_PRESENT, unsorted_claims);
    bytes.extend_from_slice(&sign_bytes(&sk, &bytes));
    write_case(
        "claims_unsorted",
        case(
            "Claims records not sorted by key",
            &encode_qr_raw(&bytes),
            trust.clone(),
            None,
            None,
            "MALFORMED",
            serde_json::json!([]),
        ),
    );

    let control_claims = b"d=2026-01-15\x1Fn=Jane\x07\x1Ft=BSc";
    let mut bytes = unsigned_prefix(&sk, FLAG_CLAIMS_PRESENT, control_claims);
    bytes.extend_from_slice(&sign_bytes(&sk, &bytes));
    write_case(
        "claims_control_char",
        case(
            "Control character in claim value",
            &encode_qr_raw(&bytes),
            trust.clone(),
            None,
            None,
            "MALFORMED",
            serde_json::json!([]),
        ),
    );

    let long_claims = vec![b'a'; 161];
    let mut bytes = unsigned_prefix(&sk, FLAG_CLAIMS_PRESENT, &long_claims);
    bytes.extend_from_slice(&[0u8; 64]);
    write_case(
        "claims_too_long",
        case(
            "claims_len over 160 bytes",
            &encode_qr_raw(&bytes),
            trust.clone(),
            None,
            None,
            "MALFORMED",
            serde_json::json!([]),
        ),
    );

    let mut bytes = unsigned_prefix(
        &sk,
        FLAG_CLAIMS_PRESENT | 0x04,
        standard_claims().encode_canonical().unwrap().as_slice(),
    );
    bytes[1] = FLAG_CLAIMS_PRESENT | 0x04;
    bytes.extend_from_slice(&sign_bytes(&sk, &bytes));
    write_case(
        "reserved_flag_bit",
        case(
            "Non-zero reserved flag bits",
            &encode_qr_raw(&bytes),
            trust.clone(),
            None,
            None,
            "MALFORMED",
            serde_json::json!([]),
        ),
    );

    let mut bytes = unsigned_prefix(&sk, 0, &[]);
    bytes[0] = 0x02;
    bytes.extend_from_slice(&[0u8; 64]);
    write_case(
        "unsupported_version",
        case(
            "Unknown payload version byte",
            &encode_qr_raw(&bytes),
            trust.clone(),
            None,
            None,
            "UNSUPPORTED_VERSION",
            serde_json::json!([]),
        ),
    );

    let (max_claims, pad) = max_claims_at_160_bytes();
    let payload = seal_with(&sk, max_claims, FLAG_CLAIMS_PRESENT, Some(FILE_BYTES));
    assert_eq!(payload.to_bytes().unwrap().len(), 292);
    let qr_max = to_qr_text(&payload).unwrap();
    write_fuzz_corpus(&qr_valid);

    write_case(
        "max_size_payload",
        case(
            "292-byte payload at maximum claims length",
            &qr_max,
            trust,
            Some(&hex::encode(FILE_BYTES)),
            None,
            "VALID",
            serde_json::json!([["n", "Jane Kila"], ["t", pad]]),
        ),
    );
}

fn max_claims_at_160_bytes() -> (Claims, String) {
    let mut pad_len = 145usize;
    loop {
        let mut b = ClaimsBuilder::new();
        b.insert("n", "Jane Kila").unwrap();
        let pad = "x".repeat(pad_len);
        match b.insert("t", &pad) {
            Ok(()) => {}
            Err(_) => {
                pad_len = pad_len.saturating_sub(1);
                continue;
            }
        }
        let bytes = b.encode().unwrap();
        if bytes.len() == 160 {
            return (b.build().unwrap(), pad);
        }
        if bytes.len() > 160 {
            pad_len -= 1;
        } else {
            pad_len += 1;
        }
    }
}
