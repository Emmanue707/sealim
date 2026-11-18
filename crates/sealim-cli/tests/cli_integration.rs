use std::fs;
use std::path::PathBuf;

use assert_cmd::cargo::cargo_bin;
use predicates::prelude::*;
use sealim_core::TrustStore;
use serde::Deserialize;
use tempfile::TempDir;

const PASS: &str = "test-only-passphrase";

#[derive(Debug, Deserialize)]
struct VectorFile {
    qr_text: String,
    file_hex: Option<String>,
    expected_code: String,
    trust: serde_json::Value,
}

fn bin() -> assert_cmd::Command {
    assert_cmd::Command::new(cargo_bin!("sealim"))
}

#[test]
fn keygen_writes_encrypted_key_and_trust() {
    let dir = TempDir::new().unwrap();
    let key_path = dir.path().join("issuer.key");
    let trust_path = dir.path().join("trust.json");
    let pass_path = dir.path().join("pass.txt");
    fs::write(&pass_path, PASS).unwrap();

    bin()
        .args([
            "keygen",
            "--name",
            "University of Waghi",
            "--out",
            key_path.to_str().unwrap(),
            "--passphrase-file",
            pass_path.to_str().unwrap(),
            "--trust-out",
            trust_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&key_path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    let trust_text = fs::read_to_string(&trust_path).unwrap();
    TrustStore::from_file_json(&trust_text).unwrap();

    let stdout = bin()
        .args([
            "keygen",
            "--name",
            "University of Waghi",
            "--out",
            dir.path().join("other.key").to_str().unwrap(),
            "--passphrase-file",
            pass_path.to_str().unwrap(),
            "--force",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let out = String::from_utf8_lossy(&stdout);
    assert!(out.contains("key_id:"));
    assert!(out.contains("public_key:"));
    assert!(!out.contains("AGE-SECRET-KEY"));
    assert!(!out.contains("-----BEGIN AGE"));
}

#[test]
fn end_to_end_seal_and_verify() {
    let dir = TempDir::new().unwrap();
    setup_key_and_trust(&dir);

    let doc = dir.path().join("document.bin");
    fs::write(&doc, b"University of Waghi transcript for Jane Kila").unwrap();
    let pass_path = dir.path().join("pass.txt");
    let trust_path = dir.path().join("trust.json");
    let key_path = dir.path().join("issuer.key");

    let seal_out = bin()
        .args([
            "seal",
            "--key",
            key_path.to_str().unwrap(),
            "--passphrase-file",
            pass_path.to_str().unwrap(),
            "--file",
            doc.to_str().unwrap(),
            "--claim",
            "n=Jane Kila",
            "--claim",
            "t=BSc Computing",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let qr = String::from_utf8_lossy(&seal_out).trim().to_string();
    assert!(qr.starts_with("SL1:"));

    bin()
        .args([
            "verify",
            "--qr",
            &qr,
            "--file",
            doc.to_str().unwrap(),
            "--trust",
            trust_path.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("VALID\n"));

    let mut bad = fs::read(&doc).unwrap();
    bad[0] ^= 0x01;
    let bad_doc = dir.path().join("bad.bin");
    fs::write(&bad_doc, &bad).unwrap();

    bin()
        .args([
            "verify",
            "--qr",
            &qr,
            "--file",
            bad_doc.to_str().unwrap(),
            "--trust",
            trust_path.to_str().unwrap(),
        ])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("HASH_MISMATCH"));

    bin()
        .args([
            "verify",
            "--qr",
            &qr,
            "--trust",
            trust_path.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("VALID_CLAIMS_ONLY"));
}

#[test]
fn png_round_trip() {
    let dir = TempDir::new().unwrap();
    setup_key_and_trust(&dir);
    let doc = dir.path().join("document.bin");
    fs::write(&doc, b"University of Waghi transcript for Jane Kila").unwrap();
    let png = dir.path().join("qr.png");

    bin()
        .args([
            "seal",
            "--key",
            dir.path().join("issuer.key").to_str().unwrap(),
            "--passphrase-file",
            dir.path().join("pass.txt").to_str().unwrap(),
            "--file",
            doc.to_str().unwrap(),
            "--claim",
            "n=Jane Kila",
            "--claim",
            "t=BSc Computing",
            "--png",
            png.to_str().unwrap(),
        ])
        .assert()
        .success();

    bin()
        .args([
            "verify",
            "--image",
            png.to_str().unwrap(),
            "--file",
            doc.to_str().unwrap(),
            "--trust",
            dir.path().join("trust.json").to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("VALID"));
}

#[test]
fn testvectors_match_expected() {
    let names = [
        "valid_with_file",
        "valid_claims_only",
        "hash_mismatch",
        "bad_signature",
        "malformed_prefix",
        "wrong_key_in_trust",
    ];
    let vectors_dir = vectors_root();
    for name in names {
        let path = vectors_dir.join(format!("{name}.json"));
        let v: VectorFile = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        let work = TempDir::new().unwrap();
        let trust_path = work.path().join("trust.json");
        fs::write(&trust_path, serde_json::to_string(&v.trust).unwrap()).unwrap();
        let mut cmd = bin();
        cmd.args([
            "verify",
            "--qr",
            &v.qr_text,
            "--trust",
            trust_path.to_str().unwrap(),
        ]);
        if let Some(hex) = &v.file_hex {
            let file_path = work.path().join("document.bin");
            fs::write(&file_path, hex::decode(hex).unwrap()).unwrap();
            cmd.args(["--file", file_path.to_str().unwrap()]);
        }
        let expected_exit = expected_exit_code(&v.expected_code);
        cmd.assert()
            .code(expected_exit)
            .stdout(predicate::str::contains(&v.expected_code));
    }
}

#[test]
fn inspect_valid_and_malformed() {
    let vectors_dir = vectors_root();
    let path = vectors_dir.join("valid_with_file.json");
    let v: VectorFile = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();

    bin()
        .args(["inspect", "--qr", &v.qr_text])
        .assert()
        .success()
        .stdout(predicate::str::contains("doc_id:"));

    bin()
        .args(["inspect", "--qr", "not-a-payload"])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("MALFORMED"));
}

#[test]
fn usage_errors() {
    let dir = TempDir::new().unwrap();
    let key_path = dir.path().join("issuer.key");
    let pass_path = dir.path().join("pass.txt");
    fs::write(&pass_path, PASS).unwrap();

    bin()
        .args([
            "keygen",
            "--name",
            "University of Waghi",
            "--out",
            key_path.to_str().unwrap(),
            "--passphrase-file",
            pass_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    bin()
        .args([
            "keygen",
            "--name",
            "University of Waghi",
            "--out",
            key_path.to_str().unwrap(),
            "--passphrase-file",
            pass_path.to_str().unwrap(),
        ])
        .assert()
        .code(2);

    let stdin_file = tempfile::NamedTempFile::new().unwrap();
    bin()
        .args([
            "keygen",
            "--name",
            "University of Waghi",
            "--out",
            dir.path().join("x.key").to_str().unwrap(),
        ])
        .pipe_stdin(stdin_file.path())
        .unwrap()
        .assert()
        .code(2);

    bin().arg("nosuch").assert().code(2);
}

fn setup_key_and_trust(dir: &TempDir) {
    let key_path = dir.path().join("issuer.key");
    let trust_path = dir.path().join("trust.json");
    let pass_path = dir.path().join("pass.txt");
    fs::write(&pass_path, PASS).unwrap();

    bin()
        .args([
            "keygen",
            "--name",
            "University of Waghi",
            "--out",
            key_path.to_str().unwrap(),
            "--passphrase-file",
            pass_path.to_str().unwrap(),
            "--trust-out",
            trust_path.to_str().unwrap(),
        ])
        .assert()
        .success();
}

fn vectors_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testvectors")
}

fn expected_exit_code(code: &str) -> i32 {
    match code {
        "VALID" | "VALID_CLAIMS_ONLY" => 0,
        _ => 1,
    }
}

#[test]
fn verify_registry_stub_revoked() {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let body = br#"{"doc_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","status":"revoked","reason":"withdrawn","superseded_by":null,"updated_at":"2026-01-01T00:00:00Z"}"#;
    thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let _ = write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(body);
            let mut discard = [0u8; 32];
            let _ = stream.read(&mut discard);
        }
    });

    let v: VectorFile =
        serde_json::from_str(&fs::read_to_string(vectors_root().join("revoked.json")).unwrap())
            .unwrap();

    let dir = TempDir::new().unwrap();
    let trust_path = dir.path().join("trust.json");
    fs::write(&trust_path, serde_json::to_string(&v.trust).unwrap()).unwrap();

    let doc_path = dir.path().join("doc.bin");
    if let Some(h) = &v.file_hex {
        fs::write(&doc_path, hex::decode(h).unwrap()).unwrap();
    }

    bin()
        .args([
            "verify",
            "--qr",
            &v.qr_text,
            "--file",
            doc_path.to_str().unwrap(),
            "--trust",
            trust_path.to_str().unwrap(),
            "--registry",
            &format!("http://{}", addr),
        ])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("REVOKED"));
}
