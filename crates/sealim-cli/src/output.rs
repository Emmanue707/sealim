use std::io::{self, Write};

use sealim_core::{ResultCode, Verification};

use crate::exit::CliError;

pub fn print_verification(v: &Verification, json: bool) -> Result<(), CliError> {
    if json {
        print_verification_json(v)?;
    } else {
        print_verification_text(v)?;
    }
    Ok(())
}

fn print_verification_text(v: &Verification) -> Result<(), CliError> {
    let mut out = io::stdout();
    writeln!(out, "{}", v.code.as_str()).map_err(|e| CliError::io(e.to_string()))?;

    // SPEC section 6: show issuer name and claims from step 7 onwards.
    let show_detail = matches!(
        v.code,
        ResultCode::Valid
            | ResultCode::ValidClaimsOnly
            | ResultCode::StatusUnknown
            | ResultCode::HashMismatch
            | ResultCode::KeyNotValidAtIssue
            | ResultCode::Revoked
            | ResultCode::Superseded
    );

    if show_detail {
        if let Some(issuer) = &v.issuer {
            writeln!(out, "issuer: {}", issuer.name).map_err(|e| CliError::io(e.to_string()))?;
        }
        for (k, val) in &v.claims {
            writeln!(out, "claim {k}: {val}").map_err(|e| CliError::io(e.to_string()))?;
        }
    }

    if let Some(detail) = &v.detail {
        writeln!(out, "detail: {detail}").map_err(|e| CliError::io(e.to_string()))?;
    }

    Ok(())
}

fn print_verification_json(v: &Verification) -> Result<(), CliError> {
    use serde_json::json;

    let (doc_id, key_id, issued_at) = match &v.payload {
        Some(p) => (
            Some(hex::encode(p.doc_id)),
            Some(hex::encode(p.key_id)),
            Some(p.issued_at),
        ),
        None => (None, None, None),
    };

    let claims: Vec<[String; 2]> = v
        .claims
        .iter()
        .map(|(k, val)| [k.clone(), val.clone()])
        .collect();

    let obj = json!({
        "code": v.code.as_str(),
        "issuer": v.issuer.as_ref().map(|i| &i.name),
        "claims": claims,
        "doc_id": doc_id,
        "key_id": key_id,
        "issued_at": issued_at,
        "detail": v.detail,
    });

    let mut out = io::stdout();
    writeln!(out, "{}", serde_json::to_string(&obj).unwrap())
        .map_err(|e| CliError::io(e.to_string()))?;
    Ok(())
}

pub fn print_inspection(payload: &sealim_core::Payload, json: bool) -> Result<(), CliError> {
    if json {
        print_inspect_json(payload)
    } else {
        print_inspect_text(payload)
    }
}

fn print_inspect_text(p: &sealim_core::Payload) -> Result<(), CliError> {
    let mut out = io::stdout();
    writeln!(out, "version: {}", p.version).map_err(|e| CliError::io(e.to_string()))?;
    writeln!(out, "flags: 0x{:02x}", p.flags).map_err(|e| CliError::io(e.to_string()))?;
    writeln!(out, "key_id: {}", hex::encode(p.key_id)).map_err(|e| CliError::io(e.to_string()))?;
    writeln!(out, "doc_id: {}", hex::encode(p.doc_id)).map_err(|e| CliError::io(e.to_string()))?;
    writeln!(out, "issued_at: {}", p.issued_at).map_err(|e| CliError::io(e.to_string()))?;
    writeln!(out, "doc_hash: {}", hex::encode(p.doc_hash))
        .map_err(|e| CliError::io(e.to_string()))?;
    writeln!(out, "signature: {}", hex::encode(p.signature))
        .map_err(|e| CliError::io(e.to_string()))?;
    for (k, v) in p.claims.pairs() {
        writeln!(out, "claim {k}: {v}").map_err(|e| CliError::io(e.to_string()))?;
    }
    Ok(())
}

fn print_inspect_json(p: &sealim_core::Payload) -> Result<(), CliError> {
    use serde_json::json;
    let claims: Vec<[String; 2]> = p
        .claims
        .pairs()
        .into_iter()
        .map(|(k, v)| [k.to_string(), v.to_string()])
        .collect();
    let obj = json!({
        "version": p.version,
        "flags": p.flags,
        "key_id": hex::encode(p.key_id),
        "doc_id": hex::encode(p.doc_id),
        "issued_at": p.issued_at,
        "doc_hash": hex::encode(p.doc_hash),
        "signature": hex::encode(p.signature),
        "claims": claims,
    });
    let mut out = io::stdout();
    writeln!(out, "{}", serde_json::to_string(&obj).unwrap())
        .map_err(|e| CliError::io(e.to_string()))?;
    Ok(())
}
