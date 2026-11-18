use std::fs;
use std::io::{Read, Write};
use std::path::Path;
use std::str::FromStr;

use age::armor::{ArmoredReader, ArmoredWriter, Format};
use age::x25519;
use argon2::{Algorithm, Argon2, Params, Version};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use bech32::{ToBase32, Variant};
use ed25519_dalek::SigningKey;
use getrandom::getrandom;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::exit::CliError;

pub const DEFAULT_M_COST_KIB: u32 = 19_456;
pub const DEFAULT_T_COST: u32 = 2;
pub const DEFAULT_P_COST: u32 = 1;

const SECRET_KEY_HRP: &str = "age-secret-key-";

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyFile {
    pub format: String,
    pub version: u32,
    pub kdf: String,
    pub salt: String,
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    pub ciphertext: String,
}

pub struct UnlockedKey {
    pub signing_key: SigningKey,
    pub public_key_b64: String,
    pub key_id_hex: String,
}

pub fn generate_and_write_key(
    path: &Path,
    passphrase: &str,
    force: bool,
) -> Result<UnlockedKey, CliError> {
    if path.exists() && !force {
        return Err(CliError::usage(format!(
            "refusing to overwrite {}; use --force",
            path.display()
        )));
    }

    let mut seed = [0u8; 32];
    getrandom(&mut seed)
        .map_err(|e| CliError::io(format!("random number generator failed: {e}")))?;

    let mut salt = [0u8; 16];
    getrandom(&mut salt)
        .map_err(|e| CliError::io(format!("random number generator failed: {e}")))?;

    let file = encrypt_seed(
        &seed,
        &salt,
        passphrase,
        DEFAULT_M_COST_KIB,
        DEFAULT_T_COST,
        DEFAULT_P_COST,
    )?;

    let json = serde_json::to_string_pretty(&file)
        .map_err(|e| CliError::io(format!("could not serialise key file: {e}")))?;
    write_key_file(path, json.as_bytes())?;

    let unlocked = unlocked_from_seed(&seed)?;
    seed.zeroize();
    Ok(unlocked)
}

pub fn unlock_key(path: &Path, passphrase: &str) -> Result<UnlockedKey, CliError> {
    let text = fs::read_to_string(path)
        .map_err(|e| CliError::io(format!("cannot read key file {}: {e}", path.display())))?;
    let file: KeyFile =
        serde_json::from_str(&text).map_err(|_| CliError::key("invalid key file JSON"))?;
    if file.format != "sealim-key" || file.version != 1 || file.kdf != "argon2id" {
        return Err(CliError::key("unsupported key file format"));
    }

    let salt = decode_b64_16(&file.salt)?;
    let seed = decrypt_seed(&file, &salt, passphrase)?;
    let unlocked = unlocked_from_seed(&seed)?;
    Ok(unlocked)
}

fn encrypt_seed(
    seed: &[u8; 32],
    salt: &[u8; 16],
    passphrase: &str,
    m_cost_kib: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<KeyFile, CliError> {
    let identity = age_identity_from_passphrase(passphrase, salt, m_cost_kib, t_cost, p_cost)?;
    let recipient = identity.to_public();
    let encrypted = age::encrypt(&recipient, seed)
        .map_err(|e| CliError::key(format!("encryption failed: {e}")))?;

    let mut armor = Vec::new();
    {
        let mut writer = ArmoredWriter::wrap_output(&mut armor, Format::AsciiArmor)
            .map_err(|e| CliError::key(format!("armor writer failed: {e}")))?;
        writer
            .write_all(&encrypted)
            .map_err(|e| CliError::key(format!("armor write failed: {e}")))?;
        writer
            .finish()
            .map_err(|e| CliError::key(format!("armor finish failed: {e}")))?;
    }
    let ciphertext = String::from_utf8(armor)
        .map_err(|_| CliError::key("armored ciphertext is not valid UTF-8"))?;

    Ok(KeyFile {
        format: "sealim-key".to_string(),
        version: 1,
        kdf: "argon2id".to_string(),
        salt: URL_SAFE_NO_PAD.encode(salt),
        m_cost_kib,
        t_cost,
        p_cost,
        ciphertext,
    })
}

fn decrypt_seed(file: &KeyFile, salt: &[u8; 16], passphrase: &str) -> Result<[u8; 32], CliError> {
    let identity =
        age_identity_from_passphrase(passphrase, salt, file.m_cost_kib, file.t_cost, file.p_cost)?;

    let mut raw = Vec::new();
    {
        let mut reader = ArmoredReader::new(file.ciphertext.as_bytes());
        reader
            .read_to_end(&mut raw)
            .map_err(|e| CliError::key(format!("could not read ciphertext: {e}")))?;
    }

    let plain = age::decrypt(&identity, &raw)
        .map_err(|_| CliError::key("wrong passphrase or corrupted key file"))?;
    if plain.len() != 32 {
        return Err(CliError::key("decrypted seed has invalid length"));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&plain);
    let mut plain = plain;
    plain.zeroize();
    Ok(seed)
}

fn age_identity_from_passphrase(
    passphrase: &str,
    salt: &[u8; 16],
    m_cost_kib: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<x25519::Identity, CliError> {
    let mut ikm = Zeroizing::new([0u8; 32]);
    derive_ikm(passphrase, salt, m_cost_kib, t_cost, p_cost, &mut ikm)?;

    let sk_base32 = ikm.as_ref().to_base32();
    let mut encoded = bech32::encode(SECRET_KEY_HRP, sk_base32, Variant::Bech32)
        .map_err(|_| CliError::key("bech32 encode failed"))?;
    encoded.make_ascii_uppercase();
    let identity = x25519::Identity::from_str(&encoded)
        .map_err(|_| CliError::key("invalid derived age identity"))?;
    encoded.zeroize();
    Ok(identity)
}

fn derive_ikm(
    passphrase: &str,
    salt: &[u8; 16],
    m_cost_kib: u32,
    t_cost: u32,
    p_cost: u32,
    out: &mut [u8; 32],
) -> Result<(), CliError> {
    let params = Params::new(m_cost_kib, t_cost, p_cost, Some(32))
        .map_err(|e| CliError::key(format!("invalid Argon2 parameters: {e}")))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, out)
        .map_err(|e| CliError::key(format!("Argon2 failed: {e}")))?;
    Ok(())
}

fn write_key_file(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    use std::fs::OpenOptions;
    use std::io::Write as _;

    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts
        .open(path)
        .map_err(|e| CliError::io(format!("cannot write key file {}: {e}", path.display())))?;
    file.write_all(bytes)
        .map_err(|e| CliError::io(format!("cannot write key file {}: {e}", path.display())))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|e| {
                CliError::io(format!("cannot set permissions on {}: {e}", path.display()))
            })?;
    }
    Ok(())
}

fn decode_b64_16(s: &str) -> Result<[u8; 16], CliError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(s.as_bytes())
        .map_err(|_| CliError::key("invalid salt encoding"))?;
    if bytes.len() != 16 {
        return Err(CliError::key("invalid salt length"));
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn unlocked_from_seed(seed: &[u8; 32]) -> Result<UnlockedKey, CliError> {
    let signing_key = SigningKey::from_bytes(seed);
    let vk = signing_key.verifying_key();
    let kid = sealim_core::key_id(&vk);
    Ok(UnlockedKey {
        signing_key,
        public_key_b64: URL_SAFE_NO_PAD.encode(vk.as_bytes()),
        key_id_hex: hex::encode(kid),
    })
}
