use std::{fs, io, path::{Path, PathBuf}};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signer, SigningKey};

use crate::transport::ClientIdentity;

const RAW_KEY_BYTES: usize = 32;

pub fn load_signing_key(path: &Path) -> io::Result<SigningKey> {
    let bytes = fs::read(path).map_err(|error| {
        io::Error::new(error.kind(), format!("unable to read authentication key {}: {error}", path.display()))
    })?;
    parse_signing_key(&bytes).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "authentication key must be a 32-byte seed or 64 hexadecimal characters"))
}

fn parse_signing_key(bytes: &[u8]) -> Option<SigningKey> {
    if bytes.len() == RAW_KEY_BYTES {
        return bytes.try_into().ok().map(|seed: [u8; RAW_KEY_BYTES]| SigningKey::from_bytes(&seed));
    }
    let text = std::str::from_utf8(bytes).ok()?.trim();
    if text.len() != RAW_KEY_BYTES * 2 {
        return None;
    }
    let mut seed = [0u8; RAW_KEY_BYTES];
    for (index, pair) in text.as_bytes().chunks_exact(2).enumerate() {
        seed[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    Some(SigningKey::from_bytes(&seed))
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

pub fn sign_challenge(identity: &ClientIdentity<'_>, nonce: &[u8], key: &SigningKey) -> String {
    STANDARD.encode(key.sign(&ztsec_protocol::auth_message(identity.fingerprint, nonce)).to_bytes())
}

pub fn public_key_hex(key: &SigningKey) -> String {
    key.verifying_key().to_bytes().iter().map(|b| format!("{b:02x}")).collect()
}

pub fn default_key_path() -> PathBuf {
    if let Some(path) = std::env::var_os("ZTSEC_AUTH_KEY_FILE") {
        PathBuf::from(path)
    } else if let Some(home) = std::env::var_os("USERPROFILE") {
        PathBuf::from(home).join(".ztsec").join("agent-ed25519.key")
    } else {
        PathBuf::from("agent-ed25519.key")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_raw_seed_and_hex_seed() {
        let raw = [7u8; 32];
        let a = parse_signing_key(&raw).unwrap();
        let hex = raw.iter().map(|b| format!("{b:02x}")).collect::<String>();
        let b = parse_signing_key(hex.as_bytes()).unwrap();
        assert_eq!(a.verifying_key(), b.verifying_key());
    }

    #[test]
    fn rejects_wrong_length() {
        assert!(parse_signing_key(b"deadbeef").is_none());
    }
}
