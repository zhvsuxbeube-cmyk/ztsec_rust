use ed25519_dalek::SigningKey;
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use winreg::enums::HKEY_LOCAL_MACHINE;
use winreg::RegKey;

pub fn machine_id() -> Option<String> {
    let key = RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey("SOFTWARE\\Microsoft\\Cryptography")
        .ok()?;
    key.get_value::<String, _>("MachineGuid").ok()
}

pub fn hwid(machine: &str) -> String {
    let mut h = Sha256::new();
    h.update(machine.as_bytes());
    h.update(b"|windows");
    hex(h.finalize().as_slice())
}

pub fn fingerprint_from_machine_id(machine: &str) -> String {
    let id = hwid(machine);
    let hk = Hkdf::<Sha256>::new(Some(id.as_bytes()), machine.as_bytes());
    let mut seed = [0u8; 32];
    hk.expand(b"mirage-identity", &mut seed)
        .expect("fixed HKDF output");
    let key = SigningKey::from_bytes(&seed);
    let mut h = Sha256::new();
    h.update(key.verifying_key().to_bytes());
    hex(h.finalize().as_slice())
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}
