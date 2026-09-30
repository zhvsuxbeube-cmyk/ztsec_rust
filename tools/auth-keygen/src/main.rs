use std::io;

use ed25519_dalek::SigningKey;

fn main() -> io::Result<()> {
    let seed = match std::env::args().nth(1).as_deref() {
        Some(value) if value == "--seed-hex" => {
            let input = std::env::args().nth(2).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing seed after --seed-hex"))?;
            decode_seed(&input)?
        }
        Some(value) => return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("unknown argument {value}"))),
        None => {
            let mut generated = [0u8; 32];
            getrandom::getrandom(&mut generated).map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
            generated
        }
    };
    let signing = SigningKey::from_bytes(&seed);
    let public = signing.verifying_key().to_bytes();
    println!("private_seed_hex={}", hex(&seed));
    println!("public_key_hex={}", hex(&public));
    eprintln!("Store private_seed_hex only on the agent. Put public_key_hex in the server authorized_keys file.");
    Ok(())
}

fn decode_seed(input: &str) -> io::Result<[u8; 32]> {
    let value = input.trim();
    if value.len() != 64 { return Err(io::Error::new(io::ErrorKind::InvalidInput, "seed must be 64 hex characters")); }
    let mut out = [0u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = (pair[0] as char).to_digit(16).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "seed is not hexadecimal"))? as u8;
        let low = (pair[1] as char).to_digit(16).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "seed is not hexadecimal"))? as u8;
        out[index] = (high << 4) | low;
    }
    Ok(out)
}

fn hex(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() }
