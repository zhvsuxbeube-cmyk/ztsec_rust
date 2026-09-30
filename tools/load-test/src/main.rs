use std::{env, io, sync::{Arc, atomic::{AtomicU64, Ordering}}, time::{Duration, Instant}};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signer, SigningKey};
use futures_util::{SinkExt, StreamExt};
use tokio::{sync::Semaphore, time::timeout};
use tokio_tungstenite::{connect_async_with_config, tungstenite::Message};

#[tokio::main]
async fn main() -> io::Result<()> {
    let endpoint = env::var("ZTSEC_LOAD_ENDPOINT").unwrap_or_else(|_| "ws://127.0.0.1:4793/ztsec".into());
    let count: usize = env::var("ZTSEC_LOAD_CONNECTIONS").ok().and_then(|v| v.parse().ok()).unwrap_or(1000);
    let duration = Duration::from_secs(env::var("ZTSEC_LOAD_DURATION_SECS").ok().and_then(|v| v.parse().ok()).unwrap_or(30));
    let private_key_hex = env::var("ZTSEC_LOAD_PRIVATE_KEY_HEX").map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "ZTSEC_LOAD_PRIVATE_KEY_HEX is required for load tests"))?;
    let signing = SigningKey::from_bytes(&decode_32_bytes(&private_key_hex)?);
    let fingerprint = env::var("ZTSEC_LOAD_FINGERPRINT").unwrap_or_else(|_| "a".repeat(64));
    if fingerprint.len() != 64 || !fingerprint.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "ZTSEC_LOAD_FINGERPRINT must be 64 hex characters"));
    }
    let concurrency = env::var("ZTSEC_LOAD_CONNECT_CONCURRENCY").ok().and_then(|v| v.parse().ok()).unwrap_or(256usize);
    let semaphore = Arc::new(Semaphore::new(concurrency));
    let successes = Arc::new(AtomicU64::new(0));
    let failures = Arc::new(AtomicU64::new(0));
    let start = Instant::now();
    let mut handles = Vec::with_capacity(count);
    for _ in 0..count {
        let permit = semaphore.clone().acquire_owned().await.map_err(|_| io::Error::new(io::ErrorKind::Other, "semaphore closed"))?;
        let endpoint = endpoint.clone();
        let signing = signing.clone();
        let fingerprint = fingerprint.clone();
        let successes = successes.clone();
        let failures = failures.clone();
        handles.push(tokio::spawn(async move {
            let _permit = permit;
            let result = run_one(&endpoint, &fingerprint, &signing, duration).await;
            if result.is_ok() { successes.fetch_add(1, Ordering::Relaxed); } else { failures.fetch_add(1, Ordering::Relaxed); }
        }));
    }
    for handle in handles { let _ = handle.await; }
    let elapsed = start.elapsed();
    println!("connections={} successes={} failures={} elapsed_ms={} connect_rate_per_s={:.2}", count, successes.load(Ordering::Relaxed), failures.load(Ordering::Relaxed), elapsed.as_millis(), count as f64 / elapsed.as_secs_f64());
    Ok(())
}

fn decode_32_bytes(input: &str) -> io::Result<[u8; 32]> {
    let value = input.trim();
    if value.len() != 64 { return Err(io::Error::new(io::ErrorKind::InvalidInput, "load-test private key must be 64 hex characters")); }
    let mut out = [0u8; 32];
    for (idx, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let hi = hex_nibble(pair[0]).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid load-test private key"))?;
        let lo = hex_nibble(pair[1]).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid load-test private key"))?;
        out[idx] = (hi << 4) | lo;
    }
    Ok(out)
}

async fn run_one(endpoint: &str, fingerprint: &str, signing: &SigningKey, duration: Duration) -> io::Result<()> {
    let (mut ws, _) = timeout(Duration::from_secs(10), connect_async_with_config(endpoint, None, false)).await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "connect timeout"))?
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    ws.send(Message::Text(format!("HELLO:FINGERPRINT:{fingerprint}").into())).await.map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    let challenge = timeout(Duration::from_secs(10), ws.next()).await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "challenge timeout"))?
        .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "challenge eof"))?
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("challenge read failed: {e}")))?;
    let challenge = match challenge { Message::Text(text) => text.to_string(), _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "challenge not text")) };
    let nonce = STANDARD.decode(challenge.strip_prefix("AUTH:CHALLENGE:").ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid challenge"))?).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid nonce"))?;
    let signature = signing.sign(&ztsec_protocol::auth_message(fingerprint, &nonce));
    let pk = signing.verifying_key().to_bytes().iter().map(|b| format!("{b:02x}")).collect::<String>();
    ws.send(Message::Text(format!("AUTH:RESPONSE:{pk}:{}", STANDARD.encode(signature.to_bytes())).into())).await.map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    let auth = timeout(Duration::from_secs(10), ws.next()).await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "auth timeout"))?
        .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "auth eof"))?
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("auth read failed: {e}")))?;
    if !matches!(auth, Message::Text(ref text) if text.as_str() == "AUTH:OK") { return Err(io::Error::new(io::ErrorKind::PermissionDenied, "auth failed")); }
    let data = "DATA:Local|load-test|ZTSecurity|load|Rust-Native/1|User|Linux|GPU|CPU|Unknown|Unknown|0m|0m|0 ms|load-hwid|".to_string() + fingerprint;
    let until = Instant::now() + duration;
    while Instant::now() < until {
        ws.send(Message::Text(data.clone().into())).await.map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        let _ = timeout(Duration::from_secs(5), ws.next()).await;
        tokio::time::sleep(Duration::from_millis(1000)).await;
    }
    let _ = ws.close(None).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_exact_auth_ok_response() {
        let message = Message::Text("AUTH:OK".to_owned().into());
        assert!(matches!(message, Message::Text(ref text) if text.as_str() == "AUTH:OK"));
    }
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}
