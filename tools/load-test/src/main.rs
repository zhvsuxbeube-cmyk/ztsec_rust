use std::{env, io, net::SocketAddr, sync::{Arc, atomic::{AtomicU64, Ordering}}, time::{Duration, Instant}};

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
    let fingerprints = load_fingerprints()?;
    let concurrency = env::var("ZTSEC_LOAD_CONNECT_CONCURRENCY").ok().and_then(|v| v.parse().ok()).unwrap_or(256usize);
    let semaphore = Arc::new(Semaphore::new(concurrency));
    let successes = Arc::new(AtomicU64::new(0));
    let failures = Arc::new(AtomicU64::new(0));
    let start = Instant::now();
    let mut handles = Vec::with_capacity(count);
    for index in 0..count {
        let permit = semaphore.clone().acquire_owned().await.map_err(|_| io::Error::new(io::ErrorKind::Other, "semaphore closed"))?;
        let endpoint = endpoint.clone();
        let signing = signing.clone();
        let fingerprint = fingerprints[index % fingerprints.len()].clone();
        let successes = successes.clone();
        let failures = failures.clone();
        let wait_for_command = env::var("ZTSEC_LOAD_WAIT_COMMAND").ok().and_then(|v| v.parse::<u64>().ok()).map(Duration::from_secs);
        handles.push(tokio::spawn(async move {
            let _permit = permit;
            let result = run_one(&endpoint, &fingerprint, &signing, duration, wait_for_command).await;
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

async fn run_one(endpoint: &str, fingerprint: &str, signing: &SigningKey, duration: Duration, wait_for_command: Option<Duration>) -> io::Result<()> {
    let (mut ws, _) = timeout(Duration::from_secs(10), connect_async_with_config(endpoint, None, false)).await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "connect timeout"))?
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    authenticate_ws(&mut ws, fingerprint, signing).await?;
    let data = "DATA:Local|load-test|ZTSecurity|load|Rust-Native/1|User|Linux|GPU|CPU|Unknown|Unknown|0m|0m|0 ms|load-hwid|".to_string() + fingerprint;
    if let Some(wait) = wait_for_command {
        let deadline = Instant::now() + wait;
        while Instant::now() < deadline {
            match timeout(Duration::from_secs(1), ws.next()).await {
                Ok(Some(Ok(Message::Text(text)))) => {
                    let command = text.to_string();
                    if command == "CMD:RECONNECT" {
                        ws.send(Message::Text("ACK:RECONNECT".into())).await.map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                        let _ = ws.close(None).await;
                        return Ok(());
                    }
                    if command == "CMD:CLOSE" {
                        ws.send(Message::Text("ACK:CLOSE".into())).await.map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                        let _ = ws.close(None).await;
                        return Ok(());
                    }
                    if let Some(address) = strip_prefix_ascii_ci(&command, "CMD:DIRECT_CONNECT:") {
                        if env::var_os("ZTSEC_LOAD_FOLLOW_DIRECT").is_some() {
                            let direct_addr = address.trim().parse::<SocketAddr>()
                                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid direct endpoint in relay command"))?;
                            if direct_addr.ip().is_unspecified() || direct_addr.ip().is_multicast() || direct_addr.port() == 0 {
                                return Err(io::Error::new(io::ErrorKind::InvalidData, "unsafe direct endpoint in relay command"));
                            }
                            ws.send(Message::Text("ACK:DIRECT_CONNECT:".into())).await.map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                            let _ = ws.close(None).await;

                            let direct_endpoint = format!("ws://{direct_addr}/ztsec");
                            let (mut direct_ws, _) = timeout(Duration::from_secs(10), connect_async_with_config(&direct_endpoint, None, false))
                                .await
                                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "direct test connect timeout"))?
                                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("direct test connect failed: {e}")))?;
                            authenticate_ws(&mut direct_ws, fingerprint, signing).await?;
                            let data = "DATA:Local|load-test-direct|ZTSecurity|load|Rust-Native/1|User|Linux|GPU|CPU|Unknown|Unknown|0m|0m|0 ms|load-hwid|".to_string() + fingerprint;
                            direct_ws.send(Message::Text(data.into())).await.map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                            let _ = timeout(Duration::from_secs(5), direct_ws.next()).await;
                            println!("direct transport connected");

                            let deadline = Instant::now() + wait;
                            while Instant::now() < deadline {
                                match timeout(Duration::from_secs(1), direct_ws.next()).await {
                                    Ok(Some(Ok(Message::Text(text)))) if text.as_str() == "CMD:DIRECT_DISCONNECT" => {
                                        direct_ws.send(Message::Text("ACK:DIRECT_DISCONNECT".into())).await.map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                                        let _ = direct_ws.close(None).await;
                                        println!("direct transport disconnected");
                                        if env::var_os("ZTSEC_LOAD_RETURN_PRIMARY").is_some() {
                                            let (mut primary_ws, _) = timeout(Duration::from_secs(10), connect_async_with_config(endpoint, None, false))
                                                .await
                                                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "primary return connect timeout"))?
                                                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("primary return connect failed: {e}")))?;
                                            authenticate_ws(&mut primary_ws, fingerprint, signing).await?;
                                            primary_ws.send(Message::Text(data_for_return(fingerprint).into())).await.map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                                            let _ = timeout(Duration::from_secs(5), primary_ws.next()).await;
                                            let _ = primary_ws.close(None).await;
                                            println!("returned to primary transport");
                                        }
                                        return Ok(());
                                    }
                                    Ok(Some(Ok(Message::Ping(payload)))) => {
                                        direct_ws.send(Message::Pong(payload)).await.map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                                    }
                                    Ok(Some(Ok(Message::Close(_)))) | Ok(None) => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "direct server closed before disconnect command")),
                                    Ok(Some(Err(error))) => return Err(io::Error::new(io::ErrorKind::Other, error.to_string())),
                                    Ok(Some(Ok(_))) | Err(_) => {}
                                }
                            }
                            return Err(io::Error::new(io::ErrorKind::TimedOut, "direct disconnect command wait timeout"));
                        }
                        let ack_suffix = command.strip_prefix("CMD:").unwrap_or(&command);
                        ws.send(Message::Text(format!("ACK:{ack_suffix}").into())).await.map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                        let _ = ws.close(None).await;
                        return Ok(());
                    }
                    if command == "CMD:DIRECT_DISCONNECT" {
                        ws.send(Message::Text("ACK:DIRECT_DISCONNECT".into())).await.map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                        let _ = ws.close(None).await;
                        return Ok(());
                    }
                }
                Ok(Some(Ok(Message::Ping(payload)))) => {
                    ws.send(Message::Pong(payload)).await.map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                }
                Ok(Some(Ok(Message::Close(_)))) | Ok(None) => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "server closed before relayed command")),
                Ok(Some(Err(error))) => return Err(io::Error::new(io::ErrorKind::Other, error.to_string())),
                Ok(Some(Ok(_))) | Err(_) => {}
            }
        }
        return Err(io::Error::new(io::ErrorKind::TimedOut, "relay command wait timeout"));
    }
    let until = Instant::now() + duration;
    while Instant::now() < until {
        ws.send(Message::Text(data.clone().into())).await.map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        let _ = timeout(Duration::from_secs(5), ws.next()).await;
        tokio::time::sleep(Duration::from_millis(1000)).await;
    }
    let _ = ws.close(None).await;
    Ok(())
}


fn strip_prefix_ascii_ci<'a>(value: &'a str, prefix: &str) -> Option<&'a str> {
    value.get(..prefix.len())
        .filter(|head| head.eq_ignore_ascii_case(prefix))
        .map(|_| &value[prefix.len()..])
}

async fn authenticate_ws<S>(ws: &mut tokio_tungstenite::WebSocketStream<S>, fingerprint: &str, signing: &SigningKey) -> io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    ws.send(Message::Text(format!("HELLO:FINGERPRINT:{fingerprint}").into())).await
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    let challenge = timeout(Duration::from_secs(10), ws.next()).await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "challenge timeout"))?
        .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "challenge eof"))?
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("challenge read failed: {e}")))?;
    let challenge = match challenge {
        Message::Text(text) => text.to_string(),
        _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "challenge not text")),
    };
    let nonce = STANDARD.decode(challenge.strip_prefix("AUTH:CHALLENGE:").ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid challenge"))?)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid nonce"))?;
    if nonce.len() != 32 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid nonce length"));
    }
    let signature = signing.sign(&ztsec_protocol::auth_message(fingerprint, &nonce));
    let pk = signing.verifying_key().to_bytes().iter().map(|b| format!("{b:02x}")).collect::<String>();
    ws.send(Message::Text(format!("AUTH:RESPONSE:{pk}:{}", STANDARD.encode(signature.to_bytes())).into())).await
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    let auth = timeout(Duration::from_secs(10), ws.next()).await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "auth timeout"))?
        .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "auth eof"))?
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("auth read failed: {e}")))?;
    if !matches!(auth, Message::Text(ref text) if text.as_str() == "AUTH:OK") {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "auth failed"));
    }
    Ok(())
}

fn data_for_return(fingerprint: &str) -> String {
    format!("DATA:Local|load-test-return|ZTSecurity|load|Rust-Native/1|User|Linux|GPU|CPU|Unknown|Unknown|0m|0m|0 ms|load-hwid|{fingerprint}")
}

fn load_fingerprints() -> io::Result<Vec<String>> {
    let raw = env::var("ZTSEC_LOAD_FINGERPRINTS")
        .or_else(|_| env::var("ZTSEC_LOAD_FINGERPRINT"))
        .unwrap_or_else(|_| "a".repeat(64));
    parse_fingerprints(&raw)
}

fn parse_fingerprints(raw: &str) -> io::Result<Vec<String>> {
    let values: Vec<String> = raw
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect();
    if values.is_empty() || values.iter().any(|value| value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit())) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "ZTSEC_LOAD_FINGERPRINT(S) must contain 64-hex fingerprints"));
    }
    Ok(values)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_exact_auth_ok_response() {
        let message = Message::Text("AUTH:OK".to_owned().into());
        assert!(matches!(message, Message::Text(ref text) if text.as_str() == "AUTH:OK"));
    }

    #[test]
    fn fingerprint_list_accepts_multiple_agents() {
        let values = parse_fingerprints(&format!("{},{}", "a".repeat(64), "b".repeat(64))).unwrap();
        assert_eq!(values.len(), 2);
        assert_eq!(values[0], "a".repeat(64));
        assert_eq!(values[1], "b".repeat(64));
    }

    #[test]
    fn fingerprint_list_rejects_malformed_entries() {
        assert!(parse_fingerprints(&format!("{},g{}", "a".repeat(64), "b".repeat(63))).is_err());
    }

    #[test]
    fn direct_relay_prefix_parser_accepts_case_variants() {
        assert_eq!(strip_prefix_ascii_ci("cmd:direct_connect:127.0.0.1:4794", "CMD:DIRECT_CONNECT:").unwrap(), "127.0.0.1:4794");
        assert!(strip_prefix_ascii_ci("CMD:RECONNECT", "CMD:DIRECT_CONNECT:").is_none());
    }

    #[test]
    fn direct_relay_address_requires_a_socket_address() {
        let address = strip_prefix_ascii_ci("CMD:DIRECT_CONNECT:127.0.0.1:4794", "CMD:DIRECT_CONNECT:").unwrap().parse::<SocketAddr>().unwrap();
        assert_eq!(address.ip().to_string(), "127.0.0.1");
        assert!("not-an-address".parse::<SocketAddr>().is_err());
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
