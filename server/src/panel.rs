use std::{fs, io, path::{Path, PathBuf}, sync::Arc, time::{Duration, SystemTime, UNIX_EPOCH}};

use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;
use tokio::{io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt}, net::{TcpListener, TcpStream}, sync::{broadcast, Semaphore}, time::timeout};
use tokio_rustls::{rustls::{self, pki_types::CertificateDer, ServerConfig}, TlsAcceptor};
use tracing::{debug, info, warn};

const MAX_FRAME_BYTES: usize = 64 * 1024;
const CHALLENGE_BYTES: usize = 32;
const MAX_AUTH_ATTEMPTS: usize = 3;
const AUTH_DOMAIN: &[u8] = b"ZTSEC-PANEL-AUTH-V1\0";

#[derive(Clone)]
pub struct PanelHub {
    tx: broadcast::Sender<Arc<str>>,
    cache: Arc<tokio::sync::RwLock<Vec<Arc<str>>>>,
}

impl PanelHub {
    pub fn new(capacity: usize) -> Self {
        let (tx, _) = broadcast::channel(capacity.max(16));
        Self { tx, cache: Arc::new(tokio::sync::RwLock::new(Vec::new())) }
    }

    pub async fn publish(&self, payload: String, fingerprint: &str) {
        let payload: Arc<str> = Arc::from(payload);
        {
            let mut cache = self.cache.write().await;
            if let Some(index) = cache.iter().position(|entry| telemetry_fingerprint(entry) == Some(fingerprint)) {
                cache[index] = Arc::clone(&payload);
            } else {
                cache.push(Arc::clone(&payload));
                if cache.len() > 4096 {
                    let drop_count = cache.len() - 4096;
                    cache.drain(0..drop_count);
                }
            }
        }
        let _ = self.tx.send(payload);
    }

    fn subscribe(&self) -> broadcast::Receiver<Arc<str>> { self.tx.subscribe() }

    async fn snapshot(&self) -> Vec<Arc<str>> { self.cache.read().await.clone() }
}

fn telemetry_fingerprint(payload: &str) -> Option<&str> {
    let value: serde_json::Value = serde_json::from_str(payload).ok()?;
    value.get("fingerprint")?.as_str()
}

#[derive(Clone)]
pub struct PanelConfig {
    pub cert: PathBuf,
    pub key: PathBuf,
    pub secret_file: PathBuf,
    pub panel_id: String,
    pub handshake_timeout: Duration,
    pub idle_timeout: Duration,
}

pub async fn run(listener: TcpListener, tls: Arc<TlsAcceptor>, config: PanelConfig, hub: PanelHub, limit: Arc<Semaphore>, shutdown: tokio::sync::watch::Receiver<bool>) {
    let secret = match load_secret(&config.secret_file) {
        Ok(secret) => Arc::new(secret),
        Err(error) => {
            warn!(path = %config.secret_file.display(), ?error, "panel gateway disabled: unable to load secret");
            return;
        }
    };

    let mut shutdown = shutdown;
    loop {
        let accepted = tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() { break; }
                continue;
            }
            accepted = listener.accept() => accepted,
        };
        let (stream, peer) = match accepted {
            Ok(value) => value,
            Err(error) => {
                warn!(?error, "panel gateway accept failed");
                continue;
            }
        };
        let Ok(permit) = limit.clone().try_acquire_owned() else {
            continue;
        };
        let tls = Arc::clone(&tls);
        let config = config.clone();
        let hub = hub.clone();
        let secret = Arc::clone(&secret);
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(error) = handle_connection(stream, peer.to_string(), tls, config, hub, secret).await {
                debug!(peer = %peer, ?error, "panel connection closed");
            }
        });
    }
}

async fn handle_connection(
    stream: TcpStream,
    peer: String,
    tls: Arc<TlsAcceptor>,
    config: PanelConfig,
    hub: PanelHub,
    secret: Arc<Zeroizing<Vec<u8>>>,
) -> io::Result<()> {
    let stream = timeout(config.handshake_timeout, tls.accept(stream)).await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "panel TLS handshake timeout"))??;
    let (mut reader, mut writer) = tokio::io::split(stream);

    let hello = timeout(config.handshake_timeout, read_json::<PanelHello, _>(&mut reader)).await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "panel hello timeout"))??;
    if hello.protocol_version != 1 || hello.message_type != "panel_hello" || hello.panel_id != config.panel_id {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "invalid panel hello"));
    }

    for _ in 0..MAX_AUTH_ATTEMPTS {
        let mut challenge = [0u8; CHALLENGE_BYTES];
        getrandom::getrandom(&mut challenge).map_err(|error| io::Error::new(io::ErrorKind::Other, error.to_string()))?;
        let expires_at_ms = now_ms().saturating_add(config.handshake_timeout.as_millis().min(u64::MAX as u128) as u64);
        write_json(&mut writer, &PanelChallenge {
            protocol_version: 1,
            message_type: "panel_challenge",
            panel_id: &config.panel_id,
            challenge: STANDARD_NO_PAD.encode(challenge),
            expires_at_ms,
        }).await?;

        let proof = timeout(config.handshake_timeout, read_json::<PanelProof, _>(&mut reader)).await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "panel proof timeout"))??;
        if proof.protocol_version != 1 || proof.message_type != "panel_proof" || proof.panel_id != config.panel_id {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, "invalid panel proof envelope"));
        }
        if now_ms() > expires_at_ms {
            continue;
        }
        let supplied = STANDARD_NO_PAD.decode(proof.proof.as_bytes()).map_err(|_| io::Error::new(io::ErrorKind::PermissionDenied, "invalid panel proof"))?;
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_slice()).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid panel secret"))?;
        mac.update(AUTH_DOMAIN);
        mac.update(config.panel_id.as_bytes());
        mac.update(&[0]);
        mac.update(&challenge);
        if mac.verify_slice(&supplied).is_ok() {
            write_json(&mut writer, &PanelAuthenticated { protocol_version: 1, message_type: "panel_authenticated", expires_at_ms }).await?;
            info!(peer = %peer, panel_id = %config.panel_id, "panel authenticated");
            return stream_events(reader, writer, hub, config.idle_timeout).await;
        }
    }

    Err(io::Error::new(io::ErrorKind::PermissionDenied, "panel authentication failed"))
}

async fn stream_events<R, W>(mut reader: R, mut writer: W, hub: PanelHub, idle_timeout: Duration) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    for payload in hub.snapshot().await {
        write_raw(&mut writer, payload.as_bytes()).await?;
    }
    let mut rx = hub.subscribe();
    loop {
        tokio::select! {
            incoming = timeout(idle_timeout, read_json::<PanelMessage, _>(&mut reader)) => {
                match incoming {
                    Ok(Ok(message)) if message.message_type == "panel_ping" && message.protocol_version.unwrap_or(1) == 1 => {
                        write_json(&mut writer, &PanelPong { protocol_version: 1, message_type: "panel_pong" }).await?;
                    }
                    Ok(Ok(message)) if message.message_type == "panel_close" => return Ok(()),
                    Ok(Ok(_)) => return Err(io::Error::new(io::ErrorKind::InvalidData, "unsupported panel message")),
                    Ok(Err(error)) => return Err(error),
                    Err(_) => return Err(io::Error::new(io::ErrorKind::TimedOut, "panel idle timeout")),
                }
            }
            update = rx.recv() => {
                match update {
                    Ok(payload) => write_raw(&mut writer, payload.as_bytes()).await?,
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        for payload in hub.snapshot().await {
                            write_raw(&mut writer, payload.as_bytes()).await?;
                        }
                    }
                    Err(broadcast::error::RecvError::Closed) => return Ok(()),
                }
            }
        }
    }
}

async fn read_json<T: for<'de> Deserialize<'de>, R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<T> {
    let mut header = [0u8; 4];
    reader.read_exact(&mut header).await?;
    let len = u32::from_be_bytes(header) as usize;
    if len == 0 || len > MAX_FRAME_BYTES {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "panel frame too large"));
    }
    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload).await?;
    serde_json::from_slice(&payload).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))
}

async fn write_json<T: Serialize, W: AsyncWrite + Unpin>(writer: &mut W, value: &T) -> io::Result<()> {
    let payload = serde_json::to_vec(value).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
    write_raw(writer, &payload).await
}

async fn write_raw<W: AsyncWrite + Unpin>(writer: &mut W, payload: &[u8]) -> io::Result<()> {
    if payload.is_empty() || payload.len() > MAX_FRAME_BYTES {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "panel response too large"));
    }
    writer.write_all(&(payload.len() as u32).to_be_bytes()).await?;
    writer.write_all(payload).await?;
    writer.flush().await
}

fn load_secret(path: &Path) -> io::Result<Zeroizing<Vec<u8>>> {
    let data = fs::read(path).map_err(|error| io::Error::new(error.kind(), format!("read panel secret {}: {error}", path.display())))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(path)?.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, "panel secret file must not be group/world readable or writable"));
        }
    }
    let secret = Zeroizing::new(data.iter().copied().filter(|byte| !byte.is_ascii_whitespace()).collect::<Vec<_>>());
    if secret.len() != 32 || secret.iter().any(|byte| !(0x21..=0x7e).contains(byte)) {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "panel secret must contain exactly 32 printable ASCII characters"));
    }
    Ok(secret)
}

pub fn validate_secret_file(path: &Path) -> io::Result<()> {
    let _ = load_secret(path)?;
    Ok(())
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis().min(u64::MAX as u128) as u64
}

pub fn build_tls_acceptor(cert_path: &Path, key_path: &Path) -> io::Result<TlsAcceptor> {
    let cert_file = fs::File::open(cert_path).map_err(|error| io::Error::new(error.kind(), format!("open panel certificate {}: {error}", cert_path.display())))?;
    let mut cert_reader = io::BufReader::new(cert_file);
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, format!("parse panel certificate: {error}")))?;
    if certs.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "panel certificate file contains no certificates"));
    }

    let key_file = fs::File::open(key_path).map_err(|error| io::Error::new(error.kind(), format!("open panel private key {}: {error}", key_path.display())))?;
    let mut key_reader = io::BufReader::new(key_file);
    let key = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, format!("parse panel private key: {error}")))?
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "panel private key file contains no supported private key"))?;

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, format!("build panel TLS configuration: {error}")))?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

#[derive(Debug, Deserialize)]
struct PanelHello {
    protocol_version: u16,
    message_type: String,
    panel_id: String,
}

#[derive(Debug, Serialize)]
struct PanelChallenge<'a> {
    protocol_version: u16,
    message_type: &'static str,
    panel_id: &'a str,
    challenge: String,
    expires_at_ms: u64,
}

#[derive(Debug, Deserialize)]
struct PanelProof {
    protocol_version: u16,
    message_type: String,
    panel_id: String,
    proof: String,
}

#[derive(Debug, Serialize)]
struct PanelAuthenticated {
    protocol_version: u16,
    message_type: &'static str,
    expires_at_ms: u64,
}

#[derive(Debug, Deserialize)]
struct PanelMessage {
    protocol_version: Option<u16>,
    message_type: String,
}

#[derive(Debug, Serialize)]
struct PanelPong {
    protocol_version: u16,
    message_type: &'static str,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn panel_secret_requires_exactly_32_printable_ascii_bytes() {
        let path = std::env::temp_dir().join(format!("ztsec-panel-secret-{}", std::process::id()));
        fs::write(&path, b"12345678901234567890123456789012\n").unwrap();
        #[cfg(unix)] { use std::os::unix::fs::PermissionsExt; fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap(); }
        assert_eq!(load_secret(&path).unwrap().len(), 32);
        fs::write(&path, b"short\n").unwrap();
        assert!(load_secret(&path).is_err());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn telemetry_cache_extracts_fingerprint() {
        let value = r#"{"fingerprint":"abc","message_type":"telemetry"}"#;
        assert_eq!(telemetry_fingerprint(value), Some("abc"));
    }
}
