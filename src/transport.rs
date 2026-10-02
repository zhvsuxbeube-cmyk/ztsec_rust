use std::{io, net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use arti_client::{config::TorClientConfigBuilder, DataStream, TorClient};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::SigningKey;
use futures_util::{SinkExt, StreamExt};
use tokio::{net::TcpStream, time::timeout};
use tokio_tungstenite::{client_async_with_config, tungstenite::{http::Request, Message}, WebSocketStream};
use tor_rtcompat::PreferredRuntime;
use zeroize::{Zeroize, Zeroizing};

use crate::auth;

#[derive(Debug, Clone)]
pub enum Endpoint {
    Onion { host: String, port: u16, path: String },
    Local { host: String, port: u16, path: String },
    Direct { host: String, port: u16, path: String },
}

impl Endpoint {
    pub fn parse(value: &str) -> Result<Self, String> {
        let (scheme, rest) = value.split_once("://").ok_or("endpoint must use ws://")?;
        if !scheme.eq_ignore_ascii_case("ws") {
            return Err("only ws:// endpoints are supported".into());
        }
        let (authority, raw_path) = rest.split_once('/').unwrap_or((rest, ""));
        let path = format!("/{}", raw_path.trim_start_matches('/'));
        let path = if path == "/" { "/".into() } else { path };
        let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
            let (host, suffix) = rest.split_once(']').ok_or("invalid bracketed host")?;
            let suffix = suffix.strip_prefix(':').ok_or("IPv6 endpoints require a port")?;
            (host.to_owned(), parse_port(suffix)?)
        } else {
            let (host, port) = authority.rsplit_once(':').ok_or("endpoint must include a port")?;
            (host.to_owned(), parse_port(port)?)
        };
        if host.is_empty() {
            return Err("endpoint host is empty".into());
        }
        if host.ends_with(".onion") {
            if !valid_onion_host(&host) {
                return Err("endpoint host is not a valid v3 onion hostname".into());
            }
            Ok(Self::Onion { host, port, path })
        } else if is_loopback_host(&host) {
            Ok(Self::Local { host, port, path })
        } else {
            Err("non-onion endpoints are restricted to loopback for deterministic testing".into())
        }
    }

    pub fn target(&self) -> (&str, u16, &str) {
        match self {
            Self::Onion { host, port, path } | Self::Local { host, port, path } | Self::Direct { host, port, path } => (host, *port, path),
        }
    }

    pub fn is_onion(&self) -> bool {
        matches!(self, Self::Onion { .. })
    }

    #[cfg(test)]
    pub fn is_direct(&self) -> bool {
        matches!(self, Self::Direct { .. })
    }

    pub fn path(&self) -> &str {
        match self {
            Self::Onion { path, .. } | Self::Local { path, .. } | Self::Direct { path, .. } => path,
        }
    }

    pub fn direct(addr: SocketAddr, path: &str) -> Result<Self, String> {
        if addr.port() == 0 {
            return Err("direct endpoint port must not be zero".into());
        }
        if addr.ip().is_unspecified() || addr.ip().is_multicast() {
            return Err("direct endpoint address is not usable".into());
        }
        let host = addr.ip().to_string();
        if host.is_empty() {
            return Err("direct endpoint host is empty".into());
        }
        Ok(Self::Direct { host, port: addr.port(), path: normalize_path(path) })
    }
}

impl Drop for Endpoint {
    fn drop(&mut self) {
        if let Self::Direct { host, path, .. } = self {
            host.zeroize();
            path.zeroize();
        }
    }
}

fn format_authority(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn normalize_path(raw: &str) -> String {
    let path = format!("/{}", raw.trim_start_matches('/'));
    if path == "/" { "/".to_owned() } else { path }
}

fn parse_port(value: &str) -> Result<u16, String> {
    let port = value.parse::<u16>().map_err(|_| "invalid endpoint port".to_owned())?;
    if port == 0 { Err("endpoint port must not be zero".into()) } else { Ok(port) }
}

fn valid_onion_host(host: &str) -> bool {
    let label = host.strip_suffix(".onion").unwrap_or_default();
    label.len() == 56 && label.bytes().all(|b| b.is_ascii_lowercase() || matches!(b, b'2'..=b'7'))
}

fn is_loopback_host(host: &str) -> bool {
    matches!(host, "127.0.0.1" | "localhost" | "::1")
}

#[derive(Debug, Clone, Copy)]
pub struct ClientIdentity<'a> {
    pub fingerprint: &'a str,
}

pub enum Session {
    Local(WebSocketStream<TcpStream>),
    Tor(WebSocketStream<DataStream>),
}

impl Session {
    pub async fn send_text(&mut self, text: &str) -> io::Result<()> {
        match self {
            Self::Local(stream) => stream.send(Message::Text(text.to_owned().into())).await.map_err(ws_io),
            Self::Tor(stream) => stream.send(Message::Text(text.to_owned().into())).await.map_err(ws_io),
        }
    }

    pub async fn send_ping(&mut self) -> io::Result<()> {
        match self {
            Self::Local(stream) => stream.send(Message::Ping(Vec::new().into())).await.map_err(ws_io),
            Self::Tor(stream) => stream.send(Message::Ping(Vec::new().into())).await.map_err(ws_io),
        }
    }

    pub async fn close(&mut self) -> io::Result<()> {
        match self {
            Self::Local(stream) => stream.close(None).await.map_err(ws_io),
            Self::Tor(stream) => stream.close(None).await.map_err(ws_io),
        }
    }

    pub async fn next_text(&mut self) -> io::Result<Option<String>> {
        loop {
            let message = match self {
                Self::Local(stream) => stream.next().await,
                Self::Tor(stream) => stream.next().await,
            };
            match message {
                Some(Ok(Message::Text(text))) => return Ok(Some(text.to_string())),
                Some(Ok(Message::Binary(_))) => return Err(io::Error::new(io::ErrorKind::InvalidData, "binary WebSocket frame is not supported")),
                Some(Ok(Message::Ping(payload))) => {
                    match self {
                        Self::Local(stream) => stream.send(Message::Pong(payload)).await,
                        Self::Tor(stream) => stream.send(Message::Pong(payload)).await,
                    }.map_err(ws_io)?;
                }
                Some(Ok(Message::Pong(_))) | Some(Ok(Message::Frame(_))) => {}
                Some(Ok(Message::Close(_))) | None => return Ok(None),
                Some(Err(error)) => return Err(ws_io(error)),
            }
        }
    }
}

fn ws_io(error: tokio_tungstenite::tungstenite::Error) -> io::Error {
    io::Error::new(io::ErrorKind::Other, error.to_string())
}

pub fn ws_config() -> tokio_tungstenite::tungstenite::protocol::WebSocketConfig {
    tokio_tungstenite::tungstenite::protocol::WebSocketConfig::default()
        .read_buffer_size(8 * 1024)
        .write_buffer_size(4 * 1024)
        .max_write_buffer_size(64 * 1024)
        .max_message_size(Some(ztsec_protocol::MAX_WS_MESSAGE_BYTES))
        .max_frame_size(Some(ztsec_protocol::MAX_WS_MESSAGE_BYTES))
}

pub struct Connector {
    endpoint: Endpoint,
    state_dir: PathBuf,
    cache_dir: PathBuf,
    tor: Option<Arc<TorClient<PreferredRuntime>>>,
}

impl Connector {
    pub fn new(endpoint: Endpoint, state_dir: PathBuf, cache_dir: PathBuf) -> Self {
        Self { endpoint, state_dir, cache_dir, tor: None }
    }

    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    pub fn set_endpoint(&mut self, endpoint: Endpoint) {
        self.endpoint = endpoint;
    }

    async fn ensure_tor(&mut self, timeout_duration: Duration) -> io::Result<Arc<TorClient<PreferredRuntime>>> {
        if let Some(tor) = &self.tor {
            return Ok(Arc::clone(tor));
        }
        std::fs::create_dir_all(&self.state_dir)?;
        std::fs::create_dir_all(&self.cache_dir)?;
        let config = TorClientConfigBuilder::from_directories(&self.state_dir, &self.cache_dir)
            .build()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("invalid Arti configuration: {e}")))?;
        let tor = timeout(timeout_duration, TorClient::create_bootstrapped(config))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Arti bootstrap timeout"))?
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Arti bootstrap failed: {e}")))?;
        self.tor = Some(Arc::clone(&tor));
        Ok(tor)
    }

    pub async fn connect_authenticated(
        &mut self,
        fingerprint: &str,
        signing_key: &SigningKey,
        connect_timeout: Duration,
        handshake_timeout: Duration,
    ) -> io::Result<Session> {
        let mut session = self.connect_ws(connect_timeout, handshake_timeout).await?;
        authenticate(&mut session, ClientIdentity { fingerprint }, signing_key, handshake_timeout).await?;
        Ok(session)
    }

    pub async fn connect_ws(&mut self, connect_timeout: Duration, handshake_timeout: Duration) -> io::Result<Session> {
        let (host, port, path) = self.endpoint.target();
        let authority = Zeroizing::new(format_authority(host, port));
        let uri = Zeroizing::new(format!("ws://{}{}", authority.as_str(), path));
        let request = Request::builder()
            .uri(uri.as_str())
            .header("Host", authority.as_str())
            .body(())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;

        let endpoint = self.endpoint.clone();
        // Endpoint implements Drop so its owned String fields cannot be moved out. Borrowing the
        // cloned endpoint also keeps the endpoint data independent from the mutable Tor cache.
        match &endpoint {
            Endpoint::Local { host, port, .. } => {
                let stream = timeout(connect_timeout, TcpStream::connect((host.as_str(), *port)))
                    .await
                    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "WebSocket connect timeout"))??;
                let (ws, _) = timeout(handshake_timeout, client_async_with_config(request, stream, Some(ws_config())))
                    .await
                    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "WebSocket handshake timeout"))?
                    .map_err(ws_io)?;
                Ok(Session::Local(ws))
            }
            Endpoint::Onion { host, port, .. } => {
                let tor = self.ensure_tor(handshake_timeout).await?;
                let stream = timeout(connect_timeout, tor.connect((host.as_str(), *port)))
                    .await
                    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Tor onion connection timeout"))?
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Tor onion connection failed: {e}")))?;
                let (ws, _) = timeout(handshake_timeout, client_async_with_config(request, stream, Some(ws_config())))
                    .await
                    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "onion WebSocket handshake timeout"))?
                    .map_err(ws_io)?;
                Ok(Session::Tor(ws))
            }
            Endpoint::Direct { host, port, .. } => {
                let stream = timeout(connect_timeout, TcpStream::connect((host.as_str(), *port)))
                    .await
                    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "direct WebSocket connect timeout"))?
                    .map_err(|e| io::Error::new(e.kind(), format!("direct endpoint connection failed: {e}")))?;
                let (ws, _) = timeout(handshake_timeout, client_async_with_config(request, stream, Some(ws_config())))
                    .await
                    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "direct WebSocket handshake timeout"))?
                    .map_err(ws_io)?;
                Ok(Session::Local(ws))
            }
        }
    }
}

async fn authenticate(
    session: &mut Session,
    identity: ClientIdentity<'_>,
    signing_key: &SigningKey,
    handshake_timeout: Duration,
) -> io::Result<()> {
    let hello = format!("HELLO:FINGERPRINT:{}", identity.fingerprint);
    timeout(handshake_timeout, session.send_text(&hello))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "authentication send timeout"))??;

    let challenge = timeout(handshake_timeout, session.next_text())
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "authentication challenge timeout"))??
        .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "server closed before authentication challenge"))?;
    let nonce_b64 = challenge.strip_prefix("AUTH:CHALLENGE:")
        .ok_or_else(|| io::Error::new(io::ErrorKind::PermissionDenied, "unexpected authentication challenge"))?;
    let nonce = STANDARD.decode(nonce_b64)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid authentication challenge"))?;
    if nonce.len() != 32 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid authentication nonce length"));
    }
    let public_key = auth::public_key_hex(signing_key);
    let signature = auth::sign_challenge(&identity, &nonce, signing_key);
    let response = format!("AUTH:RESPONSE:{public_key}:{signature}");
    timeout(handshake_timeout, session.send_text(&response))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "authentication response timeout"))??;

    let result = timeout(handshake_timeout, session.next_text())
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "authentication result timeout"))??
        .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "server closed before authentication result"))?;
    if result == "AUTH:OK" {
        Ok(())
    } else {
        Err(io::Error::new(io::ErrorKind::PermissionDenied, "authentication rejected"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_v3_onion_and_loopback_only() {
        let onion = format!("ws://{}.onion:443/ws", "a".repeat(56));
        assert!(Endpoint::parse(&onion).is_ok());
        assert!(Endpoint::parse("ws://127.0.0.1:4793/").is_ok());
        assert!(Endpoint::parse("ws://10.0.0.1:4793/").is_err());
    }

    #[test]
    fn rejects_non_ws() {
        assert!(Endpoint::parse("wss://127.0.0.1:4793/").is_err());
    }
}

#[cfg(test)]
mod direct_tests {
    use super::*;

    #[test]
    fn direct_endpoint_accepts_socket_address_and_preserves_path() {
        let endpoint = Endpoint::direct("192.0.2.10:4794".parse().unwrap(), "/ztsec").unwrap();
        assert!(endpoint.is_direct());
        assert_eq!(endpoint.target(), ("192.0.2.10", 4794, "/ztsec"));
    }

    #[test]
    fn direct_endpoint_accepts_ipv6_socket_address() {
        let endpoint = Endpoint::direct("[2001:db8::10]:4794".parse().unwrap(), "/ztsec").unwrap();
        assert!(endpoint.is_direct());
        assert_eq!(endpoint.path(), "/ztsec");
    }

    #[test]
    fn direct_endpoint_rejects_unspecified_address() {
        assert!(Endpoint::direct("0.0.0.0:4794".parse().unwrap(), "/ztsec").is_err());
    }

    #[test]
    fn websocket_authority_brackets_ipv6() {
        assert_eq!(format_authority("2001:db8::10", 4794), "[2001:db8::10]:4794");
        assert_eq!(format_authority("203.0.113.10", 4794), "203.0.113.10:4794");
    }
}
