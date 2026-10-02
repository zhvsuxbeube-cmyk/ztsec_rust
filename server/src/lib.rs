use std::{collections::HashMap, fs, io, net::{IpAddr, SocketAddr}, path::{Path, PathBuf}, sync::{Arc, atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering}}, time::{Duration, Instant, SystemTime, UNIX_EPOCH}};

#[cfg(unix)]
use std::os::unix::fs::FileTypeExt;

use arti_client::{config::TorClientConfigBuilder, TorClient};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signature, VerifyingKey, Verifier};
use futures_util::{SinkExt, StreamExt};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::{TcpListener, TcpStream, UnixListener}, sync::{mpsc, OwnedSemaphorePermit, Semaphore, watch}, time::{interval, timeout}};
use tor_cell::relaycell::msg::Connected;
use tor_hsservice::{config::{OnionServiceConfigBuilder, TokenBucketConfig}, RunningOnionService, StreamRequest};
use tor_proto::stream::IncomingStreamRequest;
use tracing::{debug, info, warn};

mod control;
mod panel;
mod public_ip;
use control::{AgentRegistry, RouteStatus};
use panel::PanelHub;

pub const DEFAULT_LOCAL_SOCKET: &str = "/run/ztsec/telemetry.sock";
pub const DEFAULT_CONTROL_SOCKET: &str = "/run/ztsec/control.sock";
pub const DEFAULT_DIRECT_LISTEN: &str = "0.0.0.0:4794";

#[derive(Debug, Clone)]
pub struct Config {
    pub onion_nickname: String,
    pub state_dir: PathBuf,
    pub cache_dir: PathBuf,
    pub authorized_keys: PathBuf,
    pub local_listen: Option<String>,
    pub direct_listen: String,
    pub enable_onion: bool,
    pub local_socket: PathBuf,
    pub control_socket: PathBuf,
    pub panel_listen: Option<String>,
    pub panel_cert: PathBuf,
    pub panel_key: PathBuf,
    pub panel_secret_file: PathBuf,
    pub panel_id: String,
    pub panel_max_connections: usize,
    pub max_agent_command_queue: usize,
    pub max_broadcast_targets: usize,
    pub max_control_requests_per_second: u32,
    pub websocket_path: String,
    pub onion_port: u16,
    pub max_connections: usize,
    pub max_auth_inflight: usize,
    pub max_ipc_queue: usize,
    pub max_messages_per_second: u32,
    pub handshake_timeout: Duration,
    pub auth_timeout: Duration,
    pub idle_timeout: Duration,
    pub ping_interval: Duration,
    pub metrics_interval: Duration,
}

impl Default for Config {
    fn default() -> Self {
        let data_dir = PathBuf::from("/var/lib/ztsec");
        Self {
            onion_nickname: "ztsec".into(),
            state_dir: data_dir.join("arti-state"),
            cache_dir: data_dir.join("arti-cache"),
            authorized_keys: PathBuf::from("/etc/ztsec/authorized_keys"),
            local_listen: None,
            direct_listen: DEFAULT_DIRECT_LISTEN.into(),
            enable_onion: true,
            local_socket: PathBuf::from(DEFAULT_LOCAL_SOCKET),
            control_socket: PathBuf::from(DEFAULT_CONTROL_SOCKET),
            panel_listen: None,
            panel_cert: PathBuf::from("/etc/ztsec/panel/server.crt"),
            panel_key: PathBuf::from("/etc/ztsec/panel/server.key"),
            panel_secret_file: PathBuf::from("/etc/ztsec/panel/secret"),
            panel_id: "panel-01".into(),
            panel_max_connections: 64,
            max_agent_command_queue: 16,
            max_broadcast_targets: 4096,
            max_control_requests_per_second: 10,
            websocket_path: "/ztsec".into(),
            onion_port: 443,
            max_connections: 4096,
            max_auth_inflight: 64,
            max_ipc_queue: 256,
            max_messages_per_second: 10,
            handshake_timeout: Duration::from_secs(8),
            auth_timeout: Duration::from_secs(8),
            idle_timeout: Duration::from_secs(90),
            ping_interval: Duration::from_secs(30),
            metrics_interval: Duration::from_secs(30),
        }
    }
}

#[derive(Default)]
pub struct Metrics {
    active: AtomicUsize,
    accepted: AtomicU64,
    closed: AtomicU64,
    auth_success: AtomicU64,
    auth_failure: AtomicU64,
    malformed: AtomicU64,
    oversized: AtomicU64,
    rate_limited: AtomicU64,
    ipc_dropped: AtomicU64,
    ipc_connected: AtomicBool,
}

impl Metrics {
    pub fn snapshot(&self, queue_len: usize) -> String {
        format!(
            "active={} accepted={} closed={} auth_success={} auth_failure={} malformed={} oversized={} rate_limited={} ipc_queue={} ipc_dropped={} ipc_connected={}",
            self.active.load(Ordering::Relaxed), self.accepted.load(Ordering::Relaxed), self.closed.load(Ordering::Relaxed),
            self.auth_success.load(Ordering::Relaxed), self.auth_failure.load(Ordering::Relaxed), self.malformed.load(Ordering::Relaxed),
            self.oversized.load(Ordering::Relaxed), self.rate_limited.load(Ordering::Relaxed), queue_len,
            self.ipc_dropped.load(Ordering::Relaxed), self.ipc_connected.load(Ordering::Relaxed)
        )
    }
}

#[derive(Clone)]
struct KeyStore {
    by_fingerprint: Arc<HashMap<String, Vec<VerifyingKey>>>,
}

impl KeyStore {
    fn load(path: &Path) -> io::Result<Self> {
        let contents = fs::read_to_string(path).map_err(|e| io::Error::new(e.kind(), format!("unable to read authorized key file {}: {e}", path.display())))?;
        let mut by_fingerprint: HashMap<String, Vec<VerifyingKey>> = HashMap::new();
        for (line_no, raw) in contents.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') { continue; }
            let mut parts = line.split_whitespace();
            let fingerprint = parts.next().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, format!("authorized key line {} missing fingerprint", line_no + 1)))?;
            let public_hex = parts.next().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, format!("authorized key line {} missing public key", line_no + 1)))?;
            if parts.next().is_some() || fingerprint.len() != 64 || !fingerprint.bytes().all(|b| b.is_ascii_hexdigit()) || public_hex.len() != 64 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, format!("invalid authorized key line {}", line_no + 1)));
            }
            let public_bytes = hex32(public_hex).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, format!("invalid public key on line {}", line_no + 1)))?;
            let key = VerifyingKey::from_bytes(&public_bytes).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, format!("invalid Ed25519 public key on line {}", line_no + 1)))?;
            by_fingerprint.entry(fingerprint.to_ascii_lowercase()).or_default().push(key);
        }
        if by_fingerprint.is_empty() { return Err(io::Error::new(io::ErrorKind::InvalidData, "authorized key file contains no keys")); }
        Ok(Self { by_fingerprint: Arc::new(by_fingerprint) })
    }

    fn verify(&self, fingerprint: &str, public_key: &[u8; 32], message: &[u8], signature: &Signature) -> bool {
        let Some(keys) = self.by_fingerprint.get(&fingerprint.to_ascii_lowercase()) else { return false; };
        if !keys.iter().any(|key| key.as_bytes() == public_key) { return false; }
        keys.iter().filter(|key| key.as_bytes() == public_key).any(|key| key.verify(message, signature).is_ok())
    }
}

#[derive(Debug)]
struct RateLimiter {
    window_start: Instant,
    count: u32,
    max_per_second: u32,
}

impl RateLimiter {
    fn new(max_per_second: u32) -> Self { Self { window_start: Instant::now(), count: 0, max_per_second } }
    fn allow(&mut self) -> bool {
        if self.window_start.elapsed() >= Duration::from_secs(1) {
            self.window_start = Instant::now();
            self.count = 0;
        }
        if self.count >= self.max_per_second { return false; }
        self.count += 1;
        true
    }
}

pub struct Server {
    config: Config,
    keys: KeyStore,
    metrics: Arc<Metrics>,
    ipc_tx: mpsc::Sender<Vec<u8>>,
    sequence: Arc<AtomicU64>,
    connection_limit: Arc<Semaphore>,
    auth_limit: Arc<Semaphore>,
    shutdown: watch::Sender<bool>,
    registry: AgentRegistry,
    control_limit: Arc<Semaphore>,
    session_ids: Arc<AtomicU64>,
    panel_hub: PanelHub,
}

impl Server {
    pub fn new(config: Config) -> io::Result<(Self, mpsc::Receiver<Vec<u8>>)> {
        if config.websocket_path.is_empty() || !config.websocket_path.starts_with('/') { return Err(io::Error::new(io::ErrorKind::InvalidInput, "websocket path must start with '/'") ); }
        if config.max_connections == 0 || config.max_auth_inflight == 0 || config.max_ipc_queue == 0 || config.panel_max_connections == 0
            || config.max_messages_per_second == 0 || config.max_agent_command_queue == 0
            || config.max_broadcast_targets == 0 || config.max_control_requests_per_second == 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "resource limits must be non-zero"));
        }
        if config.panel_id.is_empty() || config.panel_id.len() > 64 || config.panel_id.bytes().any(|byte| !byte.is_ascii_graphic()) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "panel ID must be 1-64 ASCII graphic characters"));
        }
        validate_direct_listener_configuration(&config)?;
        let keys = KeyStore::load(&config.authorized_keys)?;
        let (ipc_tx, ipc_rx) = mpsc::channel(config.max_ipc_queue);
        let panel_hub = PanelHub::new(config.max_ipc_queue);
        let (shutdown, _) = watch::channel(false);
        let server = Self {
            connection_limit: Arc::new(Semaphore::new(config.max_connections)),
            auth_limit: Arc::new(Semaphore::new(config.max_auth_inflight)),
            config,
            keys,
            metrics: Arc::new(Metrics::default()),
            ipc_tx,
            sequence: Arc::new(AtomicU64::new(0)),
            shutdown,
            registry: AgentRegistry::default(),
            control_limit: Arc::new(Semaphore::new(16)),
            session_ids: Arc::new(AtomicU64::new(1)),
            panel_hub,
        };
        Ok((server, ipc_rx))
    }

    pub fn metrics(&self) -> Arc<Metrics> { Arc::clone(&self.metrics) }

    pub async fn run(self, mut ipc_rx: mpsc::Receiver<Vec<u8>>) -> io::Result<()> {
        // Bind all local/public listeners before spawning background workers so a bind failure
        // cannot leave already-started tasks or socket files behind.
        let ipc_path = self.config.local_socket.clone();
        let ipc_listener = bind_ipc_listener(&ipc_path)?;
        let control_path = self.config.control_socket.clone();
        let control_listener = match bind_control_listener(&control_path) {
            Ok(listener) => listener,
            Err(error) => {
                let _ = fs::remove_file(&ipc_path);
                return Err(error);
            }
        };
        let local_listener = match self.config.local_listen.clone() {
            Some(address) => match TcpListener::bind(&address).await {
                Ok(listener) => Some(listener),
                Err(error) => {
                    let _ = fs::remove_file(&control_path);
                    let _ = fs::remove_file(&ipc_path);
                    return Err(io::Error::new(error.kind(), format!("bind local test listener {address}: {error}")));
                }
            },
            None => None,
        };
        let direct_listener = match TcpListener::bind(&self.config.direct_listen).await {
            Ok(listener) => listener,
            Err(error) => {
                let _ = fs::remove_file(&control_path);
                let _ = fs::remove_file(&ipc_path);
                return Err(io::Error::new(error.kind(), format!("bind direct listener {}: {error}", self.config.direct_listen)));
            }
        };
        let panel_listener = if let Some(address) = self.config.panel_listen.clone() {
            panel::validate_secret_file(&self.config.panel_secret_file)?;
            let listener = TcpListener::bind(&address).await.map_err(|error| {
                let _ = fs::remove_file(&control_path);
                let _ = fs::remove_file(&ipc_path);
                io::Error::new(error.kind(), format!("bind panel listener {address}: {error}"))
            })?;
            let tls = panel::build_tls_acceptor(&self.config.panel_cert, &self.config.panel_key)?;
            Some((listener, Arc::new(tls)))
        } else {
            None
        };

        let ipc_metrics = Arc::clone(&self.metrics);
        let ipc_shutdown = self.shutdown.subscribe();
        let ipc_queue_limit = self.config.max_ipc_queue;
        let ipc_task = tokio::spawn(async move { ipc_worker(ipc_listener, ipc_path, &mut ipc_rx, ipc_metrics, ipc_queue_limit, ipc_shutdown).await });

        let control_server = self.clone_for_task();
        let control_limit = Arc::clone(&self.control_limit);
        let control_task = tokio::spawn(async move { control_worker(control_server, control_listener, control_path, control_limit).await });

        let local_task = local_listener.map(|listener| {
            info!("local test listener enabled");
            let server = self.clone_for_task();
            tokio::spawn(async move { server.accept_tcp(listener).await })
        });
        info!("direct WebSocket listener enabled on {}", self.config.direct_listen);
        let direct_task = {
            let server = self.clone_for_task();
            tokio::spawn(async move { server.accept_tcp(direct_listener).await })
        };
        let panel_task = panel_listener.map(|(listener, tls)| {
            info!(address = ?self.config.panel_listen, "external panel gateway enabled (TLS + challenge/response; telemetry only)");
            let panel_config = panel::PanelConfig {
                cert: self.config.panel_cert.clone(),
                key: self.config.panel_key.clone(),
                secret_file: self.config.panel_secret_file.clone(),
                panel_id: self.config.panel_id.clone(),
                handshake_timeout: self.config.auth_timeout,
                idle_timeout: self.config.idle_timeout,
            };
            let hub = self.panel_hub.clone();
            let limit = Arc::new(Semaphore::new(self.config.panel_max_connections));
            let shutdown = self.shutdown.subscribe();
            tokio::spawn(async move { panel::run(listener, tls, panel_config, hub, limit, shutdown).await })
        });

        let onion_service = if self.config.enable_onion {
            let (service, request_stream) = match self.launch_onion_service().await {
                Ok(value) => value,
                Err(error) => {
                    self.shutdown();
                    ipc_task.abort();
                    control_task.abort();
                    direct_task.abort();
                    let _ = fs::remove_file(&self.config.control_socket);
                    let _ = fs::remove_file(&self.config.local_socket);
                    return Err(error);
                }
            };
            info!(address = ?service.onion_address(), "onion service started");
            let server = self.clone_for_task();
            let onion_task = tokio::spawn(async move {
                server.accept_onion_requests(request_stream).await;
            });
            Some((service, onion_task))
        } else {
            None
        };

        let metrics_task = {
            let metrics = Arc::clone(&self.metrics);
            let mut shutdown = self.shutdown.subscribe();
            let tx = self.ipc_tx.clone();
            let queue_limit = self.config.max_ipc_queue;
            let metrics_interval = self.config.metrics_interval;
            let mut tick = interval(metrics_interval);
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = tick.tick() => info!("server metrics {}", metrics.snapshot(queue_limit.saturating_sub(tx.capacity()))),
                        changed = shutdown.changed() => if changed.is_err() || *shutdown.borrow() { break; },
                    }
                }
            })
        };

        let mut shutdown_rx = self.shutdown.subscribe();
        let result = tokio::select! {
            signal = tokio::signal::ctrl_c() => {
                if let Err(error) = signal { warn!(?error, "ctrl-c handler failed"); }
                Ok(())
            }
            changed = shutdown_rx.changed() => {
                if changed.is_err() || *shutdown_rx.borrow() { Ok(()) } else { Ok(()) }
            }
        };

        self.shutdown();
        if let Some(task) = local_task { task.abort(); }
        direct_task.abort();
        if let Some(task) = panel_task { task.abort(); }
        control_task.abort();
        let _ = fs::remove_file(&self.config.control_socket);
        metrics_task.abort();
        if let Some((service, task)) = onion_service {
            drop(service);
            let _ = timeout(Duration::from_secs(5), task).await;
        }
        let _ = timeout(Duration::from_secs(5), ipc_task).await;
        result
    }

    fn clone_for_task(&self) -> Self {
        Self {
            config: self.config.clone(), keys: self.keys.clone(), metrics: Arc::clone(&self.metrics), ipc_tx: self.ipc_tx.clone(),
            sequence: Arc::clone(&self.sequence), connection_limit: Arc::clone(&self.connection_limit), auth_limit: Arc::clone(&self.auth_limit), shutdown: self.shutdown.clone(),
            registry: self.registry.clone(), control_limit: Arc::clone(&self.control_limit), session_ids: Arc::clone(&self.session_ids), panel_hub: self.panel_hub.clone(),
        }
    }

    pub async fn launch_onion_service(&self) -> io::Result<(Arc<RunningOnionService>, impl futures_util::Stream<Item = tor_hsservice::RendRequest> + use<>)> {
        fs::create_dir_all(&self.config.state_dir)?;
        fs::create_dir_all(&self.config.cache_dir)?;
        let config = TorClientConfigBuilder::from_directories(&self.config.state_dir, &self.config.cache_dir)
            .build()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("invalid Arti server configuration: {e}")))?;
        let client = TorClient::create_bootstrapped(config).await.map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Arti bootstrap failed: {e}")))?;
        let nickname = self.config.onion_nickname.parse().map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("invalid onion nickname: {e}")))?;
        let service_config = OnionServiceConfigBuilder::default()
            .nickname(nickname)
            .num_intro_points(3)
            .rate_limit_at_intro(Some(TokenBucketConfig::new(16, 32)))
            .max_concurrent_streams_per_circuit(128)
            .build()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("invalid onion service config: {e}")))?;
        client.launch_onion_service(service_config)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("launch onion service failed: {e}")))?
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Arti onion services are disabled in configuration"))
    }

    async fn accept_onion_requests(self, request_stream: impl futures_util::Stream<Item = tor_hsservice::RendRequest>) {
        let stream_requests = tor_hsservice::handle_rend_requests(request_stream);
        tokio::pin!(stream_requests);
        let mut shutdown = self.shutdown.subscribe();
        loop {
            let request = tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() { break; }
                    continue;
                }
                request = stream_requests.next() => request,
            };
            let Some(stream_request) = request else { break; };
            self.metrics.accepted.fetch_add(1, Ordering::Relaxed);
            let request_port = match stream_request.request() {
                IncomingStreamRequest::Begin(begin) => begin.port(),
                _ => {
                    self.metrics.malformed.fetch_add(1, Ordering::Relaxed);
                    let _ = stream_request.shutdown_circuit();
                    continue;
                }
            };
            if request_port != self.config.onion_port {
                let _ = stream_request.shutdown_circuit();
                continue;
            }
            let Ok(permit) = self.connection_limit.clone().try_acquire_owned() else {
                self.metrics.rate_limited.fetch_add(1, Ordering::Relaxed);
                let _ = stream_request.shutdown_circuit();
                continue;
            };
            let server = self.clone_for_task();
            tokio::spawn(async move { server.handle_onion_stream(stream_request, permit).await; });
        }
        self.shutdown();
    }

    async fn accept_tcp(self, listener: TcpListener) -> io::Result<()> {
        let mut shutdown = self.shutdown.subscribe();
        loop {
            tokio::select! {
                changed = shutdown.changed() => if changed.is_err() || *shutdown.borrow() { return Ok(()); },
                accepted = listener.accept() => {
                    let (stream, peer) = accepted?;
                    self.metrics.accepted.fetch_add(1, Ordering::Relaxed);
                    let Ok(permit) = self.connection_limit.clone().try_acquire_owned() else { self.metrics.rate_limited.fetch_add(1, Ordering::Relaxed); continue; };
                    let server = self.clone_for_task();
                    tokio::spawn(async move { server.handle_tcp_stream(stream, peer.to_string(), permit).await; });
                }
            }
        }
    }

    async fn handle_onion_stream(self, stream_request: StreamRequest, permit: OwnedSemaphorePermit) {
        match stream_request.accept(Connected::new_empty()).await {
            Ok(stream) => self.handle_stream(stream, "onion".into(), permit).await,
            Err(error) => { self.metrics.closed.fetch_add(1, Ordering::Relaxed); debug!(?error, "failed to accept onion stream"); }
        }
    }

    async fn handle_tcp_stream(self, stream: TcpStream, peer: String, permit: OwnedSemaphorePermit) {
        self.handle_stream(stream, peer, permit).await;
    }

    async fn handle_stream<S>(self, stream: S, peer: String, _permit: OwnedSemaphorePermit)
    where S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static {
        self.metrics.active.fetch_add(1, Ordering::Relaxed);
        let result = self.websocket_session(stream, &peer).await;
        self.metrics.active.fetch_sub(1, Ordering::Relaxed);
        self.metrics.closed.fetch_add(1, Ordering::Relaxed);
        if let Err(error) = result {
            debug!(peer = %peer, ?error, "connection closed with error");
        }
    }

    async fn websocket_session<S>(&self, stream: S, _peer: &str) -> io::Result<()>
    where S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static {
        let expected_path = self.config.websocket_path.clone();
        let callback = move |request: &tokio_tungstenite::tungstenite::handshake::server::Request, response: tokio_tungstenite::tungstenite::handshake::server::Response| {
            if request.uri().path() != expected_path {
                let mut error_response = response.map(|_| Some("invalid WebSocket path".to_owned()));
                *error_response.status_mut() = tokio_tungstenite::tungstenite::http::StatusCode::NOT_FOUND;
                return Err(error_response);
            }
            Ok(response)
        };
        let mut ws = timeout(self.config.handshake_timeout, tokio_tungstenite::accept_hdr_async_with_config(stream, callback, Some(ws_config()))).await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "WebSocket handshake timeout"))?
            .map_err(ws_err)?;
        let fingerprint = self.authenticate(&mut ws).await?;
        let session_id = self.session_ids.fetch_add(1, Ordering::Relaxed);
        let mut command_registration = self.registry.register(fingerprint.clone(), session_id, self.config.max_agent_command_queue).await;
        let mut limiter = RateLimiter::new(self.config.max_messages_per_second);
        let mut ping_tick = interval(self.config.ping_interval);
        let mut last_activity = Instant::now();

        let result = async {
            loop {
                let step = tokio::select! {
                _ = ping_tick.tick() => {
                    if last_activity.elapsed() > self.config.idle_timeout {
                        Ok(true)
                    } else {
                        ws.send(tokio_tungstenite::tungstenite::Message::Ping(Vec::new().into())).await.map_err(ws_err).map(|_| false)
                    }
                }
                command = command_registration.rx.recv() => {
                    match command {
                        Some(command) => ws.send(tokio_tungstenite::tungstenite::Message::Text(command.as_ref().to_owned().into())).await.map_err(ws_err).map(|_| false),
                        None => Ok(true),
                    }
                }
                message = timeout(self.config.idle_timeout, ws.next()) => {
                    match message {
                        Err(_) => Ok(true),
                        Ok(Some(Ok(tokio_tungstenite::tungstenite::Message::Text(text)))) => {
                            last_activity = Instant::now();
                            if !limiter.allow() {
                                self.metrics.rate_limited.fetch_add(1, Ordering::Relaxed);
                                Err(io::Error::new(io::ErrorKind::PermissionDenied, "message rate limit exceeded"))
                            } else if text.len() > ztsec_protocol::MAX_WS_MESSAGE_BYTES {
                                self.metrics.oversized.fetch_add(1, Ordering::Relaxed);
                                Err(io::Error::new(io::ErrorKind::InvalidData, "WebSocket message too large"))
                            } else {
                                self.handle_application_message(&mut ws, text.as_ref(), &fingerprint).await.map(|_| false)
                            }
                        }
                        Ok(Some(Ok(tokio_tungstenite::tungstenite::Message::Ping(payload)))) => {
                            last_activity = Instant::now();
                            ws.send(tokio_tungstenite::tungstenite::Message::Pong(payload)).await.map_err(ws_err).map(|_| false)
                        }
                        Ok(Some(Ok(tokio_tungstenite::tungstenite::Message::Pong(_)))) => {
                            last_activity = Instant::now();
                            Ok(false)
                        }
                        Ok(Some(Ok(tokio_tungstenite::tungstenite::Message::Binary(_)))) => {
                            self.metrics.malformed.fetch_add(1, Ordering::Relaxed);
                            Err(io::Error::new(io::ErrorKind::InvalidData, "binary messages are not supported"))
                        }
                        Ok(Some(Ok(tokio_tungstenite::tungstenite::Message::Close(_)))) | Ok(None) => Ok(true),
                        Ok(Some(Ok(tokio_tungstenite::tungstenite::Message::Frame(_)))) => Ok(false),
                        Ok(Some(Err(error))) => Err(ws_err(error)),
                    }
                }
                }?;
                if step {
                    break;
                }
            }
            Ok::<(), io::Error>(())
        }.await;

        // Always unregister, including when the session exits through a WebSocket/protocol error.
        // The session ID prevents an older connection from removing a newer registration with
        // the same fingerprint.
        self.registry.unregister(&fingerprint, session_id).await;
        result
    }

    async fn authenticate<S>(&self, ws: &mut tokio_tungstenite::WebSocketStream<S>) -> io::Result<String>
    where S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin {
        let permit = timeout(self.config.auth_timeout, self.auth_limit.clone().acquire_owned()).await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "authentication admission timeout"))?
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "authentication semaphore closed"))?;
        let first = timeout(self.config.auth_timeout, ws.next()).await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "authentication timeout"))?
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "client closed during authentication"))?
            .map_err(ws_err)?;
        let fingerprint = match first { tokio_tungstenite::tungstenite::Message::Text(text) => ztsec_protocol::parse_fingerprint_line(text.as_ref()).map_err(protocol_err)?.to_owned(), _ => return Err(io::Error::new(io::ErrorKind::PermissionDenied, "authentication must begin with fingerprint hello")) };
        let mut nonce = [0u8; 32];
        getrandom::getrandom(&mut nonce).map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        ws.send(tokio_tungstenite::tungstenite::Message::Text(format!("AUTH:CHALLENGE:{}", STANDARD.encode(nonce)).into())).await.map_err(ws_err)?;
        let response = timeout(self.config.auth_timeout, ws.next()).await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "authentication response timeout"))?
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "client closed during authentication response"))?
            .map_err(ws_err)?;
        let (public_hex, signature_b64) = match response {
            tokio_tungstenite::tungstenite::Message::Text(text) => parse_auth_response(text.as_ref())?,
            _ => return Err(io::Error::new(io::ErrorKind::PermissionDenied, "authentication response must be text")),
        };
        let public_key = hex32(&public_hex).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid authentication public key"))?;
        if signature_b64.len() > 128 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "authentication signature too large"));
        }
        let signature_bytes = STANDARD.decode(signature_b64).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid authentication signature"))?;
        let signature_array: [u8; 64] = signature_bytes.as_slice().try_into().map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid authentication signature length"))?;
        let signature = Signature::from_bytes(&signature_array);
        let valid = self.keys.verify(&fingerprint, &public_key, &ztsec_protocol::auth_message(&fingerprint, &nonce), &signature);
        drop(permit);
        if !valid {
            self.metrics.auth_failure.fetch_add(1, Ordering::Relaxed);
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, "authentication failed"));
        }
        self.metrics.auth_success.fetch_add(1, Ordering::Relaxed);
        ws.send(tokio_tungstenite::tungstenite::Message::Text("AUTH:OK".into())).await.map_err(ws_err)?;
        info!(fingerprint_prefix = %&fingerprint[..fingerprint.len().min(12)], "agent authenticated");
        Ok(fingerprint)
    }

    async fn handle_application_message<S>(&self, ws: &mut tokio_tungstenite::WebSocketStream<S>, text: &str, fingerprint: &str) -> io::Result<bool>
    where S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin {
        if text == "HB" { ws.send(tokio_tungstenite::tungstenite::Message::Text("PONG".into())).await.map_err(ws_err)?; return Ok(false); }
        if text == "PONG" { return Ok(false); }
        if text.starts_with("ACK:") || text.starts_with("ERR:") {
            debug!(fingerprint_prefix = %&fingerprint[..fingerprint.len().min(12)], message = %text, "agent command response");
            return Ok(false);
        }
        if text == "REQ:DATA" { ws.send(tokio_tungstenite::tungstenite::Message::Text("PONG".into())).await.map_err(ws_err)?; return Ok(false); }
        if !text.starts_with("DATA:") {
            self.metrics.malformed.fetch_add(1, Ordering::Relaxed);
            let _ = ws.send(tokio_tungstenite::tungstenite::Message::Text("ERR:UNSUPPORTED_MESSAGE".into())).await;
            return Err(io::Error::new(io::ErrorKind::InvalidData, "unsupported application message"));
        }
        let telemetry = ztsec_protocol::parse_data_line(text).map_err(|error| { self.metrics.malformed.fetch_add(1, Ordering::Relaxed); protocol_err(error) })?;
        telemetry.validate(fingerprint).map_err(|error| { self.metrics.malformed.fetch_add(1, Ordering::Relaxed); protocol_err(error) })?;
        let timestamp_ms = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis().min(u64::MAX as u128) as u64;
        let sequence_number = self.sequence.fetch_add(1, Ordering::Relaxed);
        let envelope = ztsec_protocol::IpcEnvelope { protocol_version: ztsec_protocol::PROTOCOL_VERSION, message_type: "telemetry", agent_id: fingerprint, fingerprint, timestamp_ms, sequence_number, telemetry: &telemetry };
        let payload = serde_json::to_vec(&envelope).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        let mut frame = Vec::with_capacity(4 + payload.len());
        frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        frame.extend_from_slice(&payload);
        let payload_len = payload.len();
        if payload_len > 256 * 1024 { self.metrics.oversized.fetch_add(1, Ordering::Relaxed); return Err(io::Error::new(io::ErrorKind::InvalidData, "IPC payload too large")); }
        match self.ipc_tx.try_send(frame) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => { self.metrics.ipc_dropped.fetch_add(1, Ordering::Relaxed); return Err(io::Error::new(io::ErrorKind::WouldBlock, "Python IPC queue full")); }
            Err(mpsc::error::TrySendError::Closed(_)) => return Err(io::Error::new(io::ErrorKind::BrokenPipe, "Python IPC is unavailable")),
        }
        self.panel_hub.publish(String::from_utf8(payload).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "telemetry JSON was not UTF-8"))?, fingerprint).await;
        // This acknowledgement is intentionally small: it provides a deterministic readiness signal for
        // the updater while avoiding application-level buffering on the Rust side.
        ws.send(tokio_tungstenite::tungstenite::Message::Text("ACK:DATA".into())).await.map_err(ws_err)?;
        Ok(false)
    }

    fn shutdown(&self) { let _ = self.shutdown.send(true); }
}


async fn control_worker(server: Server, listener: UnixListener, path: PathBuf, control_limit: Arc<Semaphore>) -> io::Result<()> {
    let mut shutdown = server.shutdown.subscribe();
    loop {
        let (stream, _) = tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() { break; }
                continue;
            }
            accepted = listener.accept() => accepted.map_err(|e| io::Error::new(e.kind(), format!("accept control IPC connection: {e}")))?,
        };
        let Ok(permit) = control_limit.clone().try_acquire_owned() else {
            continue;
        };
        let worker = server.clone_for_task();
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(error) = handle_control_client(&worker, stream).await {
                debug!(?error, "control IPC client closed");
            }
        });
    }
    let _ = fs::remove_file(path);
    Ok(())
}

async fn handle_control_client(server: &Server, stream: tokio::net::UnixStream) -> io::Result<()> {
    let (mut reader, mut writer) = stream.into_split();
    let mut limiter = RateLimiter::new(server.config.max_control_requests_per_second);
    loop {
        let mut header = [0u8; 4];
        match timeout(Duration::from_secs(10), reader.read_exact(&mut header)).await {
            Ok(Ok(_)) => {}
            Ok(Err(error)) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Ok(Err(error)) => return Err(error),
            Err(_) => return Err(io::Error::new(io::ErrorKind::TimedOut, "control IPC idle timeout")),
        }
        let len = u32::from_be_bytes(header) as usize;
        if len == 0 || len > ztsec_protocol::MAX_CONTROL_FRAME_BYTES {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "control IPC frame too large"));
        }
        let mut payload = vec![0u8; len];
        match timeout(Duration::from_secs(10), reader.read_exact(&mut payload)).await {
            Ok(Ok(_)) => {}
            Ok(Err(error)) => return Err(error),
            Err(_) => return Err(io::Error::new(io::ErrorKind::TimedOut, "control IPC payload timeout")),
        }
        let response = match serde_json::from_slice::<ztsec_protocol::ControlRequest>(&payload) {
            Ok(request) => {
                if !limiter.allow() {
                    server.metrics.rate_limited.fetch_add(1, Ordering::Relaxed);
                    control_response(request.request_id.clone(), request.target.clone(), "rate_limited", 0, 0, "control request rate limit exceeded".into())
                } else {
                    server.route_control(request).await
                }
            }
            Err(error) => ztsec_protocol::ControlResponse {
                protocol_version: ztsec_protocol::PROTOCOL_VERSION,
                message_type: "agent_command_result".into(),
                request_id: String::new(),
                status: "rejected".into(),
                target: String::new(),
                queued: 0,
                dropped: 0,
                detail: format!("invalid control request: {error}"),
            },
        };
        let body = serde_json::to_vec(&response).map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        if body.len() > ztsec_protocol::MAX_CONTROL_FRAME_BYTES {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "control response too large"));
        }
        timeout(Duration::from_secs(10), writer.write_all(&(body.len() as u32).to_be_bytes())).await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "control IPC response timeout"))??;
        timeout(Duration::from_secs(10), writer.write_all(&body)).await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "control IPC response timeout"))??;
    }
}

impl Server {
    async fn route_control(&self, request: ztsec_protocol::ControlRequest) -> ztsec_protocol::ControlResponse {
        let target = request.target.clone();
        let request_id = request.request_id.clone();
        if let Err(error) = request.validate() {
            return control_response(request_id, target, "rejected", 0, 0, error.to_string());
        }
        if !valid_control_target(&request.target) {
            return control_response(request_id, target, "rejected", 0, 0, "target must be 'broadcast' or a 64-hex agent fingerprint".into());
        }
        let command = match materialize_relay_command(&request.command, &self.config).await {
            Ok(command) => command,
            Err(error) => return control_response(request_id, target, "rejected", 0, 0, error),
        };
        let (queued, dropped, status) = self.registry.route(&request.target, command, self.config.max_broadcast_targets).await;
        match status {
            RouteStatus::Queued => control_response(request_id, target, "queued", queued, dropped, "command queued".into()),
            RouteStatus::QueueFull => control_response(request_id, target, "partial", queued, dropped, "one or more agent command queues were full".into()),
            RouteStatus::NotConnected => control_response(request_id, target, "offline", queued, dropped, "target agent is not connected".into()),
        }
    }
}

fn control_response(request_id: String, target: String, status: &str, queued: usize, dropped: usize, detail: String) -> ztsec_protocol::ControlResponse {
    let detail: String = detail.chars().take(512).collect();
    ztsec_protocol::ControlResponse {
        protocol_version: ztsec_protocol::PROTOCOL_VERSION,
        message_type: "agent_command_result".into(),
        request_id,
        status: status.into(),
        target,
        queued,
        dropped,
        detail,
    }
}

fn strip_prefix_ascii_ci<'a>(value: &'a str, prefix: &str) -> Option<&'a str> {
    value.get(..prefix.len()).filter(|head| head.eq_ignore_ascii_case(prefix)).map(|_| &value[prefix.len()..])
}

fn valid_control_target(target: &str) -> bool {
    target.eq_ignore_ascii_case("broadcast") || (target.len() == 64 && target.bytes().all(|b| b.is_ascii_hexdigit()))
}

async fn materialize_relay_command(command: &str, config: &Config) -> Result<Arc<str>, String> {
    let normalized = command.trim();
    if normalized.eq_ignore_ascii_case("CMD:DIRECT_CONNECT") {
        let listen_addr = config.direct_listen.as_str()
            .parse::<SocketAddr>()
            .map_err(|_| "server direct-listen address is invalid".to_owned())?;
        let public = public_ip::resolve_public_ip(listen_addr)
            .await
            .map_err(|error| format!("unable to determine server public IP: {error}"))?;
        return Ok(materialize_direct_command(public, listen_addr));
    }
    if strip_prefix_ascii_ci(normalized, "CMD:DIRECT_CONNECT:").is_some() {
        return Err("direct-connect must omit the IP and port; the server discovers its public IP via ifconfig.me".into());
    }
    if !ztsec_protocol::is_supported_agent_command(normalized) {
        return Err("command is not supported by the ZTSEC agent protocol".into());
    }
    Ok(Arc::<str>::from(normalized.to_owned()))
}

fn materialize_direct_command(public_ip: IpAddr, listen_addr: SocketAddr) -> Arc<str> {
    let host = match public_ip {
        IpAddr::V4(ip) => ip.to_string(),
        IpAddr::V6(ip) => format!("[{ip}]"),
    };
    Arc::<str>::from(format!("CMD:DIRECT_CONNECT:{host}:{}", listen_addr.port()))
}

fn validate_direct_listener_configuration(config: &Config) -> io::Result<()> {
    let listen_addr = config.direct_listen.parse::<SocketAddr>().map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "direct listener must be an IP:PORT socket address"))?;
    if listen_addr.port() == 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "direct listener port must not be zero"));
    }
    Ok(())
}

fn bind_control_listener(path: &Path) -> io::Result<UnixListener> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if !metadata.file_type().is_socket() {
            return Err(io::Error::new(io::ErrorKind::AlreadyExists, format!("control IPC path {} exists and is not a Unix socket", path.display())));
        }
        fs::remove_file(path)?;
    }
    let listener = UnixListener::bind(path).map_err(|e| io::Error::new(e.kind(), format!("bind control IPC socket {}: {e}", path.display())))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = fs::metadata(path)?.permissions();
        permissions.set_mode(0o660);
        fs::set_permissions(path, permissions)?;
    }
    Ok(listener)
}

fn bind_ipc_listener(path: &Path) -> io::Result<UnixListener> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    if let Ok(metadata) = fs::symlink_metadata(path) {
        #[cfg(unix)]
        {
            if !metadata.file_type().is_socket() {
                return Err(io::Error::new(io::ErrorKind::AlreadyExists, format!("IPC path {} exists and is not a Unix socket", path.display())));
            }
        }
        #[cfg(not(unix))]
        {
            let _ = metadata;
            return Err(io::Error::new(io::ErrorKind::Unsupported, "Unix IPC socket is only supported on Unix"));
        }
        fs::remove_file(path)?;
    }
    let listener = UnixListener::bind(path)
        .map_err(|e| io::Error::new(e.kind(), format!("bind IPC socket {}: {e}", path.display())))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = fs::metadata(path)?.permissions();
        permissions.set_mode(0o660);
        fs::set_permissions(path, permissions)?;
    }
    Ok(listener)
}

async fn ipc_worker(
    listener: UnixListener,
    path: PathBuf,
    rx: &mut mpsc::Receiver<Vec<u8>>,
    metrics: Arc<Metrics>,
    queue_limit: usize,
    mut shutdown: watch::Receiver<bool>,
) -> io::Result<()> {
    loop {
        if *shutdown.borrow() {
            break;
        }
        let (stream, _) = tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() { break; }
                continue;
            }
            accepted = listener.accept() => accepted.map_err(|e| io::Error::new(e.kind(), format!("accept Python IPC connection: {e}")))?,
        };
        metrics.ipc_connected.store(true, Ordering::Relaxed);
        let (mut reader, mut writer) = stream.into_split();
        let (disconnect_tx, mut disconnect_rx) = tokio::sync::oneshot::channel::<()>();
        let reader_task = tokio::spawn(async move {
            let mut byte = [0u8; 1];
            loop {
                match reader.read(&mut byte).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
            let _ = disconnect_tx.send(());
        });

        loop {
            let frame = tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() { break; }
                    continue;
                }
                disconnected = &mut disconnect_rx => {
                    let _ = disconnected;
                    break;
                }
                frame = rx.recv() => {
                    let Some(frame) = frame else {
                        let _ = writer.shutdown().await;
                        reader_task.abort();
                        metrics.ipc_connected.store(false, Ordering::Relaxed);
                        let _ = fs::remove_file(&path);
                        return Ok(());
                    };
                    frame
                }
            };
            if frame.len() < 4 || frame.len() - 4 > 256 * 1024 {
                metrics.ipc_dropped.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            match timeout(Duration::from_secs(2), writer.write_all(&frame)).await {
                Ok(Ok(_)) => {}
                Ok(Err(error)) => {
                    debug!(?error, queue_limit, "Python IPC connection dropped while forwarding telemetry");
                    metrics.ipc_connected.store(false, Ordering::Relaxed);
                    break;
                }
                Err(_) => {
                    debug!(queue_limit, "Python IPC writer timed out");
                    metrics.ipc_connected.store(false, Ordering::Relaxed);
                    break;
                }
            }
        }
        reader_task.abort();
        metrics.ipc_connected.store(false, Ordering::Relaxed);
    }
    metrics.ipc_connected.store(false, Ordering::Relaxed);
    let _ = fs::remove_file(&path);
    Ok(())
}

fn parse_auth_response(line: &str) -> io::Result<(String, String)> {
    let rest = line.strip_prefix("AUTH:RESPONSE:").ok_or_else(|| io::Error::new(io::ErrorKind::PermissionDenied, "invalid authentication response"))?;
    let mut parts = rest.split(':');
    let public = parts.next().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing public key"))?;
    let signature = parts.next().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing signature"))?;
    if parts.next().is_some() || public.len() != 64 || !public.bytes().all(|b| b.is_ascii_hexdigit()) { return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid authentication public key")); }
    Ok((public.to_ascii_lowercase(), signature.to_owned()))
}

fn hex32(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 { return None; }
    let mut out = [0u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() { out[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?; }
    Some(out)
}
fn hex_nibble(value: u8) -> Option<u8> { match value { b'0'..=b'9'=>Some(value-b'0'), b'a'..=b'f'=>Some(value-b'a'+10), b'A'..=b'F'=>Some(value-b'A'+10), _=>None } }
fn protocol_err(error: ztsec_protocol::ProtocolError) -> io::Error { io::Error::new(io::ErrorKind::InvalidData, error.to_string()) }
fn ws_err(error: tokio_tungstenite::tungstenite::Error) -> io::Error { io::Error::new(io::ErrorKind::Other, error.to_string()) }

fn ws_config() -> tokio_tungstenite::tungstenite::protocol::WebSocketConfig {
    tokio_tungstenite::tungstenite::protocol::WebSocketConfig::default()
        .read_buffer_size(8 * 1024)
        .write_buffer_size(4 * 1024)
        .max_write_buffer_size(64 * 1024)
        .max_message_size(Some(ztsec_protocol::MAX_WS_MESSAGE_BYTES))
        .max_frame_size(Some(ztsec_protocol::MAX_WS_MESSAGE_BYTES))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn authorized_key_line_parses_and_verifies() {
        let signing = SigningKey::from_bytes(&[9u8; 32]);
        let fp = "a".repeat(64);
        let pk = signing.verifying_key().to_bytes().iter().map(|b| format!("{b:02x}")).collect::<String>();
        let text = format!("{fp} {pk}\n");
        let path = std::env::temp_dir().join(format!("ztsec-keys-{}", std::process::id()));
        fs::write(&path, text).unwrap();
        let store = KeyStore::load(&path).unwrap();
        let sig = signing.sign(&ztsec_protocol::auth_message(&fp, &[1,2,3]));
        assert!(store.verify(&fp, &signing.verifying_key().to_bytes(), &ztsec_protocol::auth_message(&fp, &[1,2,3]), &sig));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn rate_limiter_is_bounded() {
        let mut limiter = RateLimiter::new(2);
        assert!(limiter.allow());
        assert!(limiter.allow());
        assert!(!limiter.allow());
    }

    #[test]
    fn control_target_validation_is_strict() {
        assert!(valid_control_target("broadcast"));
        assert!(valid_control_target(&"A".repeat(64)));
        assert!(!valid_control_target("broadcast "));
        assert!(!valid_control_target(&"a".repeat(63)));
        assert!(!valid_control_target(&"g".repeat(64)));
    }

    #[test]
    fn relay_accepts_all_agent_command_families() {
        for command in [
            "REQ:DATA",
            "CMD:RECONNECT", "CMD:CLOSE", "CMD:SLEEP", "CMD:HIBERNATE", "CMD:RESTART", "CMD:SHUTDOWN",
            "CMD:DIRECT_CONNECT", "CMD:DIRECT_DISCONNECT",
            "CMD:PLUGIN:x:eA==", "CMD:PLUGIN_BEGIN:x:y:1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "CMD:PLUGIN_CHUNK:y:0:eA==", "CMD:PLUGIN_END:y", "CMD:PLUGIN_RESUME:y", "CMD:PLUGIN_MSG:x:eA==",
            "CMD:PLUGIN_EVENT:ping", "CMD:UNLOAD:x",
            "CMD:UPDATE:a:ZW1wdHk=", "CMD:UPDATE_BEGIN:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:1",
            "CMD:UPDATE_CHUNK:0:eA==", "CMD:UPDATE_END:", "CMD:EXECUTE:ps1:ZW1wdHk=",
        ] {
            assert!(ztsec_protocol::is_supported_agent_command(command), "not relayable: {command}");
        }
        assert!(!ztsec_protocol::is_supported_agent_command("CMD:SHELL"));
        assert!(!ztsec_protocol::is_supported_agent_command("CMD:DIRECT_CONNECT:203.0.113.10:4794"));
    }

    #[test]
    fn relay_direct_command_uses_discovered_public_ip_and_listener_port() {
        let address: IpAddr = "203.0.113.10".parse().unwrap();
        let listen: SocketAddr = "0.0.0.0:4794".parse().unwrap();
        assert_eq!(materialize_direct_command(address, listen).as_ref(), "CMD:DIRECT_CONNECT:203.0.113.10:4794");
    }

    #[test]
    fn relay_direct_command_brackets_ipv6_address() {
        let address: IpAddr = "2001:db8::10".parse().unwrap();
        let listen: SocketAddr = "[::]:4794".parse().unwrap();
        assert_eq!(materialize_direct_command(address, listen).as_ref(), "CMD:DIRECT_CONNECT:[2001:db8::10]:4794");
    }

    #[test]
    fn default_direct_listener_is_valid_and_has_fixed_port() {
        let config = Config::default();
        assert_eq!(config.direct_listen, DEFAULT_DIRECT_LISTEN);
        assert!(validate_direct_listener_configuration(&config).is_ok());
        assert_eq!(config.direct_listen.parse::<SocketAddr>().unwrap().port(), 4794);
    }

    #[test]
    fn default_broadcast_bound_covers_default_connection_capacity() {
        let config = Config::default();
        assert_eq!(config.max_broadcast_targets, config.max_connections);
    }

    #[test]
    fn invalid_direct_listener_is_rejected() {
        let mut config = Config::default();
        config.direct_listen = "0.0.0.0:0".into();
        assert!(validate_direct_listener_configuration(&config).is_err());
    }

    #[tokio::test]
    async fn explicit_direct_address_is_rejected() {
        let mut config = Config::default();
        config.direct_listen = "127.0.0.1:4794".into();
        assert!(materialize_relay_command("CMD:DIRECT_CONNECT:127.0.0.1:4794", &config).await.is_err());
    }
}
