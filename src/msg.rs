pub const DEFAULT_IP: &str = "127.0.0.1";
pub const DEFAULT_PORT: u16 = 4793;
pub const RETRY_SECS: u64 = 5;
pub const HEARTBEAT_SECS: u64 = 3;
pub const PROTOCOL: &str = "Rust/1";
pub const TAG: &str = "ZTSecurity";
pub const UNKNOWN: &str = "Unknown";
pub const LOCAL: &str = "Local";
pub const MUTEX: &str = "Local\\ZTSecurityAgent";
pub const INFO: &[u8] = b"mirage-identity";

pub const OUT_CONNECTED: &str = "connected";
pub const OUT_RECONNECT: &str = "reconnecting in 5s";
pub const OUT_CLOSED: &str = "closed";
pub const OUT_RUNNING: &str = "already running";
pub const OUT_USAGE: &str = "usage: agent.exe [--ip <ip>] [--port <port>]";

pub const ACK: &str = "ACK";
pub const ERR: &str = "ERR";
pub const CMD: &str = "CMD:";
pub const HELLO: &str = "HELLO:FINGERPRINT:";
pub const DATA: &str = "DATA:";
pub const HB: &str = "HB";
pub const REQ_DATA: &str = "REQ:DATA";
pub const PONG: &str = "PONG";

pub const SLEEP: &str = "SLEEP";
pub const HIBERNATE: &str = "HIBERNATE";
pub const RESTART: &str = "RESTART";
pub const SHUTDOWN: &str = "SHUTDOWN";
pub const RECONNECT: &str = "RECONNECT";
pub const CLOSE: &str = "CLOSE";
pub const BLOCK: &str = "BLOCK";
