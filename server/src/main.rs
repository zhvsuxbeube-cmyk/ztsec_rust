use std::{env, io, path::PathBuf, time::Duration};

use tracing::info;
use ztsec_server::{Config, Server};

#[tokio::main]
async fn main() -> io::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(env::var("RUST_LOG").unwrap_or_else(|_| "ztsec_server=info,arti_client=warn,tor_hsservice=warn".into()))
        .init();

    let config = parse_args()?;
    let (server, ipc_rx) = Server::new(config)?;
    server.run(ipc_rx).await?;
    info!("ztsec server stopped");
    Ok(())
}

fn parse_args() -> io::Result<Config> {
    let mut config = Config::default();
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--nickname" => config.onion_nickname = next(&mut args, "nickname")?,
            "--state-dir" => config.state_dir = PathBuf::from(next(&mut args, "state-dir")?),
            "--cache-dir" => config.cache_dir = PathBuf::from(next(&mut args, "cache-dir")?),
            "--authorized-keys" => config.authorized_keys = PathBuf::from(next(&mut args, "authorized-keys")?),
            "--local-listen" => config.local_listen = Some(next(&mut args, "local-listen")?),
            "--direct-listen" => config.direct_listen = Some(next(&mut args, "direct-listen")?),
            "--direct-endpoint" => config.direct_endpoints.push(next_socket(&mut args, "direct-endpoint")?),
            "--max-agent-command-queue" => config.max_agent_command_queue = parse_usize(&next(&mut args, "max-agent-command-queue")?)?,
            "--max-broadcast-targets" => config.max_broadcast_targets = parse_usize(&next(&mut args, "max-broadcast-targets")?)?,
            "--max-control-requests-per-second" => config.max_control_requests_per_second = parse_u32(&next(&mut args, "max-control-requests-per-second")?)?,
            "--no-onion" => config.enable_onion = false,
            "--local-socket" => config.local_socket = PathBuf::from(next(&mut args, "local-socket")?),
            "--control-socket" => config.control_socket = PathBuf::from(next(&mut args, "control-socket")?),
            "--path" => config.websocket_path = next(&mut args, "path")?,
            "--onion-port" => config.onion_port = parse_u16(&next(&mut args, "onion-port")?)?,
            "--max-connections" => config.max_connections = parse_usize(&next(&mut args, "max-connections")?)?,
            "--max-auth-inflight" => config.max_auth_inflight = parse_usize(&next(&mut args, "max-auth-inflight")?)?,
            "--ipc-queue" => config.max_ipc_queue = parse_usize(&next(&mut args, "ipc-queue")?)?,
            "--message-rate" => config.max_messages_per_second = parse_u32(&next(&mut args, "message-rate")?)?,
            "--handshake-timeout" => config.handshake_timeout = parse_seconds(&next(&mut args, "handshake-timeout")?)?,
            "--auth-timeout" => config.auth_timeout = parse_seconds(&next(&mut args, "auth-timeout")?)?,
            "--idle-timeout" => config.idle_timeout = parse_seconds(&next(&mut args, "idle-timeout")?)?,
            "--ping-interval" => config.ping_interval = parse_seconds(&next(&mut args, "ping-interval")?)?,
            "--metrics-interval" => config.metrics_interval = parse_seconds(&next(&mut args, "metrics-interval")?)?,
            "--help" | "-h" => {
                println!("ztsec-server options: --nickname N --state-dir DIR --cache-dir DIR --authorized-keys FILE --local-listen ADDR --direct-listen ADDR --direct-endpoint IP:PORT --no-onion --local-socket PATH --control-socket PATH --path PATH --onion-port PORT --max-connections N --max-auth-inflight N --ipc-queue N --message-rate N --max-agent-command-queue N --max-broadcast-targets N --max-control-requests-per-second N --handshake-timeout S --auth-timeout S --idle-timeout S --ping-interval S --metrics-interval S");
                std::process::exit(0);
            }
            other => return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("unknown option {other}"))),
        }
    }
    Ok(config)
}

fn next<I: Iterator<Item = String>>(args: &mut I, name: &str) -> io::Result<String> { args.next().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, format!("missing value for --{name}"))) }
fn next_socket<I: Iterator<Item = String>>(args: &mut I, name: &str) -> io::Result<std::net::SocketAddr> {
    next(args, name)?.parse().map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, format!("invalid socket address for --{name}")))
}

fn parse_u16(value: &str) -> io::Result<u16> { value.parse().ok().filter(|v| *v != 0).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid u16 value")) }
fn parse_u32(value: &str) -> io::Result<u32> { value.parse().ok().filter(|v| *v != 0).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid u32 value")) }
fn parse_usize(value: &str) -> io::Result<usize> { value.parse().ok().filter(|v| *v != 0).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid usize value")) }
fn parse_seconds(value: &str) -> io::Result<Duration> { value.parse::<u64>().ok().filter(|v| *v > 0 && *v <= 86_400).map(Duration::from_secs).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid duration")) }
