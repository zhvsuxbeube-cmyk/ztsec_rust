use std::{env, path::PathBuf, process, time::Duration};

use crate::{text, transport::Endpoint, telemetry};

pub struct Args {
    pub endpoint: Endpoint,
    pub endpoint_display: String,
    pub use_websocket: bool,
    pub auth_key_file: PathBuf,
    pub arti_state_dir: PathBuf,
    pub arti_cache_dir: PathBuf,
    pub connect_timeout: Duration,
    pub handshake_timeout: Duration,
    pub heartbeat: Duration,
    pub retry_base: Duration,
    pub retry_max: Duration,
    pub legacy_ip: String,
    pub legacy_port: u16,
}

pub fn get() -> Args {
    let endpoint_env = env::var("ZTSEC_ENDPOINT").ok();
    get_from(env::args().skip(1), endpoint_env.as_deref())
}

fn get_from<I: Iterator<Item = String>>(it: I, endpoint_env: Option<&str>) -> Args {
    let mut ip = text::HOST.to_owned();
    let mut port = text::PORT;
    let mut use_websocket = endpoint_env.is_some();
    let mut endpoint = endpoint_env.map(str::to_owned);
    let mut auth_key_file = env::var_os("ZTSEC_AUTH_KEY_FILE").map(PathBuf::from).unwrap_or_else(crate::auth::default_key_path);
    let mut arti_state_dir = env::var_os("ZTSEC_ARTI_STATE_DIR").map(PathBuf::from).unwrap_or_else(default_state_dir);
    let mut arti_cache_dir = env::var_os("ZTSEC_ARTI_CACHE_DIR").map(PathBuf::from).unwrap_or_else(default_cache_dir);
    let mut connect_timeout = Duration::from_secs(15);
    let mut handshake_timeout = Duration::from_secs(10);
    let mut heartbeat = Duration::from_secs(30);
    let mut retry_base = Duration::from_secs(1);
    let mut retry_max = Duration::from_secs(60);
    let mut it = it.peekable();

    while let Some(arg) = it.next() {
        if arg.starts_with("--ztsec-update-") {
            continue;
        }
        match arg.as_str() {
            text::IP => ip = value(&mut it),
            text::PORT_ARG => {
                let v = value(&mut it);
                port = parse_u16(&v, "port");
            }
            "--endpoint" => { use_websocket = true; endpoint = Some(value(&mut it)); },
            "--auth-key-file" => auth_key_file = PathBuf::from(value(&mut it)),
            "--arti-state-dir" => arti_state_dir = PathBuf::from(value(&mut it)),
            "--arti-cache-dir" => arti_cache_dir = PathBuf::from(value(&mut it)),
            "--connect-timeout" => connect_timeout = parse_duration_secs(&value(&mut it), "connect timeout"),
            "--handshake-timeout" => handshake_timeout = parse_duration_secs(&value(&mut it), "handshake timeout"),
            "--heartbeat" => heartbeat = parse_duration_secs(&value(&mut it), "heartbeat"),
            "--retry-base" => retry_base = parse_duration_secs(&value(&mut it), "retry base"),
            "--retry-max" => retry_max = parse_duration_secs(&value(&mut it), "retry max"),
            "--print-fingerprint" => {
                println!("{}", telemetry::fingerprint());
                process::exit(0);
            }
            text::HELP | text::SHORT_HELP => {
                println!("{}", text::USAGE);
                process::exit(0);
            }
            _ => fail(),
        }
    }

    if ip.trim().is_empty() || port == 0 { fail(); }
    if connect_timeout.is_zero() || handshake_timeout.is_zero() || heartbeat.is_zero() || retry_base.is_zero() || retry_max.is_zero() || retry_max < retry_base {
        fail();
    }

    let endpoint_text = endpoint.unwrap_or_else(|| format!("ws://{}:{}/", ip, port));
    let endpoint = match Endpoint::parse(&endpoint_text) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("invalid endpoint: {error}");
            fail();
        }
    };
    Args {
        endpoint,
        endpoint_display: endpoint_text,
        use_websocket,
        auth_key_file,
        arti_state_dir,
        arti_cache_dir,
        connect_timeout,
        handshake_timeout,
        heartbeat,
        retry_base,
        retry_max,
        legacy_ip: ip,
        legacy_port: port,
    }
}

fn default_state_dir() -> PathBuf {
    env::var_os("LOCALAPPDATA").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("." )).join("ZTSEC").join("arti-state")
}

fn default_cache_dir() -> PathBuf {
    env::var_os("LOCALAPPDATA").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("." )).join("ZTSEC").join("arti-cache")
}

fn parse_u16(value: &str, label: &str) -> u16 {
    match value.parse::<u16>() { Ok(v) if v > 0 => v, _ => { eprintln!("invalid {label}"); fail(); } }
}

fn parse_duration_secs(value: &str, label: &str) -> Duration {
    match value.parse::<u64>() { Ok(v) if v > 0 && v <= 86_400 => Duration::from_secs(v), _ => { eprintln!("invalid {label}"); fail(); } }
}

fn value<I: Iterator<Item = String>>(it: &mut I) -> String {
    match it.next() { Some(v) => v, None => fail() }
}

fn fail() -> ! {
    eprintln!("{}", text::FAILED);
    process::exit(2)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_arguments_are_ignored_and_loopback_endpoint_is_default() {
        let args = get_from([
            "--ip".to_owned(), "127.0.0.1".to_owned(),
            "--port".to_owned(), "4793".to_owned(),
            "--ztsec-update-final-port=49152".to_owned(),
            "--ztsec-update-final-token=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
            "--ztsec-update-final-hash=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned(),
        ].into_iter(), None);
        assert_eq!(args.legacy_ip, "127.0.0.1");
        assert_eq!(args.legacy_port, 4793);
        assert!(matches!(args.endpoint, Endpoint::Local { .. }));
        assert!(!args.use_websocket);
    }
}
