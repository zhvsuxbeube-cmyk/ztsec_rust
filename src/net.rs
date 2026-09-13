use std::{
    io::{BufRead, BufReader, ErrorKind, Write},
    net::TcpStream,
    thread,
    time::{Duration, Instant},
};

use crate::{sys, telemetry, text};

pub fn run(ip: &str, port: u16) -> ! {
    let fp = telemetry::fingerprint();

    loop {
        let started = Instant::now();
        match TcpStream::connect((ip, port)) {
            Ok(mut stream) => {
                let ping = started.elapsed().as_millis();
                let _ = stream.set_read_timeout(Some(Duration::from_secs(text::READ)));
                let data = telemetry::record(ip, Some(ping), &fp);

                if send(&mut stream, &format!("{}{}", text::HELLO, fp)).is_ok()
                    && send(&mut stream, &format!("{}{}", text::DATA, data)).is_ok()
                {
                    println!("{}", text::CONNECTED);
                    if session(&mut stream, ip, &fp) {
                        return;
                    }
                }
            }
            Err(_) => {}
        }

        println!("{}", text::RETRYING);
        thread::sleep(Duration::from_secs(text::RETRY));
    }
}

fn session(stream: &mut TcpStream, ip: &str, fp: &str) -> bool {
    let Ok(clone) = stream.try_clone() else {
        return false;
    };
    let mut reader = BufReader::new(clone);

    loop {
        match line(&mut reader) {
            Ok(Some(value)) if value == text::HB => {
                let _ = send(stream, text::PONG);
            }
            Ok(Some(value)) if value == text::REQ => {
                let _ = send(stream, text::PONG);
                let _ = send(
                    stream,
                    &format!("{}{}", text::DATA, telemetry::record(ip, None, fp)),
                );
            }
            Ok(Some(value)) if value.starts_with(text::CMD) => {
                let cmd = value[text::CMD.len()..].trim().to_ascii_uppercase();

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
                        let _ = send(
                            stream,
                            &format!("{}{}", if ok { text::ACK } else { text::ERR }, cmd),
                        );
                        if ok {
                            return true;
                        }
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
