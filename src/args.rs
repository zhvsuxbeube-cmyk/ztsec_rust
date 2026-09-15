use std::{env, process};

use crate::text;

pub struct Args {
    pub ip: String,
    pub port: u16,
    pub update_signal_port: Option<u16>,
    pub update_signal_token: Option<String>,
}

pub fn get() -> Args {
    let mut ip = text::HOST.to_owned();
    let mut port = text::PORT;
    let mut update_signal_port = None;
    let mut update_signal_token = None;
    let mut it = env::args().skip(1);

    while let Some(arg) = it.next() {
        match arg.as_str() {
            text::IP => ip = value(&mut it),
            text::PORT_ARG => {
                let v = value(&mut it);
                port = match v.parse() {
                    Ok(v) => v,
                    Err(_) => fail(),
                };
            }
            "--update-child" => {}
            "--update-signal-port" => {
                let v = value(&mut it);
                update_signal_port = match v.parse() {
                    Ok(v) if v != 0 => Some(v),
                    _ => fail(),
                };
            }
            "--update-signal-token" => {
                let v = value(&mut it);
                if v.is_empty() || v.len() > 128 {
                    fail();
                }
                update_signal_token = Some(v);
            }
            text::HELP | text::SHORT_HELP => {
                println!("{}", text::USAGE);
                process::exit(0);
            }
            _ => fail(),
        }
    }

    if ip.trim().is_empty() || port == 0 {
        fail();
    }

    Args { ip, port, update_signal_port, update_signal_token }
}

fn value<I: Iterator<Item = String>>(it: &mut I) -> String {
    match it.next() {
        Some(v) => v,
        None => fail(),
    }
}

fn fail() -> ! {
    eprintln!("{}", text::FAILED);
    process::exit(2)
}
