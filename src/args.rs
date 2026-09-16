use std::{env, process};

use crate::text;

pub struct Args {
    pub ip: String,
    pub port: u16,
}

pub fn get() -> Args {
    get_from(env::args().skip(1))
}

fn get_from<I: Iterator<Item = String>>(it: I) -> Args {
    let mut ip = text::HOST.to_owned();
    let mut port = text::PORT;
    let mut it = it.peekable();

    while let Some(arg) = it.next() {
        if arg.starts_with("--ztsec-update-") {
            continue;
        }
        match arg.as_str() {
            text::IP => ip = value(&mut it),
            text::PORT_ARG => {
                let v = value(&mut it);
                port = match v.parse() {
                    Ok(v) => v,
                    Err(_) => fail(),
                };
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

    Args { ip, port }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn final_update_arguments_are_ignored_by_normal_argument_parser() {
        let args = get_from(
            [
                "--ip".to_owned(),
                "127.0.0.1".to_owned(),
                "--port".to_owned(),
                "4793".to_owned(),
                "--ztsec-update-final-port=49152".to_owned(),
                "--ztsec-update-final-token=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
                "--ztsec-update-final-hash=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned(),
            ]
            .into_iter(),
        );
        assert_eq!(args.ip, "127.0.0.1");
        assert_eq!(args.port, 4793);
    }
}
