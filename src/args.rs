use std::{env, process};

use crate::text;

pub struct Args {
    pub ip: String,
    pub port: u16,
}

pub fn get() -> Args {
    let mut ip = text::HOST.to_owned();
    let mut port = text::PORT;
    let mut it = env::args().skip(1);

    while let Some(arg) = it.next() {
        match arg.as_str() {
            text::IP => ip = value(&mut it),
            text::PORT_ARG => port = value(&mut it).parse().unwrap_or_else(|_| fail()),
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
    it.next().unwrap_or_else(fail)
}

fn fail() -> ! {
    eprintln!("{}", text::FAILED);
    process::exit(2)
}
