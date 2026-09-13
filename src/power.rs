use std::process::Command;

use crate::msg;

pub fn run(command: &str) -> bool {
    match command {
        msg::SLEEP => spawn("rundll32.exe", &["powrprof.dll,SetSuspendState", "0", "1", "0"]),
        msg::HIBERNATE => spawn("rundll32.exe", &["powrprof.dll,SetSuspendState", "1", "1", "0"]),
        msg::RESTART => spawn("shutdown.exe", &["/r", "/t", "0", "/f"]),
        msg::SHUTDOWN => spawn("shutdown.exe", &["/s", "/t", "0", "/f"]),
        _ => false,
    }
}

fn spawn(program: &str, args: &[&str]) -> bool {
    Command::new(program)
        .args(args)
        .spawn()
        .is_ok()
}
