mod args;
mod net;
mod plugin;
mod sys;
#[allow(dead_code, unused_macros)]
mod syscalls;
mod telemetry;
mod text;
mod update;

fn main() {
    match update::accept_handoff() {
        Ok(Some(mut handoff)) => {
            let ip = handoff.ip().to_owned();
            let port = handoff.port();
            if handoff.initialize_and_wait_for_release().is_err() {
                return;
            }
            net::run_with_handoff(&ip, port, Some(handoff));
            return;
        }
        Ok(None) => {}
        Err(err) => {
            eprintln!("update handoff rejected: {err}");
            return;
        }
    }

    if !sys::single() {
        return;
    }
    let args = args::get();
    net::run(&args.ip, args.port);
}
