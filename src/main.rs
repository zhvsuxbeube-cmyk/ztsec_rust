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
    if update::is_update_child() {
        let args = args::get();
        let Some(signal_port) = args.update_signal_port else {
            eprintln!("update successor missing signal port");
            return;
        };
        let Some(signal_token) = args.update_signal_token.as_deref() else {
            eprintln!("update successor missing signal token");
            return;
        };
        // The parent releases its mutex only after spawning us, so we must
        // poll with a generous timeout rather than trying once and giving up.
        if !sys::acquire_successor_mutex(std::time::Duration::from_secs(30)) {
            eprintln!("update successor could not acquire the normal mutex");
            return;
        }
        net::run_with_update_signal(&args.ip, args.port, signal_port, signal_token);
        return;
    }

    if !sys::single() {
        return;
    }
    let args = args::get();
    net::run(&args.ip, args.port);
}
