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
    if update::is_update() {
        let args = args::get();
        let _ = update::run(&args.ip, args.port);
        return;
    }

    let args = args::get();
    if !sys::single() {
        return;
    }
    net::run(&args.ip, args.port);
}
