mod args;
mod net;
mod plugin;
mod sys;
#[allow(dead_code, unused_macros)]
mod syscalls;
mod telemetry;
mod text;

fn main() {
    if !sys::single() {
        return;
    }
    let args = args::get();
    net::run(&args.ip, args.port);
}
