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
    let argv: Vec<String> = std::env::args().collect();
    if update::maybe_run_successor(&argv) {
        return;
    }
    if update::maybe_run_probe(&argv) { return; }
    if !sys::single() {
        return;
    }
    let args = args::get();
    net::run(&args.ip, args.port);
}
