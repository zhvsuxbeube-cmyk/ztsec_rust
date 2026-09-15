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
        if !sys::single() {
            eprintln!("update successor could not acquire the normal mutex");
            return;
        }
        net::run_with_update_signal(&args.ip, args.port);
        return;
    }

    if !sys::single() {
        return;
    }
    let args = args::get();
    net::run(&args.ip, args.port);
}
