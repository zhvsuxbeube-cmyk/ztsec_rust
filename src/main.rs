mod args;
mod auth;
mod legacy_net;
mod net;
mod plugin;
mod sys;
#[allow(dead_code, unused_macros)]
mod syscalls;
mod telemetry;
mod text;
mod transport;
mod update;

fn main() {
    let argv: Vec<String> = std::env::args().collect();
    if update::maybe_run_successor(&argv) {
        return;
    }
    if update::maybe_run_probe(&argv) {
        return;
    }
    let final_ready = match update::final_ready_args(&argv) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("ztsec update final arguments invalid: {error}");
            std::process::exit(2);
        }
    };
    if !sys::single() {
        return;
    }
    let args = args::get();
    let runtime = match tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build() {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("unable to initialize async runtime: {error}");
            std::process::exit(1);
        }
    };
    if let Err(error) = runtime.block_on(net::run(&args, final_ready)) {
        eprintln!("agent stopped: {error}");
        std::process::exit(1);
    }
}
