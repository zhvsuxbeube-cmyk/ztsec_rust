mod args;
mod net;
mod sys;
mod telemetry;
mod text;

fn main() {
    if !sys::single() {
        return;
    }

    let args = args::get();
    net::run(&args.ip, args.port);
}
