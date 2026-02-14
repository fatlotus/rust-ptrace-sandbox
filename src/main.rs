mod linux;
mod passthru;
mod interceptor;
mod vdso;
mod captured;

use passthru::Passthru;
use interceptor::run_with_interceptor;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <command> [args...]", args[0]);
        std::process::exit(1);
    }

    let cmd = &args[1];
    let cmd_args: Vec<&str> = args[2..].iter().map(|s| s.as_str()).collect();

    run_with_interceptor(cmd, &cmd_args, Passthru);
}
