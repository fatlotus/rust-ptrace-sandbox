mod linux;
mod passthru;
mod interceptor;
mod vdso;
mod captured;
mod deterministic;

use passthru::Passthru;
use deterministic::Deterministic;
use interceptor::run_with_interceptor;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} [--sandbox] <command> [args...]", args[0]);
        std::process::exit(1);
    }

    let (cmd, cmd_args, sandbox) = if args[1] == "--sandbox" {
        if args.len() < 3 {
            eprintln!("Usage: {} [--sandbox] <command> [args...]", args[0]);
            std::process::exit(1);
        }
        let cmd = &args[2];
        let cmd_args: Vec<&str> = args[3..].iter().map(|s| s.as_str()).collect();
        (cmd, cmd_args, true)
    } else {
        let cmd = &args[1];
        let cmd_args: Vec<&str> = args[2..].iter().map(|s| s.as_str()).collect();
        (cmd, cmd_args, false)
    };

    if sandbox {
        run_with_interceptor(cmd, &cmd_args, Deterministic::new());
    } else {
        run_with_interceptor(cmd, &cmd_args, Passthru);
    }
}
