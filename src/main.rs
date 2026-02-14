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
        print_usage(&args[0]);
        std::process::exit(1);
    }

    let mut sandbox = false;
    let mut verbose = false;
    let mut cmd_start_idx = 1;

    for i in 1..args.len() {
        if args[i] == "--sandbox" {
            sandbox = true;
            cmd_start_idx = i + 1;
        } else if args[i] == "--verbose" {
            verbose = true;
            cmd_start_idx = i + 1;
        } else {
            break;
        }
    }

    if cmd_start_idx >= args.len() {
        print_usage(&args[0]);
        std::process::exit(1);
    }

    let cmd = &args[cmd_start_idx];
    let cmd_args: Vec<&str> = args[cmd_start_idx + 1..].iter().map(|s| s.as_str()).collect();

    if sandbox {
        run_with_interceptor(cmd, &cmd_args, Deterministic::new(verbose));
    } else {
        run_with_interceptor(cmd, &cmd_args, Passthru::new(verbose));
    }
}

fn print_usage(program: &str) {
    eprintln!("Usage: {} [--sandbox] [--verbose] <command> [args...]", program);
}
