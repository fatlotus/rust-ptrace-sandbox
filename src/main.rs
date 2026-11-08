use nodice::deterministic::Deterministic;
use nodice::interceptor::run_with_interceptor;
use nodice::passthru::Passthru;

fn parse_jitter_ns(val: &str) -> Option<u64> {
    let s = val.trim();
    if let Some(num) = s.strip_suffix("ns") {
        num.trim().parse::<u64>().ok()
    } else if let Some(num) = s.strip_suffix("us") {
        num.trim().parse::<u64>().ok().map(|v| v.saturating_mul(1_000))
    } else if let Some(num) = s.strip_suffix("ms") {
        num.trim().parse::<u64>().ok().map(|v| v.saturating_mul(1_000_000))
    } else if let Some(num) = s.strip_suffix('s') {
        num.trim().parse::<u64>().ok().map(|v| v.saturating_mul(1_000_000_000))
    } else {
        // Default bare integer is milliseconds
        s.parse::<u64>().ok().map(|v| v.saturating_mul(1_000_000))
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        print_usage(&args[0]);
        std::process::exit(1);
    }

    let mut sandbox = true;
    let mut verbose = false;
    let mut seed: Option<u64> = None;
    let mut jitter_ns: u64 = 0;
    let mut i = 1;

    while i < args.len() {
        let arg = &args[i];
        let stripped = arg.strip_prefix("--").or_else(|| arg.strip_prefix('-'));
        if arg == "--" {
            i += 1;
            break;
        } else if matches!(stripped, Some("sandbox")) {
            sandbox = true;
            i += 1;
        } else if matches!(stripped, Some("passthru" | "no-sandbox")) {
            sandbox = false;
            i += 1;
        } else if matches!(stripped, Some("verbose" | "v")) {
            verbose = true;
            i += 1;
        } else if matches!(stripped, Some("help" | "h")) {
            print_usage(&args[0]);
            std::process::exit(0);
        } else if matches!(stripped, Some(s) if s == "seed" || s.starts_with("seed=")) {
            let s = stripped.unwrap();
            let (val, step) = if let Some(v) = s.strip_prefix("seed=") {
                (v, 1)
            } else if i + 1 < args.len() {
                (args[i + 1].as_str(), 2)
            } else {
                print_usage(&args[0]);
                std::process::exit(1);
            };
            seed = Some(val.parse::<u64>().unwrap_or_else(|_| {
                eprintln!("Invalid --seed value: {}", val);
                std::process::exit(1);
            }));
            i += step;
        } else if matches!(stripped, Some(s) if s == "jitter" || s.starts_with("jitter=")) {
            let s = stripped.unwrap();
            let (val, step) = if let Some(v) = s.strip_prefix("jitter=") {
                (v, 1)
            } else if i + 1 < args.len() {
                (args[i + 1].as_str(), 2)
            } else {
                print_usage(&args[0]);
                std::process::exit(1);
            };
            jitter_ns = parse_jitter_ns(val).unwrap_or_else(|| {
                eprintln!("Invalid --jitter value: {}", val);
                std::process::exit(1);
            });
            i += step;
        } else if arg.starts_with('-') && arg.len() > 1 {
            eprintln!("Unknown option: {}", arg);
            print_usage(&args[0]);
            std::process::exit(1);
        } else {
            break;
        }
    }

    let cmd_start_idx = i;
    if cmd_start_idx >= args.len() {
        print_usage(&args[0]);
        std::process::exit(1);
    }

    let cmd = &args[cmd_start_idx];
    let cmd_args: Vec<&str> = args[cmd_start_idx + 1..].iter().map(|s| s.as_str()).collect();

    if sandbox {
        run_with_interceptor(cmd, &cmd_args, Deterministic::with_seed_and_jitter(verbose, seed, jitter_ns));
    } else {
        run_with_interceptor(cmd, &cmd_args, Passthru::new(verbose));
    }
}

fn print_usage(program: &str) {
    eprintln!(
        "Usage: {} [--passthru] [--verbose] [--seed <N>] [--jitter <ms|Ns|Nms|Nus|Nns>] <command> [args...]",
        program
    );
}
