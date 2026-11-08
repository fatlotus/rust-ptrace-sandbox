use nodice::deterministic::Deterministic;
use nodice::interceptor::run_with_interceptor;
use nodice::passthru::Passthru;
use std::collections::BTreeMap;
use std::io::Write;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

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

fn format_jitter_ns(ns: u64) -> String {
    if ns == 0 {
        "0ms".to_string()
    } else if ns % 1_000_000 == 0 {
        format!("{}ms", ns / 1_000_000)
    } else if ns % 1_000 == 0 {
        format!("{}us", ns / 1_000)
    } else {
        format!("{}ns", ns)
    }
}

fn shell_quote(s: &str) -> String {
    if !s.is_empty()
        && s.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(b, b'_' | b'-' | b'.' | b'/' | b':' | b'=' | b'+' | b'@')
        })
    {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

fn format_repro_command(
    program: &str,
    sandbox: bool,
    verbose: bool,
    seed: u64,
    jitter_ns: u64,
    cmd: &str,
    cmd_args: &[&str],
) -> String {
    let mut parts = Vec::new();
    parts.push(shell_quote(program));
    if !sandbox {
        parts.push("--passthru".to_string());
    }
    if verbose {
        parts.push("--verbose".to_string());
    }
    parts.push("--seed".to_string());
    parts.push(seed.to_string());
    parts.push("--jitter".to_string());
    parts.push(format_jitter_ns(jitter_ns));
    if cmd.starts_with('-') {
        parts.push("--".to_string());
    }
    parts.push(shell_quote(cmd));
    for arg in cmd_args {
        parts.push(shell_quote(arg));
    }
    parts.join(" ")
}

struct FailureReport {
    idx: u64,
    seed: u64,
    jitter_ns: u64,
    output: Output,
}

fn run_iterations(
    program: &str,
    total_iters: u64,
    sandbox: bool,
    verbose: bool,
    base_seed: Option<u64>,
    explicit_jitter_ns: Option<u64>,
    cmd: &str,
    cmd_args: &[&str],
) {
    let exe = std::env::current_exe().unwrap_or_else(|_| std::path::PathBuf::from(program));
    let num_workers = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .min(total_iters as usize)
        .max(1);

    let next_idx = Arc::new(AtomicU64::new(0));
    let first_failure_idx = Arc::new(AtomicU64::new(u64::MAX));
    let stop_all = Arc::new(AtomicBool::new(false));
    let active_pids: Arc<Mutex<BTreeMap<u64, i32>>> = Arc::new(Mutex::new(BTreeMap::new()));
    let failures: Arc<Mutex<BTreeMap<u64, FailureReport>>> = Arc::new(Mutex::new(BTreeMap::new()));

    let start_seed = base_seed.unwrap_or(1);
    let cmd_owned = cmd.to_string();
    let cmd_args_owned: Vec<String> = cmd_args.iter().map(|s| (*s).to_string()).collect();

    let mut handles = Vec::with_capacity(num_workers);
    for _ in 0..num_workers {
        let exe = exe.clone();
        let next_idx = Arc::clone(&next_idx);
        let first_failure_idx = Arc::clone(&first_failure_idx);
        let stop_all = Arc::clone(&stop_all);
        let active_pids = Arc::clone(&active_pids);
        let failures = Arc::clone(&failures);
        let cmd_owned = cmd_owned.clone();
        let cmd_args_owned = cmd_args_owned.clone();

        handles.push(std::thread::spawn(move || {
            loop {
                if stop_all.load(Ordering::SeqCst) {
                    break;
                }
                let idx = next_idx.fetch_add(1, Ordering::SeqCst);
                if idx >= total_iters || idx >= first_failure_idx.load(Ordering::SeqCst) {
                    break;
                }

                let iter_seed = start_seed.wrapping_add(idx);
                // When --jitter is not specified, start with 1ms and increase by 1ms per iteration
                let iter_jitter_ns =
                    explicit_jitter_ns.unwrap_or_else(|| (idx + 1).saturating_mul(1_000_000));

                let mut command = Command::new(&exe);
                if !sandbox {
                    command.arg("--passthru");
                }
                if verbose {
                    command.arg("--verbose");
                }
                command
                    .arg("--seed")
                    .arg(iter_seed.to_string())
                    .arg("--jitter")
                    .arg(format_jitter_ns(iter_jitter_ns));
                if cmd_owned.starts_with('-') {
                    command.arg("--");
                }
                command.arg(&cmd_owned).args(&cmd_args_owned);
                command
                    .stdin(Stdio::null())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped());

                let child = match command.spawn() {
                    Ok(c) => c,
                    Err(e) => {
                        eprintln!("nodice: failed to spawn worker: {}", e);
                        stop_all.store(true, Ordering::SeqCst);
                        break;
                    }
                };

                let pid = child.id() as i32;
                {
                    let mut active = active_pids.lock().unwrap();
                    if stop_all.load(Ordering::SeqCst)
                        || idx >= first_failure_idx.load(Ordering::SeqCst)
                    {
                        let _ = nix::sys::signal::kill(
                            nix::unistd::Pid::from_raw(pid),
                            nix::sys::signal::Signal::SIGTERM,
                        );
                    } else {
                        active.insert(idx, pid);
                    }
                }

                let output = match child.wait_with_output() {
                    Ok(o) => o,
                    Err(_) => break,
                };

                active_pids.lock().unwrap().remove(&idx);

                if !output.status.success()
                    && !stop_all.load(Ordering::SeqCst)
                    && idx < first_failure_idx.load(Ordering::SeqCst)
                {
                    first_failure_idx.fetch_min(idx, Ordering::SeqCst);
                    failures.lock().unwrap().insert(
                        idx,
                        FailureReport {
                            idx,
                            seed: iter_seed,
                            jitter_ns: iter_jitter_ns,
                            output,
                        },
                    );

                    // Immediately terminate any in-flight iterations with a higher index
                    let active = active_pids.lock().unwrap();
                    for (&other_idx, &other_pid) in active.iter() {
                        if other_idx > idx {
                            let _ = nix::sys::signal::kill(
                                nix::unistd::Pid::from_raw(other_pid),
                                nix::sys::signal::Signal::SIGTERM,
                            );
                        }
                    }
                }
            }
        }));
    }

    for h in handles {
        let _ = h.join();
    }

    let mut recorded = failures.lock().unwrap();
    if let Some((_, report)) = recorded.pop_first() {
        let _ = std::io::stdout().write_all(&report.output.stdout);
        let _ = std::io::stdout().flush();
        let _ = std::io::stderr().write_all(&report.output.stderr);
        let _ = std::io::stderr().flush();

        let repro = format_repro_command(
            program,
            sandbox,
            verbose,
            report.seed,
            report.jitter_ns,
            cmd,
            cmd_args,
        );
        eprintln!(
            "\nFailed on iteration {}/{} (seed {}, jitter {}). Reproduce with:\n  {}",
            report.idx + 1,
            total_iters,
            report.seed,
            format_jitter_ns(report.jitter_ns),
            repro
        );
        let code = report.output.status.code().unwrap_or(1);
        std::process::exit(if code != 0 { code } else { 1 });
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
    let mut jitter_ns: Option<u64> = None;
    let mut iterations: Option<u64> = None;
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
            jitter_ns = Some(parse_jitter_ns(val).unwrap_or_else(|| {
                eprintln!("Invalid --jitter value: {}", val);
                std::process::exit(1);
            }));
            i += step;
        } else if matches!(stripped, Some(s) if s == "iterations" || s.starts_with("iterations=")) {
            let s = stripped.unwrap();
            let (val, step) = if let Some(v) = s.strip_prefix("iterations=") {
                (v, 1)
            } else if i + 1 < args.len() {
                (args[i + 1].as_str(), 2)
            } else {
                print_usage(&args[0]);
                std::process::exit(1);
            };
            let n = val.parse::<u64>().ok().filter(|&n| n >= 1).unwrap_or_else(|| {
                eprintln!("Invalid --iterations value: {}", val);
                std::process::exit(1);
            });
            iterations = Some(n);
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

    if let Some(total_iters) = iterations {
        run_iterations(
            &args[0],
            total_iters,
            sandbox,
            verbose,
            seed,
            jitter_ns,
            cmd,
            &cmd_args,
        );
    } else if sandbox {
        run_with_interceptor(
            cmd,
            &cmd_args,
            Deterministic::with_seed_and_jitter(verbose, seed, jitter_ns.unwrap_or(0)),
        );
    } else {
        run_with_interceptor(cmd, &cmd_args, Passthru::new(verbose));
    }
}

fn print_usage(program: &str) {
    eprintln!(
        "Usage: {} [--passthru] [--verbose] [--seed <N>] [--jitter <duration>] [--iterations <N>] <command> [args...]",
        program
    );
}
