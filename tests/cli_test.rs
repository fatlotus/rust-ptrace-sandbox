mod common;

use common::SandboxCommand;
use std::fs;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

static COUNTER: AtomicUsize = AtomicUsize::new(0);

#[test]
fn cli_echo_verbose() {
    SandboxCommand::new("/bin/echo")
        .arg("hello world")
        .verbose()
        .run()
        .assert_success()
        .assert_stdout_contains("hello world")
        .assert_stdout_contains("write(1,")
        .assert_stdout_contains("brk(");
}

#[test]
fn cli_cat_file_and_stdin() {
    let id = COUNTER.fetch_add(1, Ordering::SeqCst);
    let test_file = format!("/tmp/test_cat_{}.txt", id);
    fs::write(&test_file, b"meow world").expect("Failed to write test file");

    let res = SandboxCommand::new("/bin/cat")
        .arg(&test_file)
        .verbose()
        .run();
    let _ = fs::remove_file(&test_file);

    res.assert_success()
        .assert_stdout_contains("meow world")
        .assert_stdout_contains("read(")
        .assert_stdout_contains("write(1,")
        .assert_stdout_contains("close(");

    SandboxCommand::new("/bin/cat")
        .stdin("piped input\n")
        .run()
        .assert_success()
        .assert_stdout_eq("piped input\n");
}

#[test]
fn cli_date_sandbox_default_and_passthru() {
    // Default mode is deterministic sandbox -> fixed epoch 2000-01-01 00:00:00 UTC
    SandboxCommand::new("/bin/date")
        .run()
        .assert_success()
        .assert_stdout_contains("2000")
        .assert_stdout_contains("Jan")
        .assert_stdout_contains("00:00:00");

    // --passthru --verbose mode passes through real host clock_gettime
    SandboxCommand::new("/bin/date")
        .passthru()
        .verbose()
        .run()
        .assert_success()
        .assert_stdout_contains("20")
        .assert_stdout_contains("clock_gettime(");
}

#[test]
fn cli_shell_fork_sleep_and_exit_code() {
    let shell = if std::path::Path::new("/bin/sh").exists() {
        "/bin/sh"
    } else {
        "/bin/bash"
    };

    // 1. Subshell fork + exec trace
    SandboxCommand::new(shell)
        .args(["-c", "/bin/echo hello from fork"])
        .verbose()
        .run()
        .assert_success()
        .assert_stdout_contains("hello from fork")
        .assert_stdout_contains("write(1, \"hello from fork\\n\", 16) = 16");

    // 2. Cross-process virtual time dilation when parent shell blocks in wait4
    let start = Instant::now();
    SandboxCommand::new(shell)
        .args(["-c", "/bin/sleep 1"])
        .run()
        .assert_success();
    assert!(
        start.elapsed().as_millis() < 500,
        "Expected cross-process sleep to complete in < 500ms via virtual time dilation"
    );

    // 3. Non-zero exit code propagation
    SandboxCommand::new(shell)
        .args(["-c", "exit 42"])
        .run()
        .assert_exit_code(42);
}

#[test]
fn cli_sqlite3_database_operations() {
    let id = COUNTER.fetch_add(1, Ordering::SeqCst);
    let db_file = format!("/tmp/test_sqlite_{}.db", id);
    let cleanup = |path: &str| {
        let _ = fs::remove_file(path);
        let _ = fs::remove_file(format!("{}-journal", path));
        let _ = fs::remove_file(format!("{}-wal", path));
        let _ = fs::remove_file(format!("{}-shm", path));
    };
    cleanup(&db_file);

    let sql = "CREATE TABLE test (id INTEGER PRIMARY KEY, content TEXT); \
               INSERT INTO test (content) VALUES ('hello sqlite'); \
               SELECT content FROM test;";

    let res = SandboxCommand::new("sqlite3")
        .args([db_file.as_str(), sql])
        .verbose()
        .run();
    cleanup(&db_file);

    let res = res
        .assert_success()
        .assert_stdout_contains("hello sqlite")
        .assert_stdout_contains("fcntl(");
    assert!(
        res.stdout.contains("lseek(")
            || res.stdout.contains("pread(")
            || res.stdout.contains("pwrite(")
    );
}

#[test]
fn cli_flags_and_missing_command_error() {
    let nodice_bin = env!("CARGO_BIN_EXE_nodice");

    // 1. Single-dash and double-dash --seed / --jitter flags work identically
    let out = std::process::Command::new(nodice_bin)
        .args(["-seed=18", "--jitter=15ms", "/bin/echo", "seeded ok"])
        .output()
        .expect("Failed to run nodice");
    assert!(out.status.success());
    assert_eq!(String::from_utf8_lossy(&out.stdout), "seeded ok\n");

    // 2. Non-existent command exits cleanly with 127 instead of panicking
    let out = std::process::Command::new(nodice_bin)
        .args(["-seed=18", "--jitter=15ms", "./nonexistent_binary_12345"])
        .output()
        .expect("Failed to run nodice");
    assert_eq!(out.status.code(), Some(127));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("failed to execute './nonexistent_binary_12345'"));
    assert!(!stderr.contains("panicked at"));

    // 3. Unknown flag exits cleanly with code 1 and usage message
    let out = std::process::Command::new(nodice_bin)
        .args(["--bogus-flag", "/bin/echo", "hi"])
        .output()
        .expect("Failed to run nodice");
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("Unknown option: --bogus-flag"));
    assert!(!stderr.contains("panicked at"));
}

#[test]
fn cli_iterations_pass_and_failure_repro() {
    let nodice_bin = env!("CARGO_BIN_EXE_nodice");

    // 1. Passing iterations exit with 0 and hide all output from successful runs
    let out = std::process::Command::new(nodice_bin)
        .args(["--iterations", "6", "/bin/echo", "ok"])
        .output()
        .expect("Failed to run nodice with --iterations");
    assert!(out.status.success());
    assert!(out.stdout.is_empty(), "Expected no stdout on passing runs");
    assert!(out.stderr.is_empty(), "Expected no stderr on passing runs");

    let shell = if std::path::Path::new("/bin/sh").exists() {
        "/bin/sh"
    } else {
        "/bin/bash"
    };

    // Determine the first 4 hex bytes of /dev/urandom under seed 4 when invoked via shell
    let seed4_out = std::process::Command::new(nodice_bin)
        .args(["--seed", "4", shell, "-c", "od -An -tx1 -N4 /dev/urandom"])
        .output()
        .expect("Failed to probe seed 4 urandom");
    let seed4_hex = String::from_utf8_lossy(&seed4_out.stdout)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    assert!(!seed4_hex.is_empty());

    // 2. When --jitter is omitted, jitter starts at 1ms and increases with each iteration (4ms on iteration 4).
    // Passing iterations must have their output hidden.
    let script = format!(
        "val=$(od -An -tx1 -N4 /dev/urandom); \
         set -- $val; \
         if [ \"$1 $2 $3 $4\" = \"{}\" ]; then echo matched_seed_4; exit 7; fi; \
         echo passing_iteration_output",
        seed4_hex
    );
    let out = std::process::Command::new(nodice_bin)
        .args(["--iterations", "6", shell, "-c", &script])
        .output()
        .expect("Failed to run nodice with --iterations");
    assert_eq!(out.status.code(), Some(7));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stdout.contains("matched_seed_4"));
    assert!(
        !stdout.contains("passing_iteration_output"),
        "Expected output from successful iterations to be hidden, got:\n{}",
        stdout
    );
    assert!(
        stderr.contains("--seed 4 --jitter 4ms"),
        "Expected stderr to contain '--seed 4 --jitter 4ms', got:\n{}",
        stderr
    );

    // 3. When --jitter is explicitly specified alongside --iterations, that jitter is used
    let out = std::process::Command::new(nodice_bin)
        .args(["--iterations=6", "--jitter=15ms", shell, "-c", &script])
        .output()
        .expect("Failed to run nodice with --iterations and --jitter");
    assert_eq!(out.status.code(), Some(7));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--seed 4 --jitter 15ms"),
        "Expected stderr to contain '--seed 4 --jitter 15ms', got:\n{}",
        stderr
    );
}

