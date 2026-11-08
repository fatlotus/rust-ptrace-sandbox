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
    let ptrace_bin = env!("CARGO_BIN_EXE_ptrace");

    // 1. Single-dash and double-dash --seed / --jitter flags work identically
    let out = std::process::Command::new(ptrace_bin)
        .args(["-seed=18", "--jitter=15ms", "/bin/echo", "seeded ok"])
        .output()
        .expect("Failed to run ptrace");
    assert!(out.status.success());
    assert_eq!(String::from_utf8_lossy(&out.stdout), "seeded ok\n");

    // 2. Non-existent command exits cleanly with 127 instead of panicking
    let out = std::process::Command::new(ptrace_bin)
        .args(["-seed=18", "--jitter=15ms", "./nonexistent_binary_12345"])
        .output()
        .expect("Failed to run ptrace");
    assert_eq!(out.status.code(), Some(127));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("failed to execute './nonexistent_binary_12345'"));
    assert!(!stderr.contains("panicked at"));

    // 3. Unknown flag exits cleanly with code 1 and usage message
    let out = std::process::Command::new(ptrace_bin)
        .args(["--bogus-flag", "/bin/echo", "hi"])
        .output()
        .expect("Failed to run ptrace");
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("Unknown option: --bogus-flag"));
    assert!(!stderr.contains("panicked at"));
}

