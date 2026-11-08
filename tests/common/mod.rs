#![allow(dead_code)]

use std::fmt::Debug;
use std::io::Write;
use std::process::{Command, Output, Stdio};

const GUEST_ENV: &str = "__PTRACE_GUEST";
const RESULT_PREFIX: &str = "__PTRACE_RESULT__:";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestMode {
    Sandbox,
    Passthru,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestOutput {
    pub result: String,
    pub stdout: String,
    pub stderr: String,
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

fn hex_decode(hex: &str) -> Vec<u8> {
    let bytes = hex.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0;
    while i + 1 < bytes.len() {
        let hi = (bytes[i] as char).to_digit(16).unwrap_or(0) as u8;
        let lo = (bytes[i + 1] as char).to_digit(16).unwrap_or(0) as u8;
        out.push((hi << 4) | lo);
        i += 2;
    }
    out
}

pub fn is_guest() -> Option<GuestMode> {
    match std::env::var(GUEST_ENV).as_deref() {
        Ok("sandbox") => Some(GuestMode::Sandbox),
        Ok("passthru") => Some(GuestMode::Passthru),
        _ => None,
    }
}

pub fn spawn_guest(test_name: &str, mode: GuestMode) -> GuestOutput {
    let ptrace_bin = env!("CARGO_BIN_EXE_ptrace");
    let current_exe = std::env::current_exe().expect("Failed to determine current_exe");

    let mut cmd = Command::new(ptrace_bin);
    if mode == GuestMode::Passthru {
        cmd.arg("--passthru");
    }
    let mode_str = match mode {
        GuestMode::Sandbox => "sandbox",
        GuestMode::Passthru => "passthru",
    };

    let output = cmd
        .arg(&current_exe)
        .arg("--exact")
        .arg(test_name)
        .arg("--nocapture")
        .arg("--test-threads=1")
        .env(GUEST_ENV, mode_str)
        .output()
        .expect("Failed to spawn ptrace guest");

    let stdout_raw = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr_raw = String::from_utf8_lossy(&output.stderr).into_owned();

    assert!(
        output.status.success(),
        "Guest test `{}` ({:?}) failed with status {:?}\nSTDOUT:\n{}\nSTDERR:\n{}",
        test_name,
        mode,
        output.status,
        stdout_raw,
        stderr_raw
    );

    let mut result_val = None;
    let mut user_lines = Vec::new();
    for line in stdout_raw.lines() {
        if let Some(idx) = line.find(RESULT_PREFIX) {
            let hex = &line[idx + RESULT_PREFIX.len()..];
            let decoded = hex_decode(hex.trim());
            result_val = Some(String::from_utf8_lossy(&decoded).into_owned());
        } else if !line.starts_with("running 1 test")
            && !line.starts_with("test ")
            && !line.is_empty()
        {
            user_lines.push(line);
        }
    }

    let result = result_val.unwrap_or_else(|| {
        panic!(
            "Guest test `{}` ({:?}) exited without producing a result marker.\nSTDOUT:\n{}\nSTDERR:\n{}",
            test_name, mode, stdout_raw, stderr_raw
        )
    });

    GuestOutput {
        result,
        stdout: user_lines.join("\n"),
        stderr: stderr_raw,
    }
}

fn execute_if_guest<T, F, V>(body: F, validate: V) -> bool
where
    T: Debug,
    F: FnOnce() -> T,
    V: FnOnce(&T),
{
    if let Some(mode) = is_guest() {
        let val = body();
        if mode == GuestMode::Sandbox {
            validate(&val);
        }
        let formatted = format!("{:?}", val);
        println!("\n{}{}", RESULT_PREFIX, hex_encode(formatted.as_bytes()));
        let _ = std::io::stdout().flush();
        std::process::exit(0);
    }
    false
}

fn stress_iterations() -> usize {
    if cfg!(feature = "stress") {
        3
    } else {
        1
    }
}

/// Runs `body` inside two fresh deterministic sandboxes and asserts their outputs and return values match.
pub fn run_sandbox_test<T, F, V>(test_name: &str, body: F, validate: V)
where
    T: Debug,
    F: FnOnce() -> T,
    V: FnOnce(&T),
{
    if execute_if_guest(body, validate) {
        return;
    }
    for _ in 0..stress_iterations() {
        let run1 = spawn_guest(test_name, GuestMode::Sandbox);
        let run2 = spawn_guest(test_name, GuestMode::Sandbox);
        assert_eq!(
            run1.result, run2.result,
            "Sandbox runs produced different return values for `{}`",
            test_name
        );
        assert_eq!(
            run1.stdout, run2.stdout,
            "Sandbox runs produced different stdout for `{}`",
            test_name
        );
    }
}

/// Runs `body` twice in sandbox mode (asserting `s1 == s2`) AND in passthru mode
/// (asserting that consecutive passthru runs differ `p1 != p2`, proving genuine nondeterminism is cured).
pub fn run_nondeterminism_test<T, F, V>(test_name: &str, body: F, validate: V)
where
    T: Debug,
    F: FnOnce() -> T,
    V: FnOnce(&T),
{
    if execute_if_guest(body, validate) {
        return;
    }
    for _ in 0..stress_iterations() {
        let s1 = spawn_guest(test_name, GuestMode::Sandbox);
        let s2 = spawn_guest(test_name, GuestMode::Sandbox);
        assert_eq!(
            s1.result, s2.result,
            "Sandbox failed to make `{}` deterministic",
            test_name
        );
        assert_eq!(s1.stdout, s2.stdout);

        let p1 = spawn_guest(test_name, GuestMode::Passthru);
        let mut saw_diff = false;
        for _ in 0..4 {
            let p2 = spawn_guest(test_name, GuestMode::Passthru);
            if p1.result != p2.result || p1.stdout != p2.stdout {
                saw_diff = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        assert!(
            saw_diff,
            "Expected `{}` to be nondeterministic in passthru mode, but all passthru runs returned `{}`",
            test_name, p1.result
        );
    }
}

/// Runs `body` twice in sandbox mode (asserting `s1 == s2`) AND once in passthru mode
/// (asserting `passthru != sandbox`, proving host state is virtualized/isolated).
pub fn run_virtualized_test<T, F, V>(test_name: &str, body: F, validate: V)
where
    T: Debug,
    F: FnOnce() -> T,
    V: FnOnce(&T),
{
    if execute_if_guest(body, validate) {
        return;
    }
    for _ in 0..stress_iterations() {
        let s1 = spawn_guest(test_name, GuestMode::Sandbox);
        let s2 = spawn_guest(test_name, GuestMode::Sandbox);
        assert_eq!(
            s1.result, s2.result,
            "Sandbox runs produced different results for `{}`",
            test_name
        );

        let p1 = spawn_guest(test_name, GuestMode::Passthru);
        assert_ne!(
            s1.result, p1.result,
            "Expected sandbox to virtualize host value in `{}`, but sandbox and passthru both returned `{}`",
            test_name, s1.result
        );
    }
}

/// Fluent builder for testing external CLI commands under the `ptrace` binary.
pub struct SandboxCommand {
    program: String,
    args: Vec<String>,
    stdin_data: Option<Vec<u8>>,
    passthru: bool,
    verbose: bool,
}

pub struct CommandResult {
    pub output: Output,
    pub stdout: String,
    pub stderr: String,
}

impl SandboxCommand {
    pub fn new(program: impl Into<String>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            stdin_data: None,
            passthru: false,
            verbose: false,
        }
    }

    pub fn arg(mut self, arg: impl Into<String>) -> Self {
        self.args.push(arg.into());
        self
    }

    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        for a in args {
            self.args.push(a.into());
        }
        self
    }

    pub fn stdin(mut self, data: impl Into<Vec<u8>>) -> Self {
        self.stdin_data = Some(data.into());
        self
    }

    pub fn passthru(mut self) -> Self {
        self.passthru = true;
        self
    }

    pub fn verbose(mut self) -> Self {
        self.verbose = true;
        self
    }

    pub fn run(&self) -> CommandResult {
        let ptrace_bin = env!("CARGO_BIN_EXE_ptrace");
        let mut cmd = Command::new(ptrace_bin);
        if self.passthru {
            cmd.arg("--passthru");
        }
        if self.verbose {
            cmd.arg("--verbose");
        }
        cmd.arg(&self.program).args(&self.args);

        let output = if let Some(ref input) = self.stdin_data {
            let mut child = cmd
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("Failed to spawn ptrace command");
            child
                .stdin
                .take()
                .unwrap()
                .write_all(input)
                .expect("Failed to write to stdin");
            child.wait_with_output().expect("Failed to wait on child")
        } else {
            cmd.output().expect("Failed to execute ptrace command")
        };

        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        CommandResult {
            output,
            stdout,
            stderr,
        }
    }
}

impl CommandResult {
    pub fn assert_success(self) -> Self {
        assert!(
            self.output.status.success(),
            "Expected command to succeed, got {:?}\nSTDOUT:\n{}\nSTDERR:\n{}",
            self.output.status,
            self.stdout,
            self.stderr
        );
        self
    }

    pub fn assert_exit_code(self, expected: i32) -> Self {
        assert_eq!(
            self.output.status.code(),
            Some(expected),
            "Expected exit code {}, got {:?}\nSTDOUT:\n{}\nSTDERR:\n{}",
            expected,
            self.output.status,
            self.stdout,
            self.stderr
        );
        self
    }

    pub fn assert_stdout_eq(self, expected: &str) -> Self {
        assert_eq!(self.stdout, expected);
        self
    }

    pub fn assert_stdout_contains(self, needle: &str) -> Self {
        assert!(
            self.stdout.contains(needle),
            "Expected stdout to contain {:?}, got:\n{}",
            needle,
            self.stdout
        );
        self
    }
}

#[macro_export]
macro_rules! sandbox_test {
    ($name:ident, $body:expr) => {
        #[test]
        fn $name() {
            $crate::common::run_sandbox_test(stringify!($name), $body, |_| {});
        }
    };
    ($name:ident, $body:expr, $validate:expr) => {
        #[test]
        fn $name() {
            $crate::common::run_sandbox_test(stringify!($name), $body, $validate);
        }
    };
}

#[macro_export]
macro_rules! nondeterminism_test {
    ($name:ident, $body:expr) => {
        #[test]
        fn $name() {
            $crate::common::run_nondeterminism_test(stringify!($name), $body, |_| {});
        }
    };
    ($name:ident, $body:expr, $validate:expr) => {
        #[test]
        fn $name() {
            $crate::common::run_nondeterminism_test(stringify!($name), $body, $validate);
        }
    };
}

#[macro_export]
macro_rules! virtualized_test {
    ($name:ident, $body:expr) => {
        #[test]
        fn $name() {
            $crate::common::run_virtualized_test(stringify!($name), $body, |_| {});
        }
    };
    ($name:ident, $body:expr, $validate:expr) => {
        #[test]
        fn $name() {
            $crate::common::run_virtualized_test(stringify!($name), $body, $validate);
        }
    };
}
