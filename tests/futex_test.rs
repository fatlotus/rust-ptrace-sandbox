use std::process::Command;

fn do_test_futex(bin: &str, verbose: bool) {
    let ptrace_bin = env!("CARGO_BIN_EXE_ptrace");
    let test_bin = bin;
    
    let mut cmd = Command::new(ptrace_bin);
    if verbose {
        cmd.arg("--verbose");
    }
    let output = cmd.arg(test_bin)
        .output()
        .expect("Failed to execute ptrace bin");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    if !output.status.success() {
        println!("STDOUT: {}", stdout);
        println!("STDERR: {}", stderr);
    }

    assert!(output.status.success());
    if bin.contains("futex_test") {
        assert!(stdout.contains("Hello from thread!"));
        assert!(stdout.contains("Thread joined!"));
    } else {
        assert!(stdout.contains("Stress test finished!"));
    }
}

#[test]
#[ntest::timeout(5000)]
fn test_futex() {
    do_test_futex(env!("CARGO_BIN_EXE_futex_test"), false);
}

#[test]
#[ntest::timeout(5000)]
fn test_futex_verbose() {
    do_test_futex(env!("CARGO_BIN_EXE_futex_test"), true);
}

#[test]
#[ntest::timeout(10000)]
fn test_futex_stress() {
    do_test_futex(env!("CARGO_BIN_EXE_futex_stress_test"), false);
}

#[test]
#[ntest::timeout(10000)]
fn test_futex_sandbox() {
    let ptrace_bin = env!("CARGO_BIN_EXE_ptrace");
    let test_bin = env!("CARGO_BIN_EXE_futex_test");
    
    let output = Command::new(ptrace_bin)
        .arg("--sandbox")
        .arg(test_bin)
        .output()
        .expect("Failed to execute ptrace bin");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success());
    assert!(stdout.contains("Hello from thread!"));
    assert!(stdout.contains("Thread joined!"));
}

#[test]
#[ntest::timeout(10000)]
fn test_futex_stress_sandbox() {
    let ptrace_bin = env!("CARGO_BIN_EXE_ptrace");
    let test_bin = env!("CARGO_BIN_EXE_futex_stress_test");
    
    let output = Command::new(ptrace_bin)
        .arg("--sandbox")
        .arg(test_bin)
        .output()
        .expect("Failed to execute ptrace bin");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success());
    assert!(stdout.contains("Stress test finished!"));
}
