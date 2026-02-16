use std::process::Command;

fn do_test_date() {
    let ptrace_bin = env!("CARGO_BIN_EXE_ptrace");
    let output = Command::new(ptrace_bin)
        .arg("--verbose")
        .arg("/bin/date")
        .output()
        .expect("Failed to execute ptrace bin");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    println!("STDOUT: {}", stdout);
    println!("STDERR: {}", stderr);

    assert!(output.status.success());
    // Basic check that it output something resembling a date (usually contains a year like 20)
    assert!(stdout.contains("20"));
    
    // Verify syscalls
    assert!(stdout.contains("clock_gettime("));
}

fn do_test_date_sandbox() {
    let ptrace_bin = env!("CARGO_BIN_EXE_ptrace");
    let output = Command::new(ptrace_bin)
        .arg("--sandbox")
        .arg("/bin/date")
        .output()
        .expect("Failed to execute ptrace bin");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    println!("STDOUT: {}", stdout);
    println!("STDERR: {}", stderr);

    assert!(output.status.success());
    // Fixed timestamp: 946684800 is Sat Jan  1 00:00:00 UTC 2000
    // date command output format varies, but it should contain "Jan  1" and "00:00:00" and "2000"
    assert!(stdout.contains("2000"));
    assert!(stdout.contains("Jan"));
    assert!(stdout.contains("1"));
    assert!(stdout.contains("00:00:00"));
}

#[test]
#[ntest::timeout(1000)]
fn test_date() {
    do_test_date();
}

#[test]
#[ntest::timeout(1000)]
#[cfg(feature = "stress")]
fn stress_test_date() {
    for _ in 0..5 {
        do_test_date();
    }
}

#[test]
#[ntest::timeout(1000)]
fn test_date_sandbox() {
    do_test_date_sandbox();
}

#[test]
#[ntest::timeout(1000)]
#[cfg(feature = "stress")]
fn stress_test_date_sandbox() {
    for _ in 0..5 {
        do_test_date_sandbox();
    }
}
