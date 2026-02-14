use std::process::Command;

#[test]
fn test_date() {
    let ptrace_bin = env!("CARGO_BIN_EXE_ptrace");
    let output = Command::new(ptrace_bin)
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

#[test]
fn test_date_sandbox() {
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
    // Fixed timestamp: 1771024305 is Sat Feb 14 23:11:45 UTC 2026
    // date command output format varies, but it should contain "Feb 14" and "23:11:45" and "2026"
    assert!(stdout.contains("2026"));
    assert!(stdout.contains("Feb"));
    assert!(stdout.contains("14"));
    assert!(stdout.contains("23:11:45"));
}
