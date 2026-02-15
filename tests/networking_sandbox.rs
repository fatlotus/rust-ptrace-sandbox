use std::process::Command;

#[test]
fn test_networking_sandbox() {
    let ptrace_bin = env!("CARGO_BIN_EXE_ptrace");
    let networking_bin = env!("CARGO_BIN_EXE_networking_test");

    let output = Command::new(ptrace_bin)
        .arg("--sandbox")
        .arg("--verbose")
        .arg(networking_bin)
        .output()
        .expect("Failed to execute ptrace bin");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    println!("STDOUT: {}", stdout);
    println!("STDERR: {}", stderr);

    // We expect the test to succeed
    assert!(output.status.success(), "Networking sandbox test failed");
    
    // We expect to see virtualized networking logs
    assert!(stdout.contains("socket("), "Missing socket syscall log");
    assert!(stdout.contains("(VIRTUAL)"), "Missing VIRTUAL tag in logs");
    assert!(stdout.contains("bind("), "Missing bind syscall log");
    assert!(stdout.contains("connect("), "Missing connect syscall log");
    assert!(stdout.contains("accept("), "Missing accept syscall log");
}
