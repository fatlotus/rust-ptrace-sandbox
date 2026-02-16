use std::process::Command;

fn do_test_networking() {
    let ptrace_bin = env!("CARGO_BIN_EXE_ptrace");
    let networking_bin = env!("CARGO_BIN_EXE_networking_test");

    let output = Command::new(ptrace_bin)
        .arg("--verbose")
        .arg(networking_bin)
        .output()
        .expect("Failed to execute ptrace bin");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    println!("STDOUT: {}", stdout);
    println!("STDERR: {}", stderr);

    // We expect the test to succeed
    assert!(output.status.success(), "Networking test failed");
    
    // We expect to see some networking syscalls being intercepted and logged
    assert!(stdout.contains("socket("), "Missing socket syscall log");
    assert!(stdout.contains("bind("), "Missing bind syscall log");
    assert!(stdout.contains("connect("), "Missing connect syscall log");
}

#[test]
#[ntest::timeout(2000)]
fn test_networking() {
    do_test_networking();
}

#[test]
#[ntest::timeout(10000)]
#[cfg(feature = "stress")]
fn stress_test_networking() {
    for _ in 0..5 {
        do_test_networking();
    }
}
