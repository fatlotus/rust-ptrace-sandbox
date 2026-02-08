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
