use std::process::Command;

#[test]
fn test_echo() {
    let ptrace_bin = env!("CARGO_BIN_EXE_ptrace");
    let output = Command::new(ptrace_bin)
        .arg("/bin/echo")
        .arg("hello world")
        .output()
        .expect("Failed to execute ptrace bin");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    println!("STDOUT: {}", stdout);
    println!("STDERR: {}", stderr);

    assert!(output.status.success());
    assert!(stdout.contains("hello world"));
    // Passthru should print write and brk syscalls
    assert!(stdout.contains("write(1,"));
    assert!(stdout.contains("brk("));
}
