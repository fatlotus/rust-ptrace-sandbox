use std::process::Command;

#[test]
fn test_fork() {
    let ptrace_bin = env!("CARGO_BIN_EXE_ptrace");
    let output = Command::new(ptrace_bin)
        .arg("--verbose")
        .arg("/bin/bash")
        .arg("-c")
        .arg("/bin/echo hello from fork")
        .output()
        .expect("Failed to execute ptrace bin");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    println!("STDOUT: {}", stdout);
    println!("STDERR: {}", stderr);

    assert!(output.status.success());
    assert!(stdout.contains("hello from fork"));
    
    // We expect to see the child process's write as well
    // If fork isn't handled, the child might escape or fail.
    assert!(stdout.contains("write(1, \"hello from fork\\n\", 16) = 16"));
}
