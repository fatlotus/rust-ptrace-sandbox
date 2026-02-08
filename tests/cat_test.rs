use std::process::Command;
use std::fs;

#[test]
fn test_cat() {
    let ptrace_bin = env!("CARGO_BIN_EXE_ptrace");
    let test_file = "test_cat.txt";
    fs::write(test_file, "meow world").expect("Failed to write test file");

    let output = Command::new(ptrace_bin)
        .arg("/bin/cat")
        .arg(test_file)
        .output()
        .expect("Failed to execute ptrace bin");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    println!("STDOUT: {}", stdout);
    println!("STDERR: {}", stderr);

    // Clean up
    let _ = fs::remove_file(test_file);

    assert!(output.status.success());
    assert!(stdout.contains("meow world"));
    
    // Verify syscalls in trace output
    assert!(stdout.contains("openat("));
    assert!(stdout.contains("read("));
    assert!(stdout.contains("write(1,"));
    assert!(stdout.contains("close("));
}
