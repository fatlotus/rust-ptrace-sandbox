use std::process::Command;

#[test]
fn test_random_gen_deterministic() {
    let ptrace_bin = env!("CARGO_BIN_EXE_ptrace");
    let random_gen_bin = env!("CARGO_BIN_EXE_random_gen");

    let output1 = Command::new(ptrace_bin)
        .arg("--sandbox")
        .arg(random_gen_bin)
        .output()
        .expect("Failed to execute ptrace bin");

    let output2 = Command::new(ptrace_bin)
        .arg("--sandbox")
        .arg(random_gen_bin)
        .output()
        .expect("Failed to execute ptrace bin");

    let stdout1 = String::from_utf8_lossy(&output1.stdout);
    let stdout2 = String::from_utf8_lossy(&output2.stdout);

    println!("STDOUT 1: {}", stdout1);
    println!("STDOUT 2: {}", stdout2);

    assert!(output1.status.success());
    assert!(output2.status.success());
    
    let line1 = stdout1.lines().find(|l| l.contains("Random bytes:")).unwrap();
    let line2 = stdout2.lines().find(|l| l.contains("Random bytes:")).unwrap();
    
    assert_eq!(line1, line2);
    // Also verify it's not the same as a non-deterministic run (implicitly covered by test_random_gen_nondeterministic)
}

#[test]
fn test_random_gen_nondeterministic() {
    let ptrace_bin = env!("CARGO_BIN_EXE_ptrace");
    let random_gen_bin = env!("CARGO_BIN_EXE_random_gen");

    let output1 = Command::new(ptrace_bin)
        .arg(random_gen_bin)
        .output()
        .expect("Failed to execute ptrace bin");

    let output2 = Command::new(ptrace_bin)
        .arg(random_gen_bin)
        .output()
        .expect("Failed to execute ptrace bin");

    let stdout1 = String::from_utf8_lossy(&output1.stdout);
    let stdout2 = String::from_utf8_lossy(&output2.stdout);

    println!("STDOUT 1: {}", stdout1);
    println!("STDOUT 2: {}", stdout2);

    assert!(output1.status.success());
    assert!(output2.status.success());
    // In passthru mode, they should (almost certainly) be different
    assert_ne!(stdout1, stdout2);
}
