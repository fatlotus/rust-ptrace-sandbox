use std::process::Command;
use std::fs;

#[test]
fn test_sqlite() {
    let ptrace_bin = env!("CARGO_BIN_EXE_ptrace");
    let db_file = "test.db";
    // Clean up previous run
    let _ = fs::remove_file(db_file);
    let _ = fs::remove_file(format!("{}-journal", db_file));
    let _ = fs::remove_file(format!("{}-wal", db_file));

    let sql_commands = "CREATE TABLE test (id INTEGER PRIMARY KEY, content TEXT); INSERT INTO test (content) VALUES ('hello sqlite'); SELECT content FROM test;";

    let output = Command::new(ptrace_bin)
        .arg("--verbose")
        .arg("sqlite3")
        .arg(db_file)
        .arg(sql_commands)
        .output()
        .expect("Failed to execute ptrace bin");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    println!("STDOUT: {}", stdout);
    println!("STDERR: {}", stderr);

    // Clean up
    let _ = fs::remove_file(db_file);
    let _ = fs::remove_file(format!("{}-journal", db_file));
    let _ = fs::remove_file(format!("{}-wal", db_file));

    if !output.status.success() {
         panic!("sqlite3 failed with status: {:?}\nSTDOUT:\n{}\nSTDERR:\n{}", output.status, stdout, stderr);
    }

    assert!(stdout.contains("hello sqlite"));
    
    // Verify our new syscalls were traced (sqlite definitely uses lseek and maybe unlink/pwrite)
    // Note: interceptor prints to stdout (or stderr depending on impl). passthru prints to stdout.
    // The test captures both but checks stdout for content.
    // ptrace might output to stderr or stdout. Passthru uses println!.
    
    // sqlite3 output "hello sqlite" should be in stdout.
    // Passthru traces should be in stdout too mixed in? Or does sqlite write to non-stdout fd?
    // sqlite prints to stdout. Passthru prints to stdout.
    
    // Let's check for "lseek" in stdout if we enabled it.
    assert!(stdout.contains("lseek("));
    assert!(stdout.contains("fcntl("));
}
