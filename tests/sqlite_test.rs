use std::process::Command;
use std::fs;

fn do_test_sqlite(db_file: &str) {
    let ptrace_bin = env!("CARGO_BIN_EXE_ptrace");
    // Clean up previous run
    let _ = fs::remove_file(db_file);
    let _ = fs::remove_file(format!("{}-journal", db_file));
    let _ = fs::remove_file(format!("{}-wal", db_file));
    let _ = fs::remove_file(format!("{}-shm", db_file));

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
    let _ = fs::remove_file(format!("{}-shm", db_file));

    if !output.status.success() {
         panic!("sqlite3 failed with status: {:?}\nSTDOUT:\n{}\nSTDERR:\n{}", output.status, stdout, stderr);
    }

    assert!(stdout.contains("hello sqlite"));
    assert!(stdout.contains("lseek("));
    assert!(stdout.contains("fcntl("));
}

#[test]
#[ntest::timeout(1000)]
fn test_sqlite() {
    let thread_id = format!("{:?}", std::thread::current().id());
    let thread_id = thread_id.replace("ThreadId(", "").replace(")", "");
    do_test_sqlite(&format!("test_{}.db", thread_id));
}

#[test]
#[ntest::timeout(10000)]
#[cfg(feature = "stress")]
fn stress_test_sqlite() {
    let thread_id = format!("{:?}", std::thread::current().id());
    let thread_id = thread_id.replace("ThreadId(", "").replace(")", "");
    for i in 0..5 {
        do_test_sqlite(&format!("test_stress_{}_{}.db", thread_id, i));
    }
}
