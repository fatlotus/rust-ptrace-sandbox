use std::process::Command;
use std::fs;
use std::io::Write;
use std::sync::atomic::{AtomicUsize, Ordering};

static TEST_FILE_COUNTER: AtomicUsize = AtomicUsize::new(0);

fn do_test_cat() {
    let ptrace_bin = env!("CARGO_BIN_EXE_ptrace");
    let test_file = format!("test_cat_{}.txt", TEST_FILE_COUNTER.fetch_add(1, Ordering::SeqCst));
    {
        let mut file = fs::File::create(&test_file).expect("Failed to create test file");
        file.write_all(b"meow world").expect("Failed to write test file");
        file.sync_all().expect("Failed to sync test file");
    }

    let output = Command::new(ptrace_bin)
        .arg("--verbose")
        .arg("/bin/cat")
        .arg(&test_file)
        .output()
        .expect("Failed to execute ptrace bin");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    println!("STDOUT: {}", stdout);
    println!("STDERR: {}", stderr);

    // Clean up
    let _ = fs::remove_file(&test_file);

    assert!(output.status.success(), "cat failed with status: {:?}\nSTDERR: {}", output.status, stderr);
    assert!(stdout.contains("meow world"));
    
    // Verify syscalls in trace output
    assert!(stdout.contains("openat("));
    assert!(stdout.contains("read("));
    assert!(stdout.contains("write(1,"));
    assert!(stdout.contains("close("));
}

#[test]
#[ntest::timeout(1000)]
fn test_cat() {
    do_test_cat();
}

#[test]
#[ntest::timeout(1000)]
#[cfg(feature = "stress")]
fn stress_test_cat() {
    for _ in 0..5 {
        do_test_cat();
    }
}
