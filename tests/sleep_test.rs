use std::process::Command;
use std::time::Instant;

#[test]
#[ntest::timeout(5000)]
fn test_sleep_time_dilation() {
    let ptrace_bin = env!("CARGO_BIN_EXE_ptrace");
    let test_bin = env!("CARGO_BIN_EXE_sleep_test");

    let real_start = Instant::now();
    let output = Command::new(ptrace_bin)
        .arg("--sandbox")
        .arg(test_bin)
        .output()
        .expect("Failed to execute ptrace bin");

    let real_elapsed = real_start.elapsed();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    println!("STDOUT: {}", stdout);
    println!("STDERR: {}", stderr);
    println!("Real elapsed time: {:?}", real_elapsed);

    assert!(output.status.success());
    assert!(stdout.contains("Sleep completed successfully!"));
    assert!(stdout.contains("Virtual elapsed:"));
    // Verify that it runs much faster than 10 seconds in real time
    assert!(real_elapsed.as_secs_f64() < 5.0, "Expected run time < 5s, took {:?}", real_elapsed);
}
