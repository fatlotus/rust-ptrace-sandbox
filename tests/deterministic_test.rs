use std::process::Command;

fn do_test_random_gen_deterministic() {
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

    let time1 = stdout1.lines().find(|l| l.contains("Time:")).unwrap();
    let time2 = stdout2.lines().find(|l| l.contains("Time:")).unwrap();
    assert_eq!(time1, time2);
    assert!(time1.contains("946684800"));

    let sys1 = stdout1.lines().find(|l| l.contains("Sysinfo:")).unwrap();
    let sys2 = stdout2.lines().find(|l| l.contains("Sysinfo:")).unwrap();
    assert_eq!(sys1, sys2);

    let uname1 = stdout1.lines().find(|l| l.contains("Uname:")).unwrap();
    let uname2 = stdout2.lines().find(|l| l.contains("Uname:")).unwrap();
    assert_eq!(uname1, uname2);
    assert!(uname1.contains("nodename=sandbox"));

    let faults1 = stdout1.lines().find(|l| l.contains("Faults:")).unwrap();
    assert_eq!(faults1, "Faults: getrandom=-1 nanosleep=-1");

    let urand1 = stdout1.lines().find(|l| l.contains("Urandom:")).unwrap();
    let urand2 = stdout2.lines().find(|l| l.contains("Urandom:")).unwrap();
    assert_eq!(urand1, urand2);
    assert_eq!(urand1, "Urandom: [66, 66, 66, 66, 66, 66, 66, 66]");

    let at_rand1 = stdout1.lines().find(|l| l.contains("AT_RANDOM:")).unwrap();
    let at_rand2 = stdout2.lines().find(|l| l.contains("AT_RANDOM:")).unwrap();
    assert_eq!(at_rand1, at_rand2);
    assert_eq!(at_rand1, "AT_RANDOM: [66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66]");

    let stat1 = stdout1.lines().find(|l| l.contains("Stat:")).unwrap();
    let stat2 = stdout2.lines().find(|l| l.contains("Stat:")).unwrap();
    assert_eq!(stat1, stat2);
    assert!(stat1.ends_with("mtime=0"));

    let statx1 = stdout1.lines().find(|l| l.contains("Statx:")).unwrap();
    let statx2 = stdout2.lines().find(|l| l.contains("Statx:")).unwrap();
    assert_eq!(statx1, statx2);
    assert!(statx1.ends_with("mtime=0"));
}

fn do_test_random_gen_nondeterministic() {
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

#[test]
#[ntest::timeout(1000)]
fn test_random_gen_deterministic() {
    do_test_random_gen_deterministic();
}

#[test]
#[ntest::timeout(1000)]
#[cfg(feature = "stress")]
fn stress_test_random_gen_deterministic() {
    for _ in 0..5 {
        do_test_random_gen_deterministic();
    }
}

#[test]
#[ntest::timeout(1000)]
fn test_random_gen_nondeterministic() {
    do_test_random_gen_nondeterministic();
}

#[test]
#[ntest::timeout(1000)]
#[cfg(feature = "stress")]
fn stress_test_random_gen_nondeterministic() {
    for _ in 0..5 {
        do_test_random_gen_nondeterministic();
    }
}
