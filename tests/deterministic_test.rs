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

    let tid1 = stdout1.lines().find(|l| l.contains("Tid:")).unwrap();
    let tid2 = stdout2.lines().find(|l| l.contains("Tid:")).unwrap();
    assert_eq!(tid1, tid2);
    assert_eq!(tid1, "Tid: 1234");

    let rdir1 = stdout1.lines().find(|l| l.contains("ReadDir:")).unwrap();
    assert_eq!(rdir1, "ReadDir: true");

    let fd1 = stdout1.lines().find(|l| l.contains("FdTest:")).unwrap();
    let fd2 = stdout2.lines().find(|l| l.contains("FdTest:")).unwrap();
    assert_eq!(fd1, fd2);
    assert_eq!(fd1, "FdTest: dup=42 poll=2 rev0=0 rev1=4 rev2=32 close=0,0,-1");

    let tsc1 = stdout1.lines().find(|l| l.contains("Rdtsc:")).unwrap();
    let tsc2 = stdout2.lines().find(|l| l.contains("Rdtsc:")).unwrap();
    assert_eq!(tsc1, tsc2);
    assert!(tsc1.ends_with("aux=0 mono=true"));

    let fcheck1 = stdout1.lines().find(|l| l.contains("FutexCheck:")).unwrap();
    assert_eq!(fcheck1, "FutexCheck: eagain=-1 bitset=-1 time_after=946684800");

    let ralias1 = stdout1.lines().find(|l| l.contains("RandomAliases:")).unwrap();
    let ralias2 = stdout2.lines().find(|l| l.contains("RandomAliases:")).unwrap();
    assert_eq!(ralias1, ralias2);
    assert_eq!(
        ralias1,
        "RandomAliases: alias=[66, 66, 66, 66] readv=4(66) uuid=42424242-4242-4242-4242-424242424242"
    );

    let sysids1 = stdout1.lines().find(|l| l.contains("SysIds:")).unwrap();
    let sysids2 = stdout2.lines().find(|l| l.contains("SysIds:")).unwrap();
    assert_eq!(sysids1, sysids2);
    assert_eq!(sysids1, "SysIds: adj=0:946684800 ru=0:0 cpu=0:0:0 pgid=1 sid=1");

    let proc1 = stdout1.lines().find(|l| l.contains("ProcCheck:")).unwrap();
    let proc2 = stdout2.lines().find(|l| l.contains("ProcCheck:")).unwrap();
    assert_eq!(proc1, proc2);
    assert_eq!(proc1, "ProcCheck: cpid=1235 wpid=1235 raise=0 usr1=1");

    let page1 = stdout1.lines().find(|l| l.contains("PageBoundary:")).unwrap();
    let page2 = stdout2.lines().find(|l| l.contains("PageBoundary:")).unwrap();
    assert_eq!(page1, page2);
    assert_eq!(page1, "PageBoundary: gr=5 bytes=[66, 66, 66, 66, 66]");

    let sock1 = stdout1.lines().find(|l| l.contains("SockCheck:")).unwrap();
    let sock2 = stdout2.lines().find(|l| l.contains("SockCheck:")).unwrap();
    assert_eq!(sock1, sock2);
    assert_eq!(
        sock1,
        "SockCheck: sp=0:2:2 eagain=-1 conn=0 tiny_len=16 sentinel=0xaa fstatat=0:49152"
    );

    // Ensure full output is 100% identical across runs
    assert_eq!(stdout1, stdout2);
}

#[test]
#[ntest::timeout(1000)]
fn test_shell_sleep_and_exit_code() {
    let ptrace_bin = env!("CARGO_BIN_EXE_ptrace");

    // Verify `/bin/sh -c "/bin/sleep 1"` completes quickly via virtual time dilation even when parent blocks in wait4
    let sleep_start = std::time::Instant::now();
    let sh_sleep = Command::new(ptrace_bin)
        .arg("--sandbox")
        .arg("/bin/sh")
        .arg("-c")
        .arg("/bin/sleep 1")
        .output()
        .expect("Failed to execute sh sleep");
    assert!(sh_sleep.status.success());
    assert!(sleep_start.elapsed().as_millis() < 500);

    let false_out = Command::new(ptrace_bin)
        .arg("--sandbox")
        .arg("/bin/sh")
        .arg("-c")
        .arg("exit 42")
        .output()
        .expect("Failed to execute ptrace bin");
    assert_eq!(false_out.status.code(), Some(42));
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
