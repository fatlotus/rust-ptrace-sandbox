use nix::sys::ptrace;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{execvp, fork, ForkResult, Pid};
use std::ffi::CString;
use crate::linux::Linux;
use syscalls::Sysno;

pub fn run_with_interceptor<L: Linux>(cmd: &str, args: &[&str], mut handler: L) {
    match unsafe { fork() } {
        Ok(ForkResult::Parent { child }) => {
            parent_loop(child, &mut handler);
        }
        Ok(ForkResult::Child) => {
            ptrace::traceme().expect("Failed to traceme");
            let c_cmd = CString::new(cmd).unwrap();
            let mut c_args: Vec<CString> = Vec::new();
            c_args.push(c_cmd.clone());
            for arg in args {
                c_args.push(CString::new(*arg).unwrap());
            }
            
            let _ = execvp(&c_cmd, &c_args);
            panic!("Failed to execvp");
        }
        Err(e) => panic!("Fork failed: {}", e),
    }
}

fn waitpid_with_timeout(child: Pid) -> WaitStatus {
    let start = std::time::Instant::now();
    loop {
        match waitpid(child, Some(nix::sys::wait::WaitPidFlag::WNOHANG)).expect("Wait failed") {
            WaitStatus::StillAlive => {
                if start.elapsed().as_secs() >= 1 {
                    eprintln!("Child process timed out, killing...");
                    let _ = nix::sys::signal::kill(child, nix::sys::signal::Signal::SIGKILL);
                    panic!("Child process timed out");
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            other => return other,
        }
    }
}

fn parent_loop<L: Linux>(child: Pid, handler: &mut L) {
    // Initial wait
    waitpid_with_timeout(child);
    ptrace::setoptions(child, ptrace::Options::PTRACE_O_TRACESYSGOOD).expect("Failed to set options");

    let mut in_syscall = false;
    let mut saved_result: i64 = 0;

    loop {
        ptrace::syscall(child, None).expect("PTRACE_SYSCALL failed");
        
        let status = waitpid_with_timeout(child);

        match status {
            WaitStatus::PtraceSyscall(_) => {
                if !in_syscall {
                    // Syscall Entry
                    if let Some(res) = handle_syscall_entry(child, handler) {
                        saved_result = res;
                        let mut regs = ptrace::getregs(child).expect("Failed to get regs");
                        regs.orig_rax = u64::MAX; // -1 as u64
                        ptrace::setregs(child, regs).expect("Failed to set regs");
                    } else {
                        saved_result = -123456; // Sentinel for "did not replace"
                    }
                    in_syscall = true;
                } else {
                    // Syscall Exit
                    if saved_result != -123456 {
                        let mut regs = ptrace::getregs(child).expect("Failed to get regs");
                        regs.rax = saved_result as u64;
                        ptrace::setregs(child, regs).expect("Failed to set regs");
                    }
                    in_syscall = false;
                }
            }
            WaitStatus::Exited(_, status) => {
                println!("Child exited with status {}", status);
                break;
            }
            WaitStatus::Signaled(_, sig, _) => {
                println!("Child signaled with {}", sig);
                break;
            }
            _other => {}
        }
    }
}

fn handle_syscall_entry<L: Linux>(pid: Pid, handler: &mut L) -> Option<i64> {
    let regs = ptrace::getregs(pid).expect("Failed to get regs");
    let syscall_no = regs.orig_rax;
    let sysno = Sysno::new(syscall_no as usize);

    match sysno {
        Some(Sysno::read) => {
            let fd = regs.rdi as i32;
            let count = regs.rdx as usize;
            let _buf = handler.read(fd, count);
            None // Passthru: let the real syscall handle the memory move
        }
        Some(Sysno::write) => {
            let fd = regs.rdi as i32;
            let addr = regs.rsi as usize;
            let count = regs.rdx as usize;
            let buf = read_memory(pid, addr, count);
            Some(handler.write(fd, &buf) as i64)
        }
        Some(Sysno::open) => {
            let addr = regs.rdi as usize;
            let flags = regs.rsi as i32;
            let mode = regs.rdx as libc::mode_t;
            let pathname = read_string(pid, addr);
            let _ = handler.open(&pathname, flags, mode);
            None // Passthru
        }
        Some(Sysno::close) => {
            let fd = regs.rdi as i32;
            let _ = handler.close(fd);
            None // Passthru
        }
        Some(Sysno::fstat) => {
            let fd = regs.rdi as i32;
            let _ = handler.fstat(fd);
            None // Passthru
        }
        Some(Sysno::mmap) => {
            let addr = regs.rdi as *mut libc::c_void;
            let length = regs.rsi as usize;
            let prot = regs.rdx as i32;
            let flags = regs.r10 as i32;
            let fd = regs.r8 as i32;
            let offset = regs.r9 as libc::off_t;
            let _ = handler.mmap(addr, length, prot, flags, fd, offset);
            None // Passthru
        }
        Some(Sysno::munmap) => {
            let addr = regs.rdi as *mut libc::c_void;
            let length = regs.rsi as usize;
            let _ = handler.munmap(addr, length);
            None // Passthru
        }
        Some(Sysno::brk) => {
            let addr = regs.rdi as *mut libc::c_void;
            let _ = handler.brk(addr);
            None // Passthru
        }
        Some(Sysno::clock_gettime) => {
            let clk_id = regs.rdi as libc::clockid_t;
            let _ = handler.clock_gettime(clk_id);
            None // Passthru
        }
        Some(Sysno::openat) => {
            let dirfd = regs.rdi as i32;
            let addr = regs.rsi as usize;
            let flags = regs.rdx as i32;
            let mode = regs.r10 as libc::mode_t;
            let pathname = read_string(pid, addr);
            let _ = handler.openat(dirfd, &pathname, flags, mode);
            None // Passthru
        }
        Some(Sysno::newfstatat) => {
            let dirfd = regs.rdi as i32;
            let addr = regs.rsi as usize;
            let flags = regs.r10 as i32;
            let pathname = read_string(pid, addr);
            let _ = handler.newfstatat(dirfd, &pathname, flags);
            None // Passthru
        }
        Some(Sysno::futex) => {
            let uaddr = regs.rdi as *mut i32;
            let op = regs.rsi as i32;
            let val = regs.rdx as i32;
            println!("futex({:?}, {}, {}, ...) = passthru", uaddr, op, val);
            None // Passthru
        }
        Some(Sysno::exit) => {
            let status = regs.rdi as i32;
            handler.exit(status);
            Some(0)
        }
        Some(Sysno::exit_group) => {
            let status = regs.rdi as i32;
            handler.exit_group(status);
            Some(0)
        }
        _ => None,
    }
}

fn read_string(pid: Pid, addr: usize) -> String {
    let mut result = Vec::new();
    let mut current_addr = addr;
    loop {
        let word = ptrace::read(pid, current_addr as *mut _).unwrap_or(0);
        let bytes: [u8; 8] = word.to_ne_bytes();
        for &b in &bytes {
            if b == 0 {
                return String::from_utf8_lossy(&result).into_owned();
            }
            result.push(b);
        }
        current_addr += 8;
    }
}

fn read_memory(pid: Pid, addr: usize, count: usize) -> Vec<u8> {
    let mut data = Vec::with_capacity(count);
    let mut read = 0;
    while read < count {
        let word = ptrace::read(pid, (addr + read) as *mut _).unwrap_or(0);
        let to_copy = std::cmp::min(count - read, std::mem::size_of::<libc::c_long>());
        let bytes: [u8; 8] = word.to_ne_bytes();
        data.extend_from_slice(&bytes[..to_copy]);
        read += to_copy;
    }
    data
}
