use nix::sys::ptrace;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{execvp, fork, ForkResult, Pid};
use std::ffi::CString;
use crate::linux::Linux;
use syscalls::Sysno;
use crate::vdso;
use std::collections::HashMap;

struct ChildState {
    in_syscall: bool,
    saved_result: i64,
}

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

fn wait_any_with_timeout() -> WaitStatus {
    let start = std::time::Instant::now();
    loop {
        match waitpid(Pid::from_raw(-1), Some(nix::sys::wait::WaitPidFlag::WNOHANG)).expect("Wait failed") {
            WaitStatus::StillAlive => {
                if start.elapsed().as_secs() >= 5 { // Increased timeout for multi-process bash
                    panic!("Process group timed out");
                }
                std::thread::yield_now();
                std::thread::sleep(std::time::Duration::from_micros(100));
            }
            other => return other,
        }
    }
}

fn parent_loop<L: Linux>(initial_child: Pid, handler: &mut L) {
    // Initial wait for exec stop
    waitpid(initial_child, None).expect("Initial wait failed");
    
    // Disable vDSO before we start tracing syscalls
    let regs = ptrace::getregs(initial_child).expect("Failed to get regs for vDSO disable");
    vdso::disable_vdso(initial_child, regs.rsp);

    let options = ptrace::Options::PTRACE_O_TRACESYSGOOD |
                  ptrace::Options::PTRACE_O_TRACEFORK |
                  ptrace::Options::PTRACE_O_TRACEVFORK |
                  ptrace::Options::PTRACE_O_TRACECLONE |
                  ptrace::Options::PTRACE_O_TRACEEXEC; // Also trace exec to disable vdso again if needed
    ptrace::setoptions(initial_child, options).expect("Failed to set options");

    let mut tracees: HashMap<Pid, ChildState> = HashMap::new();
    tracees.insert(initial_child, ChildState { in_syscall: false, saved_result: 0 });

    ptrace::syscall(initial_child, None).expect("Initial PTRACE_SYSCALL failed");

    loop {
        if tracees.is_empty() { break; }

        let status = wait_any_with_timeout();
        let pid = match status.pid() {
            Some(p) => p,
            None => continue,
        };

        match status {
            WaitStatus::PtraceSyscall(_) => {
                let state = tracees.get_mut(&pid).expect("Unknown child");
                if !state.in_syscall {
                    // Syscall Entry
                    if let Some(res) = handle_syscall_entry(pid, handler) {
                        // The syscall was already executed inside handle_syscall_entry
                        // We are now at the exit stop (if still alive).
                        if let Ok(mut regs) = ptrace::getregs(pid) {
                            regs.rax = res as u64;
                            ptrace::setregs(pid, regs).expect("Failed to set regs");
                            state.in_syscall = false;
                        } else {
                            // Process likely exited during syscall injection
                            tracees.remove(&pid);
                            continue;
                        }
                    } else {
                        state.saved_result = -123456; // Sentinel for "did not replace"
                        state.in_syscall = true;
                    }
                } else {
                    // Syscall Exit
                    if state.saved_result != -123456 {
                        let mut regs = ptrace::getregs(pid).expect("Failed to get regs");
                        regs.rax = state.saved_result as u64;
                        ptrace::setregs(pid, regs).expect("Failed to set regs");
                    }
                    state.in_syscall = false;
                }
                ptrace::syscall(pid, None).expect("PTRACE_SYSCALL failed");
            }
            WaitStatus::PtraceEvent(_, _, event) => {
                if event == ptrace::Event::PTRACE_EVENT_FORK as i32 || 
                   event == ptrace::Event::PTRACE_EVENT_VFORK as i32 || 
                   event == ptrace::Event::PTRACE_EVENT_CLONE as i32 {
                    let new_pid = ptrace::getevent(pid).expect("Failed to get event msg");
                    let new_pid = Pid::from_raw(new_pid as i32);
                    tracees.insert(new_pid, ChildState { in_syscall: false, saved_result: 0 });
                    // New child is created stopped. We must wait for its SIGSTOP (or similar)
                    // which will be picked up by the main loop's waitpid.
                    // Do NOT restart it here properly to avoid races (ESRCH if not waited yet).
                } else if event == ptrace::Event::PTRACE_EVENT_EXEC as i32 {
                    // After exec, we might need to disable vDSO again?
                    // Usually vDSO is mapped to the same place, but auxv might change.
                    let regs = ptrace::getregs(pid).expect("Failed to get regs after exec");
                    vdso::disable_vdso(pid, regs.rsp);
                }
                ptrace::syscall(pid, None).expect("PTRACE_SYSCALL failed after event");
            }
            WaitStatus::Exited(_, status) => {
                println!("Child {} exited with status {}", pid, status);
                tracees.remove(&pid);
            }
            WaitStatus::Signaled(_, sig, _) => {
                println!("Child {} signaled with {}", pid, sig);
                tracees.remove(&pid);
            }
            _other => {
                // If stopped for other reasons (signals etc), just continue
                if status.pid().is_some() {
                    let _ = ptrace::syscall(pid, None);
                }
            }
        }
    }
}

fn handle_syscall_entry<L: Linux>(pid: Pid, handler: &mut L) -> Option<i64> {
    let proc = crate::captured::CapturedProcess::new(pid);
    let regs = proc.get_regs().expect("Failed to get regs");
    let syscall_no = regs.orig_rax;
    let sysno = Sysno::new(syscall_no as usize);

    match sysno {
        Some(Sysno::read) => {
            let fd = regs.rdi as i32;
            let count = regs.rdx as usize;
            match handler.read(&proc, fd, count) {
                Ok(buf) => Some(buf.len() as i64),
                Err(err) => Some(-(err as i32) as i64),
            }
        }
        Some(Sysno::write) => {
            let fd = regs.rdi as i32;
            let addr = regs.rsi as usize;
            let count = regs.rdx as usize;
            let buf = proc.read_memory(addr, count);
            match handler.write(&proc, fd, &buf) {
                Ok(res) => Some(res as i64),
                Err(err) => Some(-(err as i32) as i64),
            }
        }
        Some(Sysno::open) => {
            let addr = regs.rdi as usize;
            let flags = regs.rsi as i32;
            let mode = regs.rdx as libc::mode_t;
            let pathname = read_string(pid, addr);
            match handler.open(&proc, &pathname, flags, mode) {
                Ok(res) => Some(res as i64),
                Err(err) => Some(-(err as i32) as i64),
            }
        }
        Some(Sysno::close) => {
            let fd = regs.rdi as i32;
            match handler.close(&proc, fd) {
                Ok(res) => Some(res as i64),
                Err(err) => Some(-(err as i32) as i64),
            }
        }
        Some(Sysno::fstat) => {
            let fd = regs.rdi as i32;
            match handler.fstat(&proc, fd) {
                Ok(res) => Some(res as i64),
                Err(err) => Some(-(err as i32) as i64),
            }
        }
        Some(Sysno::mmap) => {
            let addr = regs.rdi as *mut libc::c_void;
            let length = regs.rsi as usize;
            let prot = regs.rdx as i32;
            let flags = regs.r10 as i32;
            let fd = regs.r8 as i32;
            let offset = regs.r9 as libc::off_t;
            match handler.mmap(&proc, addr, length, prot, flags, fd, offset) {
                Ok(res) => Some(res as i64),
                Err(err) => Some(-(err as i32) as i64),
            }
        }
        Some(Sysno::munmap) => {
            let addr = regs.rdi as *mut libc::c_void;
            let length = regs.rsi as usize;
            match handler.munmap(&proc, addr, length) {
                Ok(res) => Some(res as i64),
                Err(err) => Some(-(err as i32) as i64),
            }
        }
        Some(Sysno::brk) => {
            let addr = regs.rdi as *mut libc::c_void;
            match handler.brk(&proc, addr) {
                Ok(res) => Some(res as i64),
                Err(err) => Some(-(err as i32) as i64),
            }
        }
        Some(Sysno::clock_gettime) => {
            let clk_id = regs.rdi as libc::clockid_t;
            match handler.clock_gettime(&proc, clk_id) {
                Ok(res) => Some(res as i64),
                Err(err) => Some(-(err as i32) as i64),
            }
        }
        Some(Sysno::openat) => {
            let dirfd = regs.rdi as i32;
            let addr = regs.rsi as usize;
            let flags = regs.rdx as i32;
            let mode = regs.r10 as libc::mode_t;
            let pathname = read_string(pid, addr);
            match handler.openat(&proc, dirfd, &pathname, flags, mode) {
                Ok(res) => Some(res as i64),
                Err(err) => Some(-(err as i32) as i64),
            }
        }
        Some(Sysno::newfstatat) => {
            let dirfd = regs.rdi as i32;
            let addr = regs.rsi as usize;
            let flags = regs.r10 as i32;
            let pathname = read_string(pid, addr);
            match handler.newfstatat(&proc, dirfd, &pathname, flags) {
                Ok(res) => Some(res as i64),
                Err(err) => Some(-(err as i32) as i64),
            }
        }
        Some(Sysno::exit) => {
            let status = regs.rdi as i32;
            let _ = handler.exit(&proc, status);
            Some(0)
        }
        Some(Sysno::exit_group) => {
            let status = regs.rdi as i32;
            let _ = handler.exit_group(&proc, status);
            Some(0)
        }
        Some(Sysno::fork) => {
            let _ = handler.fork(&proc);
            None
        }
        Some(Sysno::vfork) => {
            let _ = handler.vfork(&proc);
            None
        }
        Some(Sysno::clone) => {
            let flags = regs.rdi as i32;
            let _ = handler.clone(&proc, flags);
            None
        }
        Some(Sysno::clone3) => {
            let _ = handler.clone(&proc, 0);
            None
        }
        Some(Sysno::socket) => {
            let domain = regs.rdi as i32;
            let ty = regs.rsi as i32;
            let protocol = regs.rdx as i32;
            match handler.socket(&proc, domain, ty, protocol) {
                Ok(res) => Some(res as i64),
                Err(err) => Some(-(err as i32) as i64),
            }
        }
        Some(Sysno::bind) => {
            let fd = regs.rdi as i32;
            let addr = regs.rsi as *const libc::sockaddr;
            let len = regs.rdx as libc::socklen_t;
            match handler.bind(&proc, fd, addr, len) {
                Ok(res) => Some(res as i64),
                Err(err) => Some(-(err as i32) as i64),
            }
        }
        Some(Sysno::listen) => {
            let fd = regs.rdi as i32;
            let backlog = regs.rsi as i32;
            match handler.listen(&proc, fd, backlog) {
                Ok(res) => Some(res as i64),
                Err(err) => Some(-(err as i32) as i64),
            }
        }
        Some(Sysno::accept) => {
            let fd = regs.rdi as i32;
            let addr = regs.rsi as *mut libc::sockaddr;
            let len = regs.rdx as *mut libc::socklen_t;
            match handler.accept(&proc, fd, addr, len) {
                Ok(res) => Some(res as i64),
                Err(err) => Some(-(err as i32) as i64),
            }
        }
        Some(Sysno::accept4) => {
            let fd = regs.rdi as i32;
            let addr = regs.rsi as *mut libc::sockaddr;
            let len = regs.rdx as *mut libc::socklen_t;
            let flags = regs.r10 as i32;
            match handler.accept4(&proc, fd, addr, len, flags) {
                Ok(res) => Some(res as i64),
                Err(err) => Some(-(err as i32) as i64),
            }
        }
        Some(Sysno::connect) => {
            let fd = regs.rdi as i32;
            let addr = regs.rsi as *const libc::sockaddr;
            let len = regs.rdx as libc::socklen_t;
            match handler.connect(&proc, fd, addr, len) {
                Ok(res) => Some(res as i64),
                Err(err) => Some(-(err as i32) as i64),
            }
        }
        Some(Sysno::setsockopt) => {
            let fd = regs.rdi as i32;
            let level = regs.rsi as i32;
            let optname = regs.rdx as i32;
            let optval = regs.r10 as *const libc::c_void;
            let optlen = regs.r8 as libc::socklen_t;
            match handler.setsockopt(&proc, fd, level, optname, optval, optlen) {
                Ok(res) => Some(res as i64),
                Err(err) => Some(-(err as i32) as i64),
            }
        }
        Some(Sysno::getsockname) => {
            let fd = regs.rdi as i32;
            let addr = regs.rsi as *mut libc::sockaddr;
            let len = regs.rdx as *mut libc::socklen_t;
            match handler.getsockname(&proc, fd, addr, len) {
                Ok(res) => Some(res as i64),
                Err(err) => Some(-(err as i32) as i64),
            }
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
