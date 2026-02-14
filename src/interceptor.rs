use nix::sys::ptrace;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{execvp, fork, ForkResult, Pid};
use std::ffi::CString;
use crate::linux::Linux;
use syscalls::Sysno;
use crate::vdso;
use std::collections::HashMap;
use libc::c_int;


struct ChildState<Fd> {
    in_syscall: bool,
    saved_result: i64,
    fd_map: HashMap<c_int, Fd>,
    pending_child_handler: Option<Box<dyn Linux<Fd> + Send>>,
}

pub fn run_with_interceptor<Fd, L>(cmd: &str, args: &[&str], handler: L)
where
    Fd: Clone + Copy + std::fmt::Debug + Send + 'static,
    L: Linux<Fd> + Send + 'static,
{
    match unsafe { fork() } {
        Ok(ForkResult::Parent { child }) => {
            parent_loop(child, Box::new(handler));
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

fn wait_pid_with_timeout(pid: Pid) -> WaitStatus {
    let start = std::time::Instant::now();
    loop {
        match waitpid(pid, Some(nix::sys::wait::WaitPidFlag::WNOHANG)).expect("Wait failed") {
            WaitStatus::StillAlive => {
                if start.elapsed().as_secs() >= 5 {
                    panic!("Process {} timed out", pid);
                }
                std::thread::yield_now();
                std::thread::sleep(std::time::Duration::from_micros(100));
            }
            other => return other,
        }
    }
}

fn parent_loop<Fd>(initial_child: Pid, handler: Box<dyn Linux<Fd> + Send>)
where
    Fd: Clone + Copy + std::fmt::Debug + Send + 'static,
{
    tracee_loop(initial_child, handler, true);
}

fn tracee_loop<Fd>(pid: Pid, mut handler: Box<dyn Linux<Fd> + Send>, is_initial: bool)
where
    Fd: Clone + Copy + std::fmt::Debug + Send + 'static,
{
    if is_initial {
        // Initial wait for exec stop
        waitpid(pid, None).expect("Initial wait failed");
        
        // Disable vDSO before we start tracing syscalls
        let regs = ptrace::getregs(pid).expect("Failed to get regs for vDSO disable");
        vdso::disable_vdso(pid, regs.rsp);
    } else {
        // Thread handover: the parent thread already called detach(SIGSTOP).
        // It might take a moment for the child to stop and be ready for attachment.
        let mut attached = false;
        for _ in 0..100 {
            match ptrace::attach(pid) {
                Ok(_) => {
                    attached = true;
                    break;
                }
                Err(nix::Error::ESRCH) => {
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                Err(e) => {
                    eprintln!("[{}] Failed to attach: {}", pid, e);
                    return;
                }
            }
        }
        if !attached {
            return;
        }
        
        // Wait for the SIGSTOP from attach
        loop {
            match waitpid(pid, None) {
                Ok(WaitStatus::Stopped(_, nix::sys::signal::Signal::SIGSTOP)) => break,
                Ok(status) => {
                    if let WaitStatus::Exited(_, _) | WaitStatus::Signaled(_, _, _) = status {
                        return;
                    }
                    let _ = ptrace::syscall(pid, None);
                }
                Err(_) => return,
            }
        }
    }

    let options = ptrace::Options::PTRACE_O_TRACESYSGOOD |
                  ptrace::Options::PTRACE_O_TRACEFORK |
                  ptrace::Options::PTRACE_O_TRACEVFORK |
                  ptrace::Options::PTRACE_O_TRACECLONE |
                  ptrace::Options::PTRACE_O_TRACEEXEC;
    if ptrace::setoptions(pid, options).is_err() {
        return;
    }

    let mut state = ChildState {
        in_syscall: false,
        saved_result: 0,
        fd_map: HashMap::new(),
        pending_child_handler: None,
    };

    if ptrace::syscall(pid, None).is_err() {
        return;
    }

    loop {
        let status = wait_pid_with_timeout(pid);
        match status {
            WaitStatus::PtraceSyscall(_) => {
                if !state.in_syscall {
                    // Syscall Entry
                    if let Some(res) = handle_syscall_entry(pid, handler.as_mut(), &mut state) {
                        // The syscall was already executed inside handle_syscall_entry
                        // We are now at the exit stop (if still alive).
                        if let Ok(mut regs) = ptrace::getregs(pid) {
                            regs.rax = res as u64;
                            let _ = ptrace::setregs(pid, regs);
                            state.in_syscall = false;
                        } else {
                            break;
                        }
                    } else {
                        state.saved_result = -123456; // Sentinel for "did not replace"
                        state.in_syscall = true;
                    }
                } else {
                    // Syscall Exit
                    if state.saved_result != -123456 {
                        if let Ok(mut regs) = ptrace::getregs(pid) {
                            regs.rax = state.saved_result as u64;
                            let _ = ptrace::setregs(pid, regs);
                        } else {
                            break;
                        }
                    }
                    state.in_syscall = false;
                }
                let _ = ptrace::syscall(pid, None);
            }
            WaitStatus::PtraceEvent(_, _, event) => {
                if event == ptrace::Event::PTRACE_EVENT_FORK as i32 || 
                   event == ptrace::Event::PTRACE_EVENT_VFORK as i32 || 
                   event == ptrace::Event::PTRACE_EVENT_CLONE as i32 {
                    let new_pid = ptrace::getevent(pid).expect("Failed to get event msg");
                    let new_pid = Pid::from_raw(new_pid as i32);
                    
                    // Handover: detach from this thread so another can attach.
                    let _ = ptrace::detach(new_pid, Some(nix::sys::signal::Signal::SIGSTOP));

                    let child_handler = state.pending_child_handler.take().expect("No pending handler for fork");
                    std::thread::spawn(move || {
                        tracee_loop(new_pid, child_handler, false);
                    });
                } else if event == ptrace::Event::PTRACE_EVENT_EXEC as i32 {
                    if let Ok(regs) = ptrace::getregs(pid) {
                        vdso::disable_vdso(pid, regs.rsp);
                    }
                }
                let _ = ptrace::syscall(pid, None);
            }
            WaitStatus::Exited(_, status) => {
                println!("Child {} exited with status {}", pid, status);
                break;
            }
            WaitStatus::Signaled(_, sig, _) => {
                println!("Child {} signaled with {}", pid, sig);
                break;
            }
            _other => {
                let _ = ptrace::syscall(pid, None);
            }
        }
    }
}


fn handle_syscall_entry<Fd>(pid: Pid, handler: &mut dyn Linux<Fd>, state: &mut ChildState<Fd>) -> Option<i64>
where
    Fd: Clone + Copy + std::fmt::Debug,
{
    let proc = crate::captured::CapturedProcess::new(pid);
    let regs = proc.get_regs().expect("Failed to get regs");
    let syscall_no = regs.orig_rax;
    let sysno = Sysno::new(syscall_no as usize);

    match sysno {
        Some(Sysno::read) => {
            let fd = get_fd(state, handler, regs.rdi as i32);
            let count = regs.rdx as usize;
            match handler.read(&proc, fd, count) {
                Ok(buf) => Some(buf.len() as i64),
                Err(err) => Some(-(err as i32) as i64),
            }
        }
        Some(Sysno::write) => {
            let fd = get_fd(state, handler, regs.rdi as i32);
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
                Ok(res) => Some(register_fd(state, handler, res) as i64),
                Err(err) => Some(-(err as i32) as i64),
            }
        }
        Some(Sysno::close) => {
            let guest_fd = regs.rdi as i32;
            let fd = get_fd(state, handler, guest_fd);
            match handler.close(&proc, fd) {
                Ok(res) => {
                    state.fd_map.remove(&guest_fd);
                    Some(res as i64)
                },
                Err(err) => Some(-(err as i32) as i64),
            }
        }
        Some(Sysno::fstat) => {
            let fd = get_fd(state, handler, regs.rdi as i32);
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
            let fd = get_fd(state, handler, regs.r8 as i32);
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
            let dirfd = get_fd(state, handler, regs.rdi as i32);
            let addr = regs.rsi as usize;
            let flags = regs.rdx as i32;
            let mode = regs.r10 as libc::mode_t;
            let pathname = read_string(pid, addr);
            match handler.openat(&proc, dirfd, &pathname, flags, mode) {
                Ok(res) => Some(register_fd(state, handler, res) as i64),
                Err(err) => Some(-(err as i32) as i64),
            }
        }
        Some(Sysno::newfstatat) => {
            let dirfd = get_fd(state, handler, regs.rdi as i32);
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
            match handler.fork(&proc) {
                Ok((_, child_handler)) => {
                    state.pending_child_handler = Some(child_handler);
                    None
                }
                Err(err) => Some(-(err as i32) as i64),
            }
        }
        Some(Sysno::vfork) => {
            match handler.vfork(&proc) {
                Ok((_, child_handler)) => {
                    state.pending_child_handler = Some(child_handler);
                    None
                }
                Err(err) => Some(-(err as i32) as i64),
            }
        }
        Some(Sysno::clone) => {
            let flags = regs.rdi as i32;
            match handler.clone(&proc, flags) {
                Ok((_, child_handler)) => {
                    state.pending_child_handler = Some(child_handler);
                    None
                }
                Err(err) => Some(-(err as i32) as i64),
            }
        }
        Some(Sysno::clone3) => {
            match handler.clone(&proc, 0) {
                Ok((_, child_handler)) => {
                    state.pending_child_handler = Some(child_handler);
                    None
                }
                Err(err) => Some(-(err as i32) as i64),
            }
        }
        Some(Sysno::socket) => {
            let domain = regs.rdi as i32;
            let ty = regs.rsi as i32;
            let protocol = regs.rdx as i32;
            match handler.socket(&proc, domain, ty, protocol) {
                Ok(res) => Some(register_fd(state, handler, res) as i64),
                Err(err) => Some(-(err as i32) as i64),
            }
        }
        Some(Sysno::bind) => {
            let fd = get_fd(state, handler, regs.rdi as i32);
            let addr = regs.rsi as *const libc::sockaddr;
            let len = regs.rdx as libc::socklen_t;
            match handler.bind(&proc, fd, addr, len) {
                Ok(res) => Some(res as i64),
                Err(err) => Some(-(err as i32) as i64),
            }
        }
        Some(Sysno::listen) => {
            let fd = get_fd(state, handler, regs.rdi as i32);
            let backlog = regs.rsi as i32;
            match handler.listen(&proc, fd, backlog) {
                Ok(res) => Some(res as i64),
                Err(err) => Some(-(err as i32) as i64),
            }
        }
        Some(Sysno::accept) => {
            let fd = get_fd(state, handler, regs.rdi as i32);
            let addr = regs.rsi as *mut libc::sockaddr;
            let len = regs.rdx as *mut libc::socklen_t;
            match handler.accept(&proc, fd, addr, len) {
                Ok(res) => Some(register_fd(state, handler, res) as i64),
                Err(err) => Some(-(err as i32) as i64),
            }
        }
        Some(Sysno::accept4) => {
            let fd = get_fd(state, handler, regs.rdi as i32);
            let addr = regs.rsi as *mut libc::sockaddr;
            let len = regs.rdx as *mut libc::socklen_t;
            let flags = regs.r10 as i32;
            match handler.accept4(&proc, fd, addr, len, flags) {
                Ok(res) => Some(register_fd(state, handler, res) as i64),
                Err(err) => Some(-(err as i32) as i64),
            }
        }
        Some(Sysno::connect) => {
            let fd = get_fd(state, handler, regs.rdi as i32);
            let addr = regs.rsi as *const libc::sockaddr;
            let len = regs.rdx as libc::socklen_t;
            match handler.connect(&proc, fd, addr, len) {
                Ok(res) => Some(res as i64),
                Err(err) => Some(-(err as i32) as i64),
            }
        }
        Some(Sysno::setsockopt) => {
            let fd = get_fd(state, handler, regs.rdi as i32);
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
            let fd = get_fd(state, handler, regs.rdi as i32);
            let addr = regs.rsi as *mut libc::sockaddr;
            let len = regs.rdx as *mut libc::socklen_t;
            match handler.getsockname(&proc, fd, addr, len) {
                Ok(res) => Some(res as i64),
                Err(err) => Some(-(err as i32) as i64),
            }
        }
        Some(other_system_call) => {
            eprintln!("Child {} got an unknown system call: {}", pid, other_system_call);
            None
        }
        _ => None,
    }
}

fn get_fd<Fd, L>(state: &mut ChildState<Fd>, handler: &L, guest_fd: c_int) -> Fd
where
    Fd: Clone + Copy + std::fmt::Debug,
    L: Linux<Fd> + ?Sized,
{
    *state.fd_map.entry(guest_fd).or_insert_with(|| handler.wrap_fd(guest_fd))
}

fn register_fd<Fd, L>(state: &mut ChildState<Fd>, handler: &L, fd: Fd) -> c_int
where
    Fd: Clone + Copy + std::fmt::Debug,
    L: Linux<Fd> + ?Sized,
{
    let guest_fd = handler.unwrap_fd(fd);
    state.fd_map.insert(guest_fd, fd);
    guest_fd
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
