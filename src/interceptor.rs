use nix::sys::ptrace;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{execvp, fork, ForkResult, Pid};
use std::ffi::CString;
use crate::linux::{Linux, PollFd};
use syscalls::Sysno;
use crate::vdso;
use std::collections::HashMap;
use libc::c_int;
use std::sync::atomic::{AtomicBool, Ordering};

static SHUTDOWN: AtomicBool = AtomicBool::new(false);

extern "C" fn handle_sigterm(_: i32) {
    SHUTDOWN.store(true, Ordering::Relaxed);
}


struct ChildState<Fd> {
    in_syscall: bool,
    saved_result: i64,
    fd_map: HashMap<c_int, Fd>,
    next_fd: c_int,
    pending_child_handler: Option<Box<dyn Linux<Fd> + Send>>,
}

pub fn run_with_interceptor<Fd, L>(cmd: &str, args: &[&str], handler: L)
where
    Fd: Send + 'static + std::os::unix::io::AsRawFd,
    L: Linux<Fd> + Send + 'static,
{
    match unsafe { fork() } {
        Ok(ForkResult::Parent { child }) => {
            unsafe {
                let sig_action = nix::sys::signal::SigAction::new(
                    nix::sys::signal::SigHandler::Handler(handle_sigterm),
                    nix::sys::signal::SaFlags::empty(),
                    nix::sys::signal::SigSet::empty(),
                );
                let _ = nix::sys::signal::sigaction(nix::sys::signal::Signal::SIGTERM, &sig_action);
            }
            parent_loop(child, Box::new(handler));
        }
        Ok(ForkResult::Child) => {
            ptrace::traceme().expect("Failed to traceme");
            
            // Disable ASLR for the child process to improve determinism
            unsafe {
                let current = libc::personality(0xffffffff);
                if current != -1 {
                    libc::personality(current as u64 | libc::ADDR_NO_RANDOMIZE as u64);
                }
            }

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
        if SHUTDOWN.load(Ordering::Relaxed) {
            // Kill and reap the child
            let _ = nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGKILL);
            let _ = waitpid(pid, None);
             return WaitStatus::Signaled(pid, nix::sys::signal::Signal::SIGKILL, false);
        }

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

fn parent_loop<Fd>(initial_child: Pid, mut handler: Box<dyn Linux<Fd> + Send>)
where
    Fd: Send + 'static + std::os::unix::io::AsRawFd,
{
    let mut fd_map = HashMap::new();
    let (stdin, stdout, stderr) = handler.default_fds();
    fd_map.insert(0, stdin);
    fd_map.insert(1, stdout);
    fd_map.insert(2, stderr);
    tracee_loop(initial_child, handler, fd_map, 10000, true);
}

fn tracee_loop<Fd>(pid: Pid, mut handler: Box<dyn Linux<Fd> + Send>, fd_map: HashMap<c_int, Fd>, next_fd: c_int, is_initial: bool)
where
    Fd: Send + 'static + std::os::unix::io::AsRawFd,
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
        for _ in 0..1000 {
            match ptrace::attach(pid) {
                Ok(_) => {
                    attached = true;
                    break;
                }
                Err(nix::Error::ESRCH) | Err(nix::Error::EPERM) => {
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
                Ok(WaitStatus::PtraceSyscall(_)) | Ok(WaitStatus::PtraceEvent(_, _, _)) => {
                    // If we get other ptrace stops, just keep going until we get the SIGSTOP
                    let _ = ptrace::syscall(pid, None);
                }
                Ok(status) => {
                    if let WaitStatus::Exited(_, _) | WaitStatus::Signaled(_, _, _) = status {
                        return;
                    }
                    // For other signals, we might need to pass them through if we were the tracer,
                    // but here we are still trying to become the tracer.
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
        fd_map,
        next_fd,
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
                    
                    // The new child is automatically traced by us. 
                    // We must wait for it to stop before we can detach.
                    let _ = waitpid(new_pid, None);

                    // Handover: detach from this thread so another can attach.
                    let _ = ptrace::detach(new_pid, Some(nix::sys::signal::Signal::SIGSTOP));

                    let mut child_handler = state.pending_child_handler.take().expect("No pending handler for fork");
                    // After fork, child inherits all file descriptors from parent
                    // Duplicate all parent fds for the child
                    let mut child_fd_map = HashMap::new();
                    for (guest_fd, parent_fd) in &state.fd_map {
                        let child_fd = child_handler.dup_fd(parent_fd);
                        child_fd_map.insert(*guest_fd, child_fd);
                    }
                    let child_next_fd = state.next_fd;
                    std::thread::spawn(move || {
                        tracee_loop(new_pid, child_handler, child_fd_map, child_next_fd, false);
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
    Fd: std::os::unix::io::AsRawFd,
{
    let proc = crate::captured::CapturedProcess::new(pid);
    let regs = proc.get_regs().expect("Failed to get regs");
    let syscall_no = regs.orig_rax;
    let sysno = Sysno::new(syscall_no as usize);

    match sysno {
        Some(Sysno::read) => {
            if let Some(fd) = get_fd_mut(state, regs.rdi as i32) {
                let addr = regs.rsi as usize;
                let count = regs.rdx as usize;
                match handler.read(&proc, fd, count) {
                    Ok(buf) => {
                        write_bytes(pid, addr, &buf);
                        Some(buf.len() as i64)
                    }
                    Err(err) => Some(-(err as i32) as i64),
                }
            } else {
                Some(-libc::EBADF as i64)
            }
        }
        Some(Sysno::write) => {
            if let Some(fd) = get_fd_mut(state, regs.rdi as i32) {
                let addr = regs.rsi as usize;
                let count = regs.rdx as usize;
                let buf = proc.read_memory(addr, count);
                match handler.write(&proc, fd, &buf) {
                    Ok(res) => Some(res as i64),
                    Err(err) => Some(-(err as i32) as i64),
                }
            } else {
                Some(-libc::EBADF as i64)
            }
        }
        Some(Sysno::open) => {
            let addr = regs.rdi as usize;
            let flags = regs.rsi as i32;
            let mode = regs.rdx as libc::mode_t;
            let pathname = read_string(pid, addr);
            match handler.open(&proc, &pathname, flags, mode) {
                Ok(res) => Some(register_fd(state, res) as i64),
                Err(err) => Some(-(err as i32) as i64),
            }
        }
        Some(Sysno::close) => {
            let guest_fd = regs.rdi as i32;
            if let Some(fd) = take_fd(state, guest_fd) {
                match handler.close(&proc, fd) {
                    Ok(res) => Some(res as i64),
                    Err(err) => Some(-(err as i32) as i64),
                }
            } else {
                Some(-libc::EBADF as i64)
            }
        }
        Some(Sysno::fstat) => {
            if let Some(fd) = get_fd_mut(state, regs.rdi as i32) {
                match handler.fstat(&proc, fd) {
                    Ok(res) => Some(res as i64),
                    Err(err) => Some(-(err as i32) as i64),
                }
            } else {
                Some(-libc::EBADF as i64)
            }
        }
        Some(Sysno::mmap) => {
            let addr = regs.rdi as *mut libc::c_void;
            let length = regs.rsi as usize;
            let prot = regs.rdx as i32;
            let flags = regs.r10 as i32;
            let fd_opt = get_fd_mut(state, regs.r8 as i32);
            let offset = regs.r9 as libc::off_t;
            match handler.mmap(&proc, addr, length, prot, flags, fd_opt, offset) {
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
            let dirfd_opt = get_fd_mut(state, regs.rdi as i32);
            let addr = regs.rsi as usize;
            let flags = regs.rdx as i32;
            let mode = regs.r10 as libc::mode_t;
            let pathname = read_string(pid, addr);
            match handler.openat(&proc, dirfd_opt, &pathname, flags, mode) {
                Ok(res) => Some(register_fd(state, res) as i64),
                Err(err) => Some(-(err as i32) as i64),
            }
        }
        Some(Sysno::newfstatat) => {
            let dirfd_opt = get_fd_mut(state, regs.rdi as i32);
            let addr = regs.rsi as usize;
            let flags = regs.r10 as i32;
            let pathname = read_string(pid, addr);
            match handler.newfstatat(&proc, dirfd_opt, &pathname, flags) {
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
                Ok(res) => Some(register_fd(state, res) as i64),
                Err(err) => Some(-(err as i32) as i64),
            }
        }
        Some(Sysno::bind) => {
            if let Some(fd) = get_fd_mut(state, regs.rdi as i32) {
                let addr = regs.rsi as *const libc::sockaddr;
                let len = regs.rdx as libc::socklen_t;
                match handler.bind(&proc, fd, addr, len) {
                    Ok(res) => Some(res as i64),
                    Err(err) => Some(-(err as i32) as i64),
                }
            } else {
                Some(-libc::EBADF as i64)
            }
        }
        Some(Sysno::listen) => {
            if let Some(fd) = get_fd_mut(state, regs.rdi as i32) {
                let backlog = regs.rsi as i32;
                match handler.listen(&proc, fd, backlog) {
                    Ok(res) => Some(res as i64),
                    Err(err) => Some(-(err as i32) as i64),
                }
            } else {
                Some(-libc::EBADF as i64)
            }
        }
        Some(Sysno::accept) => {
            if let Some(fd) = get_fd_mut(state, regs.rdi as i32) {
                let addr = regs.rsi as *mut libc::sockaddr;
                let len = regs.rdx as *mut libc::socklen_t;
                match handler.accept(&proc, fd, addr, len) {
                    Ok(res) => Some(register_fd(state, res) as i64),
                    Err(err) => Some(-(err as i32) as i64),
                }
            } else {
                Some(-libc::EBADF as i64)
            }
        }
        Some(Sysno::accept4) => {
            if let Some(fd) = get_fd_mut(state, regs.rdi as i32) {
                let addr = regs.rsi as *mut libc::sockaddr;
                let len = regs.rdx as *mut libc::socklen_t;
                let flags = regs.r10 as i32;
                match handler.accept4(&proc, fd, addr, len, flags) {
                    Ok(res) => Some(register_fd(state, res) as i64),
                    Err(err) => Some(-(err as i32) as i64),
                }
            } else {
                Some(-libc::EBADF as i64)
            }
        }
        Some(Sysno::connect) => {
            if let Some(fd) = get_fd_mut(state, regs.rdi as i32) {
                let addr = regs.rsi as *const libc::sockaddr;
                let len = regs.rdx as libc::socklen_t;
                match handler.connect(&proc, fd, addr, len) {
                    Ok(res) => Some(res as i64),
                    Err(err) => Some(-(err as i32) as i64),
                }
            } else {
                Some(-libc::EBADF as i64)
            }
        }
        Some(Sysno::setsockopt) => {
            if let Some(fd) = get_fd_mut(state, regs.rdi as i32) {
                let level = regs.rsi as i32;
                let optname = regs.rdx as i32;
                let optval = regs.r10 as *const libc::c_void;
                let optlen = regs.r8 as libc::socklen_t;
                match handler.setsockopt(&proc, fd, level, optname, optval, optlen) {
                    Ok(res) => Some(res as i64),
                    Err(err) => Some(-(err as i32) as i64),
                }
            } else {
                Some(-libc::EBADF as i64)
            }
        }
        Some(Sysno::getsockname) => {
            if let Some(fd) = get_fd_mut(state, regs.rdi as i32) {
                let addr = regs.rsi as *mut libc::sockaddr;
                let len = regs.rdx as *mut libc::socklen_t;
                match handler.getsockname(&proc, fd, addr, len) {
                    Ok(res) => Some(res as i64),
                    Err(err) => Some(-(err as i32) as i64),
                }
            } else {
                Some(-libc::EBADF as i64)
            }
        }
        Some(Sysno::pread64) => {
            if let Some(fd) = get_fd_mut(state, regs.rdi as i32) {
                let addr = regs.rsi as usize;
                let count = regs.rdx as usize;
                let offset = regs.r10 as libc::off_t;
                if let Ok(buf) = handler.pread(&proc, fd, count, offset) {
                     write_bytes(pid, addr, &buf);
                     Some(buf.len() as i64)
                } else {
                     Some(-1)
                }
            } else {
                Some(-libc::EBADF as i64)
            }
        }
        Some(Sysno::poll) => {
            let fds_addr = regs.rdi as usize;
            let nfds = regs.rsi as usize;
            let timeout = regs.rdx as i32;
            let (mut fds, guest_fds) = read_pollfds(pid, fds_addr, nfds, state);
            
            // Patch guest memory with Host FDs so the syscall works
            write_fds_to_guest(pid, fds_addr, &fds);
            
            let result = handler.poll(&proc, &mut fds, timeout);
            
            // Always restore guest FDs and fds back to the map
            match result {
                Ok(res) => {
                    // Write back revents
                    write_pollfds_revents(pid, fds_addr, &fds);
                    // Restore original Guest FDs
                    restore_guest_fds(pid, fds_addr, &guest_fds);
                    // Restore fds back to the map
                    restore_pollfds(state, &guest_fds, fds);
                    Some(res as i64)
                },
                Err(err) => {
                    // Restore original Guest FDs even on error
                    restore_guest_fds(pid, fds_addr, &guest_fds);
                    // Restore fds back to the map
                    restore_pollfds(state, &guest_fds, fds);
                    Some(-(err as i32) as i64)
                },
            }
        }
        Some(Sysno::sendto) => {
            if let Some(fd) = get_fd_mut(state, regs.rdi as i32) {
                let buf_addr = regs.rsi as usize;
                let len = regs.rdx as usize;
                let flags = regs.r10 as i32;
                let dest_addr = regs.r8 as *const libc::sockaddr;
                let addrlen = regs.r9 as libc::socklen_t;
                let buf = proc.read_memory(buf_addr, len);
                match handler.sendto(&proc, fd, &buf, flags, dest_addr, addrlen) {
                    Ok(res) => Some(res as i64),
                    Err(err) => Some(-(err as i32) as i64),
                }
            } else {
                Some(-libc::EBADF as i64)
            }
        }
        Some(Sysno::recvfrom) => {
            if let Some(fd) = get_fd_mut(state, regs.rdi as i32) {
                let buf_addr = regs.rsi as usize;
                let len = regs.rdx as usize;
                let flags = regs.r10 as i32;
                let src_addr = regs.r8 as *mut libc::sockaddr;
                let addrlen = regs.r9 as *mut libc::socklen_t;
                match handler.recvfrom(&proc, fd, len, flags, src_addr, addrlen) {
                    Ok(buf) => {
                        write_bytes(pid, buf_addr, &buf);
                        Some(buf.len() as i64)
                    },
                    Err(err) => Some(-(err as i32) as i64),
                }
            } else {
                Some(-libc::EBADF as i64)
            }
        }
        Some(Sysno::fcntl) => {
            if let Some(fd) = get_fd_mut(state, regs.rdi as i32) {
                let cmd = regs.rsi as i32;
                let arg = regs.rdx as libc::c_ulong;
                match handler.fcntl(&proc, fd, cmd, arg) {
                    Ok(res) => Some(res as i64),
                    Err(err) => Some(-(err as i32) as i64),
                }
            } else {
                Some(-libc::EBADF as i64)
            }
        }
        Some(Sysno::lseek) => {
            if let Some(fd) = get_fd_mut(state, regs.rdi as i32) {
                let offset = regs.rsi as libc::off_t;
                let whence = regs.rdx as i32;
                match handler.lseek(&proc, fd, offset, whence) {
                    Ok(res) => Some(res as i64),
                    Err(err) => Some(-(err as i32) as i64),
                }
            } else {
                Some(-libc::EBADF as i64)
            }
        }
        Some(Sysno::unlink) => {
            let addr = regs.rdi as usize;
            let pathname = read_string(pid, addr);
            match handler.unlink(&proc, &pathname) {
                Ok(res) => Some(res as i64),
                Err(err) => Some(-(err as i32) as i64),
            }
        }
        Some(Sysno::pwrite64) => {
            if let Some(fd) = get_fd_mut(state, regs.rdi as i32) {
                let addr = regs.rsi as usize;
                let count = regs.rdx as usize;
                let offset = regs.r10 as libc::off_t;
                let buf = proc.read_memory(addr, count);
                match handler.pwrite(&proc, fd, &buf, offset) {
                    Ok(res) => Some(res as i64),
                    Err(err) => Some(-(err as i32) as i64),
                }
            } else {
                Some(-libc::EBADF as i64)
            }
        }
        Some(Sysno::fsync) => {
            if let Some(fd) = get_fd_mut(state, regs.rdi as i32) {
                match handler.fsync(&proc, fd) {
                    Ok(res) => Some(res as i64),
                    Err(err) => Some(-(err as i32) as i64),
                }
            } else {
                Some(-libc::EBADF as i64)
            }
        }
        Some(Sysno::fdatasync) => {
            if let Some(fd) = get_fd_mut(state, regs.rdi as i32) {
                match handler.fdatasync(&proc, fd) {
                    Ok(res) => Some(res as i64),
                    Err(err) => Some(-(err as i32) as i64),
                }
            } else {
                Some(-libc::EBADF as i64)
            }
        }
        Some(Sysno::getcwd) => {
            let buf_addr = regs.rdi as usize;
            let size = regs.rsi as usize;
            match handler.getcwd(&proc, size) {
                Ok(buf) => {
                     if buf.len() > 0 {
                         write_bytes(pid, buf_addr, &buf);
                         Some(buf.len() as i64) 
                     } else {
                         Some(0)
                     }
                },
                Err(err) => Some(-(err as i32) as i64),
            }
        }
        Some(Sysno::getpid) => {
            match handler.getpid(&proc) {
                Ok(res) => Some(res as i64),
                Err(err) => Some(-(err as i32) as i64),
            }
        }
        Some(Sysno::getuid) => {
            match handler.getuid(&proc) {
                Ok(res) => Some(res as i64),
                Err(err) => Some(-(err as i32) as i64),
            }
        }
        Some(Sysno::geteuid) => {
            match handler.geteuid(&proc) {
                Ok(res) => Some(res as i64),
                Err(err) => Some(-(err as i32) as i64),
            }
        }
        Some(Sysno::getgid) => {
            match handler.getgid(&proc) {
                Ok(res) => Some(res as i64),
                Err(err) => Some(-(err as i32) as i64),
            }
        }
        Some(Sysno::getegid) => {
            match handler.getegid(&proc) {
                Ok(res) => Some(res as i64),
                Err(err) => Some(-(err as i32) as i64),
            }
        }
        Some(Sysno::getppid) => {
            match handler.getppid(&proc) {
                Ok(res) => Some(res as i64),
                Err(err) => Some(-(err as i32) as i64),
            }
        }
        Some(Sysno::getpgrp) => {
            match handler.getpgrp(&proc) {
                Ok(res) => Some(res as i64),
                Err(err) => Some(-(err as i32) as i64),
            }
        }
        Some(Sysno::gettimeofday) => {
            match handler.gettimeofday(&proc) {
                Ok(res) => Some(res as i64),
                Err(err) => Some(-(err as i32) as i64),
            }
        }
        Some(Sysno::uname) => {
            match handler.uname(&proc) {
                Ok(res) => Some(res as i64),
                Err(err) => Some(-(err as i32) as i64),
            }
        }
        Some(Sysno::sysinfo) => {
            match handler.sysinfo(&proc) {
                Ok(res) => Some(res as i64),
                Err(err) => Some(-(err as i32) as i64),
            }
        }
        Some(Sysno::times) => {
            match handler.times(&proc) {
                Ok(res) => Some(res as i64),
                Err(err) => Some(-(err as i32) as i64),
            }
        }
        Some(Sysno::writev) => {
            if let Some(fd) = get_fd_mut(state, regs.rdi as i32) {
                let iov = regs.rsi as u64;
                let iovcnt = regs.rdx as i32;
                match handler.writev(&proc, fd, iov, iovcnt) {
                    Ok(res) => Some(res as i64),
                    Err(err) => Some(-(err as i32) as i64),
                }
            } else {
                Some(-libc::EBADF as i64)
            }
        }
        Some(Sysno::rt_sigprocmask) => {
            // Let it fall through to the kernel.
            // We handle it here just to avoid the "unknown system call" message.
            None
        }
        Some(Sysno::rt_sigaction) => {
            // Let it fall through to the kernel.
            None
        }
        Some(Sysno::getrandom) => {
            let buf_addr = regs.rdi as usize;
            let count = regs.rsi as usize;
            let flags = regs.rdx as i32;
            let mut buf = vec![0u8; count];
            match handler.getrandom(&proc, &mut buf, flags) {
                Ok(res) => {
                    write_bytes(pid, buf_addr, &buf[..res]);
                    Some(res as i64)
                }
                Err(err) => Some(-(err as i32) as i64),
            }
        }
        Some(other_system_call) => {
            if handler.is_verbose() {
                eprintln!("Child {} got an unknown system call: {}", pid, other_system_call);
            }
            None
        }
        _ => None,
    }
}

fn get_fd_mut<Fd>(state: &mut ChildState<Fd>, guest_fd: c_int) -> Option<&mut Fd> {
    if guest_fd < 0 {
        return None;
    }
    state.fd_map.get_mut(&guest_fd)
}

fn take_fd<Fd>(state: &mut ChildState<Fd>, guest_fd: c_int) -> Option<Fd> {
    state.fd_map.remove(&guest_fd)
}

fn register_fd<Fd>(state: &mut ChildState<Fd>, fd: Fd) -> c_int {
    let guest_fd = state.next_fd;
    state.next_fd += 1;
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

fn write_bytes(pid: Pid, addr: usize, bytes: &[u8]) {
    let mut current_addr = addr;
    let mut i = 0;
    while i < bytes.len() {
        let word_addr = (current_addr & !7) as *mut libc::c_void;
        let offset = current_addr & 7;
        
        if let Ok(orig_word) = ptrace::read(pid, word_addr) {
            let mut word_bytes = orig_word.to_ne_bytes();
            let mut j = 0;
            while j < 8 - offset && i < bytes.len() {
                word_bytes[offset + j] = bytes[i];
                i += 1;
                j += 1;
            }
            let new_word = i64::from_ne_bytes(word_bytes);
            ptrace::write(pid, word_addr, new_word).unwrap_or(());
            current_addr += j;
        } else {
             break;
        }
    }
}

fn read_pollfds<Fd>(pid: Pid, addr: usize, nfds: usize, state: &mut ChildState<Fd>) -> (Vec<PollFd<Fd>>, Vec<i32>)
where
    Fd: std::os::unix::io::AsRawFd,
{
     let mut fds = Vec::with_capacity(nfds);
     let mut guest_fds = Vec::with_capacity(nfds);
     let pollfd_size = std::mem::size_of::<libc::pollfd>();
     for i in 0..nfds {
         let item_addr = addr + i * pollfd_size;
         let word_addr = (item_addr & !7) as *mut libc::c_void;
         let offset = item_addr & 7;
         
         let fd_int;
         let events;
         let revents;

         if offset == 0 {
             if let Ok(word) = ptrace::read(pid, word_addr) {
                 let bytes = word.to_ne_bytes();
                 fd_int = i32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                 events = i16::from_ne_bytes([bytes[4], bytes[5]]);
                 revents = i16::from_ne_bytes([bytes[6], bytes[7]]);
             } else {
                 fd_int = -1;
                 events = 0;
                 revents = 0;
             }
         } else {
             // Fallback manual read... simplistic approach for now assuming alignment or simple read
             // We reuse the read_memory logic implicit here or just read word
             if let Ok(word) = ptrace::read(pid, item_addr as *mut libc::c_void) {
                 let bytes = word.to_ne_bytes();
                 fd_int = i32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                 events = i16::from_ne_bytes([bytes[4], bytes[5]]);
                 revents = i16::from_ne_bytes([bytes[6], bytes[7]]);
             } else {
                 fd_int = -1;
                 events = 0;
                 revents = 0;
             }
         }
         
         guest_fds.push(fd_int);
         // Temporarily remove the fd from the map (we'll restore it after poll)
         if let Some(fd) = state.fd_map.remove(&fd_int) {
             fds.push(PollFd { fd, events, revents });
         } else {
             // fd not in map, skip (might be -1 or invalid)
             // We need a placeholder - this is an error case, but let's handle it gracefully
             // For now, we'll panic since this shouldn't happen in normal operation
             if fd_int >= 0 {
                 panic!("Guest FD {} not found in map during poll", fd_int);
             }
             // For negative fds (like -1), we can't create a PollFd without a valid Fd
             // This is an edge case we'll need to handle
         }
     }
     (fds, guest_fds)
}

fn restore_pollfds<Fd>(state: &mut ChildState<Fd>, guest_fds: &[i32], fds: Vec<PollFd<Fd>>) {
    for (guest_fd, pollfd) in guest_fds.iter().zip(fds.into_iter()) {
        if *guest_fd >= 0 {
            state.fd_map.insert(*guest_fd, pollfd.fd);
        }
    }
}

fn write_pollfds_revents<Fd>(pid: Pid, addr: usize, fds: &[PollFd<Fd>]) {
    let pollfd_size = std::mem::size_of::<libc::pollfd>();
    for (i, fd) in fds.iter().enumerate() {
        let item_addr = addr + i * pollfd_size;
        // revents is at offset 6.
        let revents_addr = item_addr + 6;
        let revents_bytes = fd.revents.to_ne_bytes();
        write_bytes(pid, revents_addr, &revents_bytes);
    }
}

fn write_fds_to_guest<Fd>(pid: Pid, addr: usize, fds: &[PollFd<Fd>]) 
where Fd: std::os::unix::io::AsRawFd 
{
    let pollfd_size = std::mem::size_of::<libc::pollfd>();
    for (i, pollfd) in fds.iter().enumerate() {
        let item_addr = addr + i * pollfd_size;
        // fd is at offset 0.
        let fd_int = pollfd.fd.as_raw_fd();
        let fd_bytes = fd_int.to_ne_bytes();
        write_bytes(pid, item_addr, &fd_bytes);
    }
}

fn restore_guest_fds(pid: Pid, addr: usize, guest_fds: &[i32]) {
    let pollfd_size = std::mem::size_of::<libc::pollfd>();
    for (i, &guest_fd) in guest_fds.iter().enumerate() {
        let item_addr = addr + i * pollfd_size;
        // fd is at offset 0.
        let fd_bytes = guest_fd.to_ne_bytes();
        write_bytes(pid, item_addr, &fd_bytes);
    }
}
