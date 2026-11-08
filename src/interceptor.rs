use nix::sys::ptrace;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{execvp, fork, ForkResult, Pid};
use std::ffi::CString;
use crate::linux::{Linux, PollFd};
use syscalls::Sysno;
use crate::vdso;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use libc::c_int;
use std::sync::atomic::{AtomicBool, Ordering};

static SHUTDOWN: AtomicBool = AtomicBool::new(false);

extern "C" fn handle_sigterm(_: i32) {
    SHUTDOWN.store(true, Ordering::Relaxed);
}


struct ChildState<Fd> {
    in_syscall: bool,
    saved_result: i64,
    fd_map: Arc<Mutex<HashMap<c_int, Fd>>>,
    pending_child_handler: Option<Box<dyn Linux<Fd> + Send>>,
    pending_clone_files: bool,
    pending_parent_tidptr: Option<u64>,
    pending_child_tidptr: Option<u64>,
    exit_code: Option<i32>,
}

pub fn run_with_interceptor<Fd, L>(cmd: &str, args: &[&str], handler: L)
where
    Fd: Clone + Send + 'static + std::os::unix::io::AsRawFd,
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
            
            unsafe {
                if handler.is_deterministic() {
                    let current = libc::personality(0xffffffff);
                    if current != -1 {
                        libc::personality(current as u64 | libc::ADDR_NO_RANDOMIZE as u64);
                    }
                    let mut cpuset: libc::cpu_set_t = std::mem::zeroed();
                    libc::CPU_SET(0, &mut cpuset);
                    let _ = libc::sched_setaffinity(
                        0,
                        std::mem::size_of::<libc::cpu_set_t>(),
                        &cpuset,
                    );
                    libc::prctl(libc::PR_SET_TSC, libc::PR_TSC_SIGSEGV, 0, 0, 0);
                    // Enable CPUID faulting (ARCH_SET_CPUID = 0x1012) if supported by the CPU/kernel
                    let _ = libc::syscall(libc::SYS_arch_prctl, 0x1012, 0);
                }
            }

            let c_cmd = CString::new(cmd).unwrap();
            let mut c_args: Vec<CString> = Vec::new();
            c_args.push(c_cmd.clone());
            for arg in args {
                c_args.push(CString::new(*arg).unwrap());
            }
            
            let Err(err) = execvp(&c_cmd, &c_args);
            eprintln!("nodice: failed to execute '{}': {}", cmd, err);
            unsafe {
                libc::_exit(127);
            }
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
    Fd: Clone + Send + 'static + std::os::unix::io::AsRawFd,
{
    let mut fd_map = HashMap::new();
    let (stdin, stdout, stderr) = handler.default_fds();
    fd_map.insert(0, stdin);
    fd_map.insert(1, stdout);
    fd_map.insert(2, stderr);
    let child_threads: Arc<Mutex<Vec<std::thread::JoinHandle<()>>>> = Arc::new(Mutex::new(Vec::new()));
    let exit_code = tracee_loop(
        initial_child,
        handler,
        Arc::new(Mutex::new(fd_map)),
        true,
        child_threads.clone(),
    );
    loop {
        let handle_opt = child_threads.lock().unwrap().pop();
        if let Some(h) = handle_opt {
            let _ = h.join();
        } else {
            break;
        }
    }
    if let Some(code) = exit_code {
        if code != 0 {
            std::process::exit(code);
        }
    }
}

fn tracee_loop<Fd>(
    pid: Pid,
    mut handler: Box<dyn Linux<Fd> + Send>,
    fd_map: Arc<Mutex<HashMap<c_int, Fd>>>,
    is_initial: bool,
    child_threads: Arc<Mutex<Vec<std::thread::JoinHandle<()>>>>,
) -> Option<i32>
where
    Fd: Clone + Send + 'static + std::os::unix::io::AsRawFd,
{
    if is_initial {
        // Initial wait for exec stop
        match waitpid(pid, None).expect("Initial wait failed") {
            WaitStatus::Exited(_, code) => return Some(code),
            WaitStatus::Signaled(_, sig, _) => return Some(128 + sig as i32),
            _ => {}
        }

        // Disable vDSO before we start tracing syscalls
        let regs = match ptrace::getregs(pid) {
            Ok(r) => r,
            Err(_) => return Some(127),
        };
        vdso::disable_vdso(pid, regs.rsp);
        handler.on_exec(&crate::captured::CapturedProcess::new(pid), regs.rsp);
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
                    handler.on_exit(&crate::captured::CapturedProcess::new(pid));
                    return None;
                }
            }
        }
        if !attached {
            handler.on_exit(&crate::captured::CapturedProcess::new(pid));
            return None;
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
                        handler.on_exit(&crate::captured::CapturedProcess::new(pid));
                        return None;
                    }
                    // For other signals, we might need to pass them through if we were the tracer,
                    // but here we are still trying to become the tracer.
                    let _ = ptrace::syscall(pid, None);
                }
                Err(_) => {
                    handler.on_exit(&crate::captured::CapturedProcess::new(pid));
                    return None;
                }
            }
        }
    }

    let options = ptrace::Options::PTRACE_O_TRACESYSGOOD |
                  ptrace::Options::PTRACE_O_TRACEFORK |
                  ptrace::Options::PTRACE_O_TRACEVFORK |
                  ptrace::Options::PTRACE_O_TRACECLONE |
                  ptrace::Options::PTRACE_O_TRACEEXEC |
                  ptrace::Options::PTRACE_O_EXITKILL;
    if ptrace::setoptions(pid, options).is_err() {
        handler.on_exit(&crate::captured::CapturedProcess::new(pid));
        return None;
    }

    let mut state = ChildState {
        in_syscall: false,
        saved_result: -123456,
        fd_map,
        pending_child_handler: None,
        pending_clone_files: false,
        pending_parent_tidptr: None,
        pending_child_tidptr: None,
        exit_code: None,
    };

    if ptrace::syscall(pid, None).is_err() {
        handler.on_exit(&crate::captured::CapturedProcess::new(pid));
        return None;
    }

    loop {
        let status = wait_pid_with_timeout(pid);
        match status {
            WaitStatus::PtraceSyscall(_) => {
                if !state.in_syscall {
                    // Syscall Entry
                    state.saved_result = -123456;
                    if let Some(res) = handle_syscall_entry(pid, handler.as_mut(), &mut state) {
                        // The syscall was already executed inside handle_syscall_entry
                        // We are now at the exit stop (if still alive).
                        if let Ok(mut regs) = ptrace::getregs(pid) {
                            regs.rax = res as u64;
                            let _ = ptrace::setregs(pid, regs);
                            state.in_syscall = false;
                        } else {
                            let proc = crate::captured::CapturedProcess::new(pid);
                            handler.on_exit(&proc);
                            return if is_initial { state.exit_code } else { None };
                        }
                    } else {
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
                    state.saved_result = -123456;
                    state.pending_child_handler = None;
                    state.pending_parent_tidptr = None;
                    state.pending_child_tidptr = None;
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

                    let parent_proc = crate::captured::CapturedProcess::new(pid);
                    if let Some(det_pid) = handler.on_child_created(
                        &parent_proc,
                        new_pid,
                        state.pending_parent_tidptr.take(),
                        state.pending_child_tidptr.take(),
                    ) {
                        state.saved_result = det_pid;
                    }

                    // Handover: detach from this thread so another can attach.
                    let _ = ptrace::detach(new_pid, Some(nix::sys::signal::Signal::SIGSTOP));

                    let mut child_handler = state.pending_child_handler.take().expect("No pending handler for fork");
                    child_handler.on_start(new_pid);
                    let child_fd_map = if state.pending_clone_files {
                        state.fd_map.clone()
                    } else {
                        let parent_map = state.fd_map.lock().unwrap();
                        let mut new_map = HashMap::new();
                        for (guest_fd, parent_fd) in parent_map.iter() {
                            let child_fd = child_handler.dup_fd(parent_fd);
                            new_map.insert(*guest_fd, child_fd);
                        }
                        Arc::new(Mutex::new(new_map))
                    };
                    let threads_clone = child_threads.clone();
                    let handle = std::thread::spawn(move || {
                        let _ = tracee_loop(new_pid, child_handler, child_fd_map, false, threads_clone);
                    });
                    child_threads.lock().unwrap().push(handle);
                } else if event == ptrace::Event::PTRACE_EVENT_EXEC as i32 {
                    // Prune any file descriptors closed by the kernel due to O_CLOEXEC
                    let mut closed_fds = Vec::new();
                    {
                        let mut map = state.fd_map.lock().unwrap();
                        map.retain(|_, fd_obj| {
                            let raw = fd_obj.as_raw_fd();
                            let exists = std::fs::metadata(format!("/proc/{}/fd/{}", pid.as_raw(), raw)).is_ok();
                            if !exists {
                                closed_fds.push(fd_obj.clone());
                            }
                            exists
                        });
                    }
                    for fd_obj in closed_fds {
                        handler.on_fd_overwritten(fd_obj);
                    }
                    if let Ok(regs) = ptrace::getregs(pid) {
                        vdso::disable_vdso(pid, regs.rsp);
                        handler.on_exec(&crate::captured::CapturedProcess::new(pid), regs.rsp);
                    }
                }
                let _ = ptrace::syscall(pid, None);
            }
            WaitStatus::Exited(_, status) => {
                if handler.is_verbose() {
                    println!("Child {} exited with status {}", pid, status);
                }
                let proc = crate::captured::CapturedProcess::new(pid);
                handler.on_exit(&proc);
                let code = state.exit_code.unwrap_or(status);
                return if is_initial { Some(code) } else { None };
            }
            WaitStatus::Signaled(_, sig, _) => {
                if handler.is_verbose() {
                    println!("Child {} signaled with {}", pid, sig);
                }
                let proc = crate::captured::CapturedProcess::new(pid);
                handler.on_exit(&proc);
                return if is_initial { Some(128 + sig as i32) } else { None };
            }
            WaitStatus::Stopped(_, sig) => {
                if sig == nix::sys::signal::Signal::SIGSEGV {
                    let proc = crate::captured::CapturedProcess::new(pid);
                    if handler.emulate_rdtsc(&proc) {
                        let _ = ptrace::syscall(pid, None);
                        continue;
                    }
                }
                let forward_sig = if sig == nix::sys::signal::Signal::SIGTRAP || sig == nix::sys::signal::Signal::SIGSTOP {
                    None
                } else {
                    Some(sig)
                };
                let _ = ptrace::syscall(pid, forward_sig);
            }
            _other => {
                let _ = ptrace::syscall(pid, None);
            }
        }
    }
    None
}


fn handle_syscall_entry<Fd>(pid: Pid, handler: &mut dyn Linux<Fd>, state: &mut ChildState<Fd>) -> Option<i64>
where
    Fd: Clone + std::os::unix::io::AsRawFd,
{
    let proc = crate::captured::CapturedProcess::new(pid);
    let Ok(regs) = proc.get_regs() else {
        return None;
    };
    let syscall_no = regs.orig_rax;
    let sysno = Sysno::new(syscall_no as usize);

    match sysno {
        Some(Sysno::read) => {
            let guest_fd = regs.rdi as i32;
            if let Some(mut fd) = get_fd(state, guest_fd) {
                let addr = regs.rsi as usize;
                let count = regs.rdx as usize;
                let res = match handler.read(&proc, &mut fd, count) {
                    Ok(buf) => {
                        proc.write_memory(addr, &buf);
                        Some(buf.len() as i64)
                    }
                    Err(err) => Some(-(err as i32) as i64),
                };
                update_fd(state, guest_fd, fd);
                res
            } else {
                ebadf(&proc)
            }
        }
        Some(Sysno::write) => {
            if let Some(mut fd) = get_fd(state, regs.rdi as i32) {
                let addr = regs.rsi as usize;
                let count = regs.rdx as usize;
                let buf = proc.read_memory(addr, count);
                match handler.write(&proc, &mut fd, &buf) {
                    Ok(res) => Some(res as i64),
                    Err(err) => Some(-(err as i32) as i64),
                }
            } else {
                ebadf(&proc)
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
        Some(Sysno::creat) => {
            let addr = regs.rdi as usize;
            let mode = regs.rsi as libc::mode_t;
            let pathname = read_string(pid, addr);
            let flags = libc::O_CREAT | libc::O_WRONLY | libc::O_TRUNC;
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
                ebadf(&proc)
            }
        }
        Some(Sysno::dup) => {
            if let Some(old_fd) = get_fd(state, regs.rdi as i32) {
                match handler.dup(&proc, &old_fd) {
                    Ok(new_fd) => Some(register_fd(state, new_fd) as i64),
                    Err(err) => Some(-(err as i32) as i64),
                }
            } else {
                ebadf(&proc)
            }
        }
        Some(Sysno::dup2) => {
            let old_raw = regs.rdi as i32;
            let new_raw = regs.rsi as i32;
            if new_raw < 0 {
                return ebadf(&proc);
            }
            if let Some(old_fd) = get_fd(state, old_raw) {
                if old_raw == new_raw {
                    let _ = proc.skip_syscall();
                    Some(new_raw as i64)
                } else {
                    match handler.dup2(&proc, &old_fd, new_raw) {
                        Ok(new_fd) => {
                            let overwritten = state.fd_map.lock().unwrap().insert(new_raw, new_fd);
                            if let Some(old_entry) = overwritten {
                                handler.on_fd_overwritten(old_entry);
                            }
                            Some(new_raw as i64)
                        }
                        Err(err) => Some(-(err as i32) as i64),
                    }
                }
            } else {
                ebadf(&proc)
            }
        }
        Some(Sysno::dup3) => {
            let old_raw = regs.rdi as i32;
            let new_raw = regs.rsi as i32;
            let flags = regs.rdx as i32;
            if new_raw < 0 {
                return ebadf(&proc);
            }
            if let Some(old_fd) = get_fd(state, old_raw) {
                if old_raw == new_raw {
                    let _ = proc.skip_syscall();
                    Some(-libc::EINVAL as i64)
                } else {
                    match handler.dup3(&proc, &old_fd, new_raw, flags) {
                        Ok(new_fd) => {
                            let overwritten = state.fd_map.lock().unwrap().insert(new_raw, new_fd);
                            if let Some(old_entry) = overwritten {
                                handler.on_fd_overwritten(old_entry);
                            }
                            Some(new_raw as i64)
                        }
                        Err(err) => Some(-(err as i32) as i64),
                    }
                }
            } else {
                ebadf(&proc)
            }
        }
        Some(Sysno::pipe) | Some(Sysno::pipe2) => {
            let pipefd_addr = regs.rdi as usize;
            let res = if sysno == Some(Sysno::pipe) {
                proc.syscall(libc::SYS_pipe as u64, regs.rdi, 0, 0, 0, 0, 0)
            } else {
                proc.syscall(libc::SYS_pipe2 as u64, regs.rdi, regs.rsi, 0, 0, 0, 0)
            };
            match res {
                Ok(0) => {
                    let bytes = proc.read_memory(pipefd_addr, 8);
                    if bytes.len() == 8 {
                        let rfd = i32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                        let wfd = i32::from_ne_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
                        let r_entry = handler.wrap_raw_fd(&proc, rfd);
                        let w_entry = handler.wrap_raw_fd(&proc, wfd);
                        let mut map = state.fd_map.lock().unwrap();
                        map.insert(rfd, r_entry);
                        map.insert(wfd, w_entry);
                    }
                    Some(0)
                }
                Ok(other) => Some(other),
                Err(err) => Some(-(err as i32) as i64),
            }
        }
        Some(Sysno::socketpair) => {
            let sv_addr = regs.r10 as usize;
            match proc.syscall(libc::SYS_socketpair as u64, regs.rdi, regs.rsi, regs.rdx, regs.r10, 0, 0) {
                Ok(0) => {
                    let bytes = proc.read_memory(sv_addr, 8);
                    if bytes.len() == 8 {
                        let fd0 = i32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                        let fd1 = i32::from_ne_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
                        let entry0 = handler.wrap_raw_fd(&proc, fd0);
                        let entry1 = handler.wrap_raw_fd(&proc, fd1);
                        let mut map = state.fd_map.lock().unwrap();
                        map.insert(fd0, entry0);
                        map.insert(fd1, entry1);
                    }
                    Some(0)
                }
                Ok(other) => Some(other),
                Err(err) => Some(-(err as i32) as i64),
            }
        }
        Some(Sysno::memfd_create)
        | Some(Sysno::eventfd)
        | Some(Sysno::eventfd2)
        | Some(Sysno::epoll_create)
        | Some(Sysno::epoll_create1)
        | Some(Sysno::timerfd_create)
        | Some(Sysno::signalfd)
        | Some(Sysno::signalfd4)
        | Some(Sysno::inotify_init)
        | Some(Sysno::inotify_init1) => {
            match proc.syscall(syscall_no, regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9) {
                Ok(res) => {
                    if res >= 0 {
                        let fd_entry = handler.wrap_raw_fd(&proc, res as c_int);
                        register_fd(state, fd_entry);
                    }
                    Some(res)
                }
                Err(err) => Some(-(err as i32) as i64),
            }
        }
        Some(Sysno::stat) => {
            let addr = regs.rdi as usize;
            let pathname = read_string(pid, addr);
            match handler.stat(&proc, &pathname) {
                Ok(res) => Some(res as i64),
                Err(err) => Some(-(err as i32) as i64),
            }
        }
        Some(Sysno::lstat) => {
            let addr = regs.rdi as usize;
            let pathname = read_string(pid, addr);
            match handler.lstat(&proc, &pathname) {
                Ok(res) => Some(res as i64),
                Err(err) => Some(-(err as i32) as i64),
            }
        }
        Some(Sysno::fstat) => {
            if let Some(mut fd) = get_fd(state, regs.rdi as i32) {
                match handler.fstat(&proc, &mut fd) {
                    Ok(res) => Some(res as i64),
                    Err(err) => Some(-(err as i32) as i64),
                }
            } else {
                ebadf(&proc)
            }
        }
        Some(Sysno::mmap) => {
            let addr = regs.rdi as *mut libc::c_void;
            let length = regs.rsi as usize;
            let prot = regs.rdx as i32;
            let flags = regs.r10 as i32;
            let mut fd_opt = get_fd(state, regs.r8 as i32);
            let offset = regs.r9 as libc::off_t;
            match handler.mmap(&proc, addr, length, prot, flags, fd_opt.as_mut(), offset) {
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
            let raw_dirfd = regs.rdi as i32;
            let addr = regs.rsi as usize;
            let flags = regs.rdx as i32;
            let mode = regs.r10 as libc::mode_t;
            let pathname = read_string(pid, addr);
            let mut dirfd_opt = get_fd(state, raw_dirfd);
            if raw_dirfd != libc::AT_FDCWD && !pathname.starts_with('/') && dirfd_opt.is_none() {
                return ebadf(&proc);
            }
            match handler.openat(&proc, dirfd_opt.as_mut(), &pathname, flags, mode) {
                Ok(res) => Some(register_fd(state, res) as i64),
                Err(err) => Some(-(err as i32) as i64),
            }
        }
        Some(Sysno::openat2) => {
            let raw_dirfd = regs.rdi as i32;
            let addr = regs.rsi as usize;
            let how_addr = regs.rdx as usize;
            let how_size = regs.r10 as usize;
            let pathname = read_string(pid, addr);
            let mut dirfd_opt = get_fd(state, raw_dirfd);
            if raw_dirfd != libc::AT_FDCWD && !pathname.starts_with('/') && dirfd_opt.is_none() {
                return ebadf(&proc);
            }
            let how_bytes = proc.read_memory(how_addr, std::cmp::min(how_size, 24));
            if how_bytes.len() < 24 {
                let _ = proc.skip_syscall();
                return Some(-libc::EFAULT as i64);
            }
            let flags = u64::from_ne_bytes(how_bytes[0..8].try_into().unwrap()) as c_int;
            let mode = u64::from_ne_bytes(how_bytes[8..16].try_into().unwrap()) as libc::mode_t;
            let resolve = u64::from_ne_bytes(how_bytes[16..24].try_into().unwrap());
            if resolve == 0 {
                match handler.openat(&proc, dirfd_opt.as_mut(), &pathname, flags, mode) {
                    Ok(res) => Some(register_fd(state, res) as i64),
                    Err(err) => Some(-(err as i32) as i64),
                }
            } else {
                let actual_dirfd = dirfd_opt.as_ref().map(|d| d.as_raw_fd()).unwrap_or(libc::AT_FDCWD);
                match proc.syscall(libc::SYS_openat2 as u64, actual_dirfd as i64 as u64, regs.rsi, regs.rdx, regs.r10, 0, 0) {
                    Ok(res) => {
                        if res >= 0 {
                            let fd_entry = handler.wrap_raw_fd(&proc, res as c_int);
                            register_fd(state, fd_entry);
                        }
                        Some(res)
                    }
                    Err(err) => Some(-(err as i32) as i64),
                }
            }
        }
        Some(Sysno::newfstatat) => {
            let raw_dirfd = regs.rdi as i32;
            let addr = regs.rsi as usize;
            let flags = regs.r10 as i32;
            let pathname = read_string(pid, addr);
            let mut dirfd_opt = get_fd(state, raw_dirfd);
            if raw_dirfd != libc::AT_FDCWD && !pathname.starts_with('/') && dirfd_opt.is_none() {
                return ebadf(&proc);
            }
            match handler.newfstatat(&proc, dirfd_opt.as_mut(), &pathname, flags) {
                Ok(res) => Some(res as i64),
                Err(err) => Some(-(err as i32) as i64),
            }
        }
        Some(Sysno::statx) => {
            let raw_dirfd = regs.rdi as i32;
            let addr = regs.rsi as usize;
            let flags = regs.rdx as i32;
            let mask = regs.r10 as libc::c_uint;
            let pathname = read_string(pid, addr);
            let mut dirfd_opt = get_fd(state, raw_dirfd);
            if raw_dirfd != libc::AT_FDCWD && !pathname.starts_with('/') && dirfd_opt.is_none() {
                return ebadf(&proc);
            }
            match handler.statx(&proc, dirfd_opt.as_mut(), &pathname, flags, mask) {
                Ok(res) => Some(res as i64),
                Err(err) => Some(-(err as i32) as i64),
            }
        }
        Some(Sysno::exit) => {
            let status = regs.rdi as i32;
            state.exit_code = Some(status);
            let _ = handler.exit(&proc, status);
            Some(0)
        }
        Some(Sysno::exit_group) => {
            let status = regs.rdi as i32;
            state.exit_code = Some(status);
            let _ = handler.exit_group(&proc, status);
            Some(0)
        }
        Some(Sysno::fork) => {
            match handler.fork(&proc) {
                Ok((_, child_handler)) => {
                    state.pending_child_handler = Some(child_handler);
                    state.pending_clone_files = false;
                    state.pending_parent_tidptr = None;
                    state.pending_child_tidptr = None;
                    None
                }
                Err(err) => Some(-(err as i32) as i64),
            }
        }
        Some(Sysno::vfork) => {
            match handler.vfork(&proc) {
                Ok((_, child_handler)) => {
                    state.pending_child_handler = Some(child_handler);
                    state.pending_clone_files = false;
                    state.pending_parent_tidptr = None;
                    state.pending_child_tidptr = None;
                    None
                }
                Err(err) => Some(-(err as i32) as i64),
            }
        }
        Some(Sysno::clone) => {
            let flags = regs.rdi as i32;
            let parent_tid = if (flags & libc::CLONE_PARENT_SETTID) != 0 {
                Some(regs.rdx as u64)
            } else {
                None
            };
            let child_settid = if (flags & libc::CLONE_CHILD_SETTID) != 0 {
                Some(regs.r10 as u64)
            } else {
                None
            };
            let child_cleartid = if (flags & libc::CLONE_CHILD_CLEARTID) != 0 {
                Some(regs.r10 as *mut c_int)
            } else {
                None
            };
            match handler.clone(&proc, flags, child_cleartid) {
                Ok((_, child_handler)) => {
                    state.pending_child_handler = Some(child_handler);
                    state.pending_clone_files = (flags & libc::CLONE_FILES) != 0;
                    state.pending_parent_tidptr = parent_tid;
                    state.pending_child_tidptr = child_settid;
                    None
                }
                Err(err) => Some(-(err as i32) as i64),
            }
        }
        Some(Sysno::clone3) => {
            let addr = regs.rdi as usize;
            let size = regs.rsi as usize;
            let args_bytes = proc.read_memory(addr, std::cmp::min(size, 64)); // We only need the first few fields
            
            let mut flags = 0u64;
            let mut child_cleartid = None;
            let mut child_settid = None;
            let mut parent_tid = None;
            
            if args_bytes.len() >= 8 {
                flags = u64::from_ne_bytes(args_bytes[0..8].try_into().unwrap());
            }
            if args_bytes.len() >= 24 {
                let tid_addr = u64::from_ne_bytes(args_bytes[16..24].try_into().unwrap());
                if (flags & libc::CLONE_CHILD_CLEARTID as u64) != 0 {
                    child_cleartid = Some(tid_addr as *mut c_int);
                }
                if (flags & libc::CLONE_CHILD_SETTID as u64) != 0 {
                    child_settid = Some(tid_addr);
                }
            }
            if args_bytes.len() >= 32 {
                let ptid_addr = u64::from_ne_bytes(args_bytes[24..32].try_into().unwrap());
                if (flags & libc::CLONE_PARENT_SETTID as u64) != 0 {
                    parent_tid = Some(ptid_addr);
                }
            }

            match handler.clone(&proc, flags as i32, child_cleartid) {
                Ok((_, child_handler)) => {
                    state.pending_child_handler = Some(child_handler);
                    state.pending_clone_files = (flags as i32 & libc::CLONE_FILES) != 0;
                    state.pending_parent_tidptr = parent_tid;
                    state.pending_child_tidptr = child_settid;
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
            if let Some(mut fd) = get_fd(state, regs.rdi as i32) {
                let addr = regs.rsi as *const libc::sockaddr;
                let len = regs.rdx as libc::socklen_t;
                match handler.bind(&proc, &mut fd, addr, len) {
                    Ok(res) => Some(res as i64),
                    Err(err) => Some(-(err as i32) as i64),
                }
            } else {
                ebadf(&proc)
            }
        }
        Some(Sysno::listen) => {
            if let Some(mut fd) = get_fd(state, regs.rdi as i32) {
                let backlog = regs.rsi as i32;
                match handler.listen(&proc, &mut fd, backlog) {
                    Ok(res) => Some(res as i64),
                    Err(err) => Some(-(err as i32) as i64),
                }
            } else {
                ebadf(&proc)
            }
        }
        Some(Sysno::accept) => {
            if let Some(mut fd) = get_fd(state, regs.rdi as i32) {
                let addr = regs.rsi as *mut libc::sockaddr;
                let len = regs.rdx as *mut libc::socklen_t;
                match handler.accept(&proc, &mut fd, addr, len) {
                    Ok(res) => Some(register_fd(state, res) as i64),
                    Err(err) => Some(-(err as i32) as i64),
                }
            } else {
                ebadf(&proc)
            }
        }
        Some(Sysno::accept4) => {
            if let Some(mut fd) = get_fd(state, regs.rdi as i32) {
                let addr = regs.rsi as *mut libc::sockaddr;
                let len = regs.rdx as *mut libc::socklen_t;
                let flags = regs.r10 as i32;
                match handler.accept4(&proc, &mut fd, addr, len, flags) {
                    Ok(res) => Some(register_fd(state, res) as i64),
                    Err(err) => Some(-(err as i32) as i64),
                }
            } else {
                ebadf(&proc)
            }
        }
        Some(Sysno::connect) => {
            if let Some(mut fd) = get_fd(state, regs.rdi as i32) {
                let addr = regs.rsi as *const libc::sockaddr;
                let len = regs.rdx as libc::socklen_t;
                match handler.connect(&proc, &mut fd, addr, len) {
                    Ok(res) => Some(res as i64),
                    Err(err) => Some(-(err as i32) as i64),
                }
            } else {
                ebadf(&proc)
            }
        }
        Some(Sysno::setsockopt) => {
            if let Some(mut fd) = get_fd(state, regs.rdi as i32) {
                let level = regs.rsi as i32;
                let optname = regs.rdx as i32;
                let optval = regs.r10 as *const libc::c_void;
                let optlen = regs.r8 as libc::socklen_t;
                match handler.setsockopt(&proc, &mut fd, level, optname, optval, optlen) {
                    Ok(res) => Some(res as i64),
                    Err(err) => Some(-(err as i32) as i64),
                }
            } else {
                ebadf(&proc)
            }
        }
        Some(Sysno::getsockname) => {
            if let Some(mut fd) = get_fd(state, regs.rdi as i32) {
                let addr = regs.rsi as *mut libc::sockaddr;
                let len = regs.rdx as *mut libc::socklen_t;
                match handler.getsockname(&proc, &mut fd, addr, len) {
                    Ok(res) => Some(res as i64),
                    Err(err) => Some(-(err as i32) as i64),
                }
            } else {
                ebadf(&proc)
            }
        }
        Some(Sysno::getpeername) => {
            if let Some(mut fd) = get_fd(state, regs.rdi as i32) {
                let addr = regs.rsi as *mut libc::sockaddr;
                let len = regs.rdx as *mut libc::socklen_t;
                match handler.getpeername(&proc, &mut fd, addr, len) {
                    Ok(res) => Some(res as i64),
                    Err(err) => Some(-(err as i32) as i64),
                }
            } else {
                ebadf(&proc)
            }
        }
        Some(Sysno::getsockopt) => {
            if let Some(mut fd) = get_fd(state, regs.rdi as i32) {
                let level = regs.rsi as i32;
                let optname = regs.rdx as i32;
                let optval = regs.r10;
                let optlen = regs.r8;
                match handler.getsockopt(&proc, &mut fd, level, optname, optval, optlen) {
                    Ok(res) => Some(res as i64),
                    Err(err) => Some(-(err as i32) as i64),
                }
            } else {
                ebadf(&proc)
            }
        }
        Some(Sysno::shutdown) => {
            if let Some(mut fd) = get_fd(state, regs.rdi as i32) {
                let how = regs.rsi as i32;
                match handler.shutdown(&proc, &mut fd, how) {
                    Ok(res) => Some(res as i64),
                    Err(err) => Some(-(err as i32) as i64),
                }
            } else {
                ebadf(&proc)
            }
        }
        Some(Sysno::sendmsg) => {
            if let Some(mut fd) = get_fd(state, regs.rdi as i32) {
                match handler.sendmsg(&proc, &mut fd, regs.rsi, regs.rdx as i32) {
                    Ok(res) => Some(res as i64),
                    Err(err) => Some(-(err as i32) as i64),
                }
            } else {
                ebadf(&proc)
            }
        }
        Some(Sysno::recvmsg) => {
            if let Some(mut fd) = get_fd(state, regs.rdi as i32) {
                match handler.recvmsg(&proc, &mut fd, regs.rsi, regs.rdx as i32) {
                    Ok(res) => Some(res as i64),
                    Err(err) => Some(-(err as i32) as i64),
                }
            } else {
                ebadf(&proc)
            }
        }
        Some(Sysno::pread64) => {
            if let Some(mut fd) = get_fd(state, regs.rdi as i32) {
                let addr = regs.rsi as usize;
                let count = regs.rdx as usize;
                let offset = regs.r10 as libc::off_t;
                match handler.pread(&proc, &mut fd, count, offset) {
                    Ok(buf) => {
                        proc.write_memory(addr, &buf);
                        Some(buf.len() as i64)
                    }
                    Err(err) => Some(-(err as i32) as i64),
                }
            } else {
                ebadf(&proc)
            }
        }
        Some(Sysno::poll) | Some(Sysno::ppoll) => {
            let fds_addr = regs.rdi as usize;
            let nfds = std::cmp::min(regs.rsi as usize, 4096);
            let timeout = if sysno == Some(Sysno::poll) {
                regs.rdx as i32
            } else {
                match read_timespec_timeout_ms(&proc, regs.rdx as usize) {
                    Ok(t) => t,
                    Err(errno) => return Some(errno),
                }
            };
            let mut fds = read_pollfds(pid, fds_addr, nfds, state);
            
            match handler.poll(&proc, &mut fds, timeout) {
                Ok(res) => {
                    write_pollfds_revents(&proc, fds_addr, &fds);
                    Some(res as i64)
                }
                Err(err) => Some(-(err as i32) as i64),
            }
        }
        Some(Sysno::sendto) => {
            if let Some(mut fd) = get_fd(state, regs.rdi as i32) {
                let buf_addr = regs.rsi as usize;
                let len = regs.rdx as usize;
                let flags = regs.r10 as i32;
                let dest_addr = regs.r8 as *const libc::sockaddr;
                let addrlen = regs.r9 as libc::socklen_t;
                let buf = proc.read_memory(buf_addr, len);
                match handler.sendto(&proc, &mut fd, &buf, flags, dest_addr, addrlen) {
                    Ok(res) => Some(res as i64),
                    Err(err) => Some(-(err as i32) as i64),
                }
            } else {
                ebadf(&proc)
            }
        }
        Some(Sysno::recvfrom) => {
            if let Some(mut fd) = get_fd(state, regs.rdi as i32) {
                let buf_addr = regs.rsi as usize;
                let len = regs.rdx as usize;
                let flags = regs.r10 as i32;
                let src_addr = regs.r8 as *mut libc::sockaddr;
                let addrlen = regs.r9 as *mut libc::socklen_t;
                match handler.recvfrom(&proc, &mut fd, len, flags, src_addr, addrlen) {
                    Ok(buf) => {
                        proc.write_memory(buf_addr, &buf);
                        Some(buf.len() as i64)
                    },
                    Err(err) => Some(-(err as i32) as i64),
                }
            } else {
                ebadf(&proc)
            }
        }
        Some(Sysno::fcntl) => {
            let guest_fd = regs.rdi as i32;
            if let Some(mut fd) = get_fd(state, guest_fd) {
                let cmd = regs.rsi as i32;
                let arg = regs.rdx as libc::c_ulong;
                let res = match handler.fcntl(&proc, &mut fd, cmd, arg) {
                    Ok(res) => {
                        if (cmd == libc::F_DUPFD || cmd == libc::F_DUPFD_CLOEXEC) && res >= 0 {
                            let duped = handler.dup_fd_to(&fd, res);
                            state.fd_map.lock().unwrap().insert(res, duped);
                        }
                        Some(res as i64)
                    }
                    Err(err) => Some(-(err as i32) as i64),
                };
                update_fd(state, guest_fd, fd);
                res
            } else {
                ebadf(&proc)
            }
        }
        Some(Sysno::lseek) => {
            let guest_fd = regs.rdi as i32;
            if let Some(mut fd) = get_fd(state, guest_fd) {
                let offset = regs.rsi as libc::off_t;
                let whence = regs.rdx as i32;
                let res = match handler.lseek(&proc, &mut fd, offset, whence) {
                    Ok(res) => Some(res as i64),
                    Err(err) => Some(-(err as i32) as i64),
                };
                update_fd(state, guest_fd, fd);
                res
            } else {
                ebadf(&proc)
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
            if let Some(mut fd) = get_fd(state, regs.rdi as i32) {
                let addr = regs.rsi as usize;
                let count = regs.rdx as usize;
                let offset = regs.r10 as libc::off_t;
                let buf = proc.read_memory(addr, count);
                match handler.pwrite(&proc, &mut fd, &buf, offset) {
                    Ok(res) => Some(res as i64),
                    Err(err) => Some(-(err as i32) as i64),
                }
            } else {
                ebadf(&proc)
            }
        }
        Some(Sysno::fsync) => {
            if let Some(mut fd) = get_fd(state, regs.rdi as i32) {
                match handler.fsync(&proc, &mut fd) {
                    Ok(res) => Some(res as i64),
                    Err(err) => Some(-(err as i32) as i64),
                }
            } else {
                ebadf(&proc)
            }
        }
        Some(Sysno::fdatasync) => {
            if let Some(mut fd) = get_fd(state, regs.rdi as i32) {
                match handler.fdatasync(&proc, &mut fd) {
                    Ok(res) => Some(res as i64),
                    Err(err) => Some(-(err as i32) as i64),
                }
            } else {
                ebadf(&proc)
            }
        }
        Some(Sysno::getcwd) => {
            let buf_addr = regs.rdi as usize;
            let size = regs.rsi as usize;
            match handler.getcwd(&proc, size) {
                Ok(buf) => {
                     if buf.len() > 0 {
                         proc.write_memory(buf_addr, &buf);
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
        Some(Sysno::gettid) => {
            match handler.gettid(&proc) {
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
        Some(Sysno::getresuid) => {
            match handler.getresuid(&proc, regs.rdi, regs.rsi, regs.rdx) {
                Ok(res) => Some(res as i64),
                Err(err) => Some(-(err as i32) as i64),
            }
        }
        Some(Sysno::getresgid) => {
            match handler.getresgid(&proc, regs.rdi, regs.rsi, regs.rdx) {
                Ok(res) => Some(res as i64),
                Err(err) => Some(-(err as i32) as i64),
            }
        }
        Some(Sysno::clock_getres) => {
            match handler.clock_getres(&proc, regs.rdi as libc::clockid_t, regs.rsi) {
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
        Some(Sysno::getpgid) => {
            match handler.getpgid(&proc, regs.rdi as i32) {
                Ok(res) => Some(res as i64),
                Err(err) => Some(-(err as i32) as i64),
            }
        }
        Some(Sysno::getsid) => {
            match handler.getsid(&proc, regs.rdi as i32) {
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
        Some(Sysno::time) => {
            let tloc = regs.rdi as *mut libc::time_t;
            match handler.time(&proc, tloc) {
                Ok(res) => Some(res as i64),
                Err(err) => Some(-(err as i32) as i64),
            }
        }
        Some(Sysno::adjtimex) => {
            match handler.adjtimex(&proc, regs.rdi) {
                Ok(res) => Some(res as i64),
                Err(err) => Some(-(err as i32) as i64),
            }
        }
        Some(Sysno::clock_adjtime) => {
            match handler.clock_adjtime(&proc, regs.rdi as libc::clockid_t, regs.rsi) {
                Ok(res) => Some(res as i64),
                Err(err) => Some(-(err as i32) as i64),
            }
        }
        Some(Sysno::getrusage) => {
            match handler.getrusage(&proc, regs.rdi as i32, regs.rsi) {
                Ok(res) => Some(res as i64),
                Err(err) => Some(-(err as i32) as i64),
            }
        }
        Some(Sysno::getcpu) => {
            match handler.getcpu(&proc, regs.rdi, regs.rsi, regs.rdx) {
                Ok(res) => Some(res as i64),
                Err(err) => Some(-(err as i32) as i64),
            }
        }
        Some(Sysno::wait4) => {
            match handler.wait4(&proc, regs.rdi as i32, regs.rsi, regs.rdx as i32, regs.r10) {
                Ok(res) => Some(res as i64),
                Err(err) => Some(-(err as i32) as i64),
            }
        }
        Some(Sysno::kill) => {
            match handler.kill(&proc, regs.rdi as i32, regs.rsi as i32) {
                Ok(res) => Some(res as i64),
                Err(err) => Some(-(err as i32) as i64),
            }
        }
        Some(Sysno::tkill) => {
            match handler.tkill(&proc, regs.rdi as i32, regs.rsi as i32) {
                Ok(res) => Some(res as i64),
                Err(err) => Some(-(err as i32) as i64),
            }
        }
        Some(Sysno::tgkill) => {
            match handler.tgkill(&proc, regs.rdi as i32, regs.rsi as i32, regs.rdx as i32) {
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
            if let Some(mut fd) = get_fd(state, regs.rdi as i32) {
                let iov = regs.rsi as u64;
                let iovcnt = regs.rdx as i32;
                match handler.writev(&proc, &mut fd, iov, iovcnt) {
                    Ok(res) => Some(res as i64),
                    Err(err) => Some(-(err as i32) as i64),
                }
            } else {
                ebadf(&proc)
            }
        }
        Some(Sysno::readv) => {
            let guest_fd = regs.rdi as i32;
            if let Some(mut fd) = get_fd(state, guest_fd) {
                let iov = regs.rsi as u64;
                let iovcnt = regs.rdx as i32;
                let res = match handler.readv(&proc, &mut fd, iov, iovcnt) {
                    Ok(res) => Some(res as i64),
                    Err(err) => Some(-(err as i32) as i64),
                };
                update_fd(state, guest_fd, fd);
                res
            } else {
                ebadf(&proc)
            }
        }
        Some(Sysno::preadv) | Some(Sysno::preadv2) => {
            let guest_fd = regs.rdi as i32;
            if let Some(mut fd) = get_fd(state, guest_fd) {
                let iov = regs.rsi as u64;
                let iovcnt = regs.rdx as i32;
                let offset = regs.r10 as libc::off_t;
                if sysno == Some(Sysno::preadv2) && offset == -1 {
                    let res = match handler.readv(&proc, &mut fd, iov, iovcnt) {
                        Ok(res) => Some(res as i64),
                        Err(err) => Some(-(err as i32) as i64),
                    };
                    update_fd(state, guest_fd, fd);
                    res
                } else {
                    match handler.preadv(&proc, &mut fd, iov, iovcnt, offset) {
                        Ok(res) => Some(res as i64),
                        Err(err) => Some(-(err as i32) as i64),
                    }
                }
            } else {
                ebadf(&proc)
            }
        }
        Some(Sysno::pwritev) | Some(Sysno::pwritev2) => {
            if get_fd(state, regs.rdi as i32).is_none() {
                return ebadf(&proc);
            }
            None
        }
        Some(Sysno::epoll_ctl) => {
            let epfd_raw = regs.rdi as i32;
            let op = regs.rsi as i32;
            let target_raw = regs.rdx as i32;
            let event_addr = regs.r10;
            if epfd_raw < 0 || target_raw < 0 {
                return ebadf(&proc);
            }
            let target_fd = get_fd(state, target_raw);
            match handler.epoll_ctl(&proc, epfd_raw, op, target_raw, target_fd.as_ref(), event_addr) {
                Ok(res) => Some(res as i64),
                Err(err) => Some(-(err as i32) as i64),
            }
        }
        Some(Sysno::epoll_wait) | Some(Sysno::epoll_pwait) | Some(Sysno::epoll_pwait2) => {
            let epfd_raw = regs.rdi as i32;
            let events_addr = regs.rsi;
            let maxevents = regs.rdx as i32;
            if epfd_raw < 0 {
                return ebadf(&proc);
            }
            let timeout = if sysno == Some(Sysno::epoll_pwait2) {
                match read_timespec_timeout_ms(&proc, regs.r10 as usize) {
                    Ok(t) => t,
                    Err(errno) => return Some(errno),
                }
            } else {
                regs.r10 as i32
            };
            match handler.epoll_wait(&proc, epfd_raw, events_addr, maxevents, timeout) {
                Ok(res) => Some(res as i64),
                Err(err) => Some(-(err as i32) as i64),
            }
        }
        Some(Sysno::rt_sigprocmask)
        | Some(Sysno::rt_sigaction)
        | Some(Sysno::rt_sigreturn)
        | Some(Sysno::sigaltstack)
        | Some(Sysno::access)
        | Some(Sysno::arch_prctl)
        | Some(Sysno::set_robust_list)
        | Some(Sysno::rseq)
        | Some(Sysno::mprotect)
        | Some(Sysno::madvise)
        | Some(Sysno::prlimit64)
        | Some(Sysno::sched_getaffinity)
        | Some(Sysno::sched_setaffinity)
        | Some(Sysno::sched_yield)
        | Some(Sysno::prctl) => {
            // Let it fall through to the kernel without printing "unknown system call".
            None
        }
        Some(Sysno::getrandom) => {
            let buf_addr = regs.rdi as usize;
            let count = regs.rsi as usize;
            let flags = regs.rdx as i32;
            if count > 0 && (buf_addr == 0 || ptrace::read(pid, (buf_addr & !7) as *mut _).is_err()) {
                let _ = proc.skip_syscall();
                return Some(-libc::EFAULT as i64);
            }
            let capped_count = std::cmp::min(count, 65536);
            let mut buf = vec![0u8; capped_count];
            match handler.getrandom(&proc, &mut buf, flags) {
                Ok(res) => {
                    proc.write_memory(buf_addr, &buf[..res]);
                    Some(res as i64)
                }
                Err(err) => Some(-(err as i32) as i64),
            }
        }
        Some(Sysno::futex) => {
            let uaddr = regs.rdi as *mut u32;
            let op = regs.rsi as i32;
            let val = regs.rdx as u32;
            let timeout = regs.r10 as *const libc::timespec;
            let uaddr2 = regs.r8 as *mut u32;
            let val3 = regs.r9 as u32;
            match handler.futex(&proc, uaddr, op, val, timeout, uaddr2, val3) {
                Ok(res) => Some(res as i64),
                Err(err) => Some(-(err as i32) as i64),
            }
        }
        Some(Sysno::set_tid_address) => {
            let tidptr = regs.rdi as *mut c_int;
            match handler.set_tid_address(&proc, tidptr) {
                Ok(res) => Some(res as i64),
                Err(err) => Some(-(err as i32) as i64),
            }
        }
        Some(Sysno::nanosleep) => {
            let req = regs.rdi as *const libc::timespec;
            let rem = regs.rsi as *mut libc::timespec;
            match handler.nanosleep(&proc, req, rem) {
                Ok(res) => Some(res as i64),
                Err(err) => Some(-(err as i32) as i64),
            }
        }
        Some(Sysno::clock_nanosleep) => {
            let clk_id = regs.rdi as libc::clockid_t;
            let flags = regs.rsi as c_int;
            let req = regs.rdx as *const libc::timespec;
            let rem = regs.r10 as *mut libc::timespec;
            match handler.clock_nanosleep(&proc, clk_id, flags, req, rem) {
                Ok(res) => Some(res as i64),
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

fn read_timespec_timeout_ms(proc: &crate::captured::CapturedProcess, addr: usize) -> Result<i32, i64> {
    if addr == 0 {
        return Ok(-1);
    }
    let ts = proc.read_memory(addr, 16);
    if ts.len() < 16 {
        let _ = proc.skip_syscall();
        return Err(-libc::EFAULT as i64);
    }
    let sec = i64::from_ne_bytes(ts[0..8].try_into().unwrap());
    let nsec = i64::from_ne_bytes(ts[8..16].try_into().unwrap());
    if sec < 0 || nsec < 0 || nsec >= 1_000_000_000 {
        let _ = proc.skip_syscall();
        return Err(-libc::EINVAL as i64);
    }
    let ms = sec
        .saturating_mul(1000)
        .saturating_add((nsec + 999_999) / 1_000_000)
        .clamp(0, i32::MAX as i64) as i32;
    Ok(ms)
}

fn ebadf(proc: &crate::captured::CapturedProcess) -> Option<i64> {
    let _ = proc.skip_syscall();
    Some(-libc::EBADF as i64)
}

fn get_fd<Fd: Clone + std::os::unix::io::AsRawFd>(state: &ChildState<Fd>, guest_fd: c_int) -> Option<Fd> {
    if guest_fd < 0 {
        return None;
    }
    let map = state.fd_map.lock().unwrap();
    if let Some(fd) = map.get(&guest_fd) {
        Some(fd.clone())
    } else {
        map.values().find(|fd| fd.as_raw_fd() == guest_fd).cloned()
    }
}

fn update_fd<Fd: std::os::unix::io::AsRawFd>(state: &ChildState<Fd>, guest_fd: c_int, fd: Fd) {
    let mut map = state.fd_map.lock().unwrap();
    if map.contains_key(&guest_fd) {
        map.insert(guest_fd, fd);
    }
}

fn take_fd<Fd: std::os::unix::io::AsRawFd>(state: &ChildState<Fd>, guest_fd: c_int) -> Option<Fd> {
    let mut map = state.fd_map.lock().unwrap();
    if let Some(fd) = map.remove(&guest_fd) {
        return Some(fd);
    }
    let key = map.iter().find(|(_, fd)| fd.as_raw_fd() == guest_fd).map(|(k, _)| *k);
    if let Some(k) = key {
        return map.remove(&k);
    }
    None
}

fn register_fd<Fd: std::os::unix::io::AsRawFd>(state: &ChildState<Fd>, fd: Fd) -> c_int {
    let raw_fd = fd.as_raw_fd();
    state.fd_map.lock().unwrap().insert(raw_fd, fd);
    raw_fd
}


fn read_string(pid: Pid, addr: usize) -> String {
    if addr == 0 {
        return String::new();
    }
    let mut result = Vec::new();
    let mut current_addr = addr;
    loop {
        let aligned_addr = current_addr & !7;
        let offset = current_addr & 7;
        let word = match ptrace::read(pid, aligned_addr as *mut _) {
            Ok(w) => w,
            Err(_) => return String::from_utf8_lossy(&result).into_owned(),
        };
        let bytes: [u8; 8] = word.to_ne_bytes();
        for &b in &bytes[offset..] {
            if b == 0 {
                return String::from_utf8_lossy(&result).into_owned();
            }
            result.push(b);
        }
        current_addr = aligned_addr + 8;
    }
}

fn read_pollfds<Fd>(pid: Pid, addr: usize, nfds: usize, state: &ChildState<Fd>) -> Vec<PollFd<Fd>>
where
    Fd: Clone + std::os::unix::io::AsRawFd,
{
    let mut fds = Vec::with_capacity(nfds);
    let pollfd_size = std::mem::size_of::<libc::pollfd>();
    let proc = crate::captured::CapturedProcess::new(pid);
    for i in 0..nfds {
        let item_addr = addr + i * pollfd_size;
        let bytes = proc.read_memory(item_addr, 8);
        let (fd_int, events, revents) = if bytes.len() == 8 {
            (
                i32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
                i16::from_ne_bytes([bytes[4], bytes[5]]),
                i16::from_ne_bytes([bytes[6], bytes[7]]),
            )
        } else {
            (-1, 0, 0)
        };
        let fd_opt = get_fd(state, fd_int);
        fds.push(PollFd {
            fd: fd_opt,
            raw_fd: fd_int,
            events,
            revents,
        });
    }
    fds
}

fn write_pollfds_revents<Fd>(proc: &crate::captured::CapturedProcess, addr: usize, fds: &[PollFd<Fd>]) {
    let pollfd_size = std::mem::size_of::<libc::pollfd>();
    for (i, fd) in fds.iter().enumerate() {
        let item_addr = addr + i * pollfd_size;
        // revents is at offset 6.
        let revents_addr = item_addr + 6;
        let revents_bytes = fd.revents.to_ne_bytes();
        proc.write_memory(revents_addr, &revents_bytes);
    }
}
