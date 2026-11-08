use libc::{c_int, c_void, mode_t, off_t};
use crate::captured::CapturedProcess;

pub trait Linux<Fd> {
    /// Get default file descriptors for stdin, stdout, stderr
    fn default_fds(&mut self) -> (Fd, Fd, Fd);
    
    /// Create a new Fd object for the same underlying file descriptor.
    /// Used for fork/clone where child inherits file descriptors.
    fn dup_fd(&mut self, fd: &Fd) -> Fd;

    /// Create a new Fd object referring to the same resource at `new_raw_fd`.
    /// Used for `dup`, `dup2`, `dup3`, `fcntl(F_DUPFD)`.
    fn dup_fd_to(&mut self, fd: &Fd, new_raw_fd: c_int) -> Fd;

    /// Called when an existing Fd in `fd_map` is silently closed by `dup2`/`dup3`.
    fn on_fd_overwritten(&mut self, _fd: Fd) {}

    /// Wrap a newly created raw kernel FD (e.g., from `pipe`, `pipe2`, or `openat2`) into `Fd`.
    fn wrap_raw_fd(&mut self, proc: &CapturedProcess, raw_fd: c_int) -> Fd;

    /// dup - duplicate a file descriptor
    fn dup(&mut self, proc: &CapturedProcess, oldfd: &Fd) -> nix::Result<Fd>;

    /// dup2 - duplicate a file descriptor to a target fd
    fn dup2(&mut self, proc: &CapturedProcess, oldfd: &Fd, newfd: c_int) -> nix::Result<Fd>;

    /// dup3 - duplicate a file descriptor to a target fd with flags
    fn dup3(&mut self, proc: &CapturedProcess, oldfd: &Fd, newfd: c_int, flags: c_int) -> nix::Result<Fd>;

    /// write - write to a file descriptor
    ///
    /// write() writes up to count bytes from the buffer starting at buf to the file referred to by the file descriptor fd.
    fn write(&mut self, proc: &CapturedProcess, fd: &mut Fd, buf: &[u8]) -> nix::Result<usize>;

    /// read - read from a file descriptor
    ///
    /// read() attempts to read up to count bytes from file descriptor fd into the buffer starting at buf.
    fn read(&mut self, proc: &CapturedProcess, fd: &mut Fd, count: usize) -> nix::Result<Vec<u8>>;

    /// open, openat, creat - open and possibly create a file
    ///
    /// The open() system call opens the file specified by pathname. If the specified file does not exist, it may optionally (if O_CREAT is specified in flags) be created by open().
    fn open(&mut self, proc: &CapturedProcess, pathname: &str, flags: c_int, mode: mode_t) -> nix::Result<Fd>;

    /// openat - open and possibly create a file relative to a directory file descriptor
    /// dirfd: None means AT_FDCWD
    fn openat(&mut self, proc: &CapturedProcess, dirfd: Option<&mut Fd>, pathname: &str, flags: c_int, mode: mode_t) -> nix::Result<Fd>;

    /// close - close a file descriptor
    ///
    /// close() closes a file descriptor, so that it no longer refers to any file and may be reused.
    fn close(&mut self, proc: &CapturedProcess, fd: Fd) -> nix::Result<c_int>;

    /// stat, fstat, lstat, fstatat, statx - get file status
    ///
    /// These functions return information about a file, in the buffer pointed to by statbuf.
    fn stat(&mut self, proc: &CapturedProcess, pathname: &str) -> nix::Result<c_int>;

    fn lstat(&mut self, proc: &CapturedProcess, pathname: &str) -> nix::Result<c_int>;

    fn fstat(&mut self, proc: &CapturedProcess, fd: &mut Fd) -> nix::Result<c_int>;

    /// newfstatat - get file status relative to a directory file descriptor
    /// dirfd: None means AT_FDCWD
    fn newfstatat(&mut self, proc: &CapturedProcess, dirfd: Option<&mut Fd>, pathname: &str, flags: c_int) -> nix::Result<c_int>;

    /// statx - get file status (extended)
    /// dirfd: None means AT_FDCWD
    fn statx(&mut self, proc: &CapturedProcess, dirfd: Option<&mut Fd>, pathname: &str, flags: c_int, mask: libc::c_uint) -> nix::Result<c_int>;

    /// mmap, munmap - map or unmap files or devices into memory
    ///
    /// mmap() creates a new mapping in the virtual address space of the calling process.
    /// fd: None means -1 (anonymous mapping)
    fn mmap(&mut self, proc: &CapturedProcess, addr: *mut c_void, length: usize, prot: c_int, flags: c_int, fd: Option<&mut Fd>, offset: off_t) -> nix::Result<*mut c_void>;

    /// munmap - unmap a file or device from memory
    ///
    /// The munmap() system call deletes the mappings for the specified address range.
    fn munmap(&mut self, proc: &CapturedProcess, addr: *mut c_void, length: usize) -> nix::Result<c_int>;

    /// _exit, _Exit - terminate the calling process
    ///
    /// The function _exit() terminates the calling process "immediately".
    fn exit(&mut self, proc: &CapturedProcess, status: c_int) -> nix::Result<()>;

    /// exit_group - exit all threads in a process
    ///
    /// This system call is equivalent to _exit(2) except that it terminates not only the calling thread, but all threads in the calling process's thread group.
    fn exit_group(&mut self, proc: &CapturedProcess, status: c_int) -> nix::Result<()>;

    /// brk, sbrk - change data segment size
    ///
    /// brk() and sbrk() change the location of the program break, which defines the end of the process's data segment.
    fn brk(&mut self, proc: &CapturedProcess, addr: *mut c_void) -> nix::Result<*mut c_void>;

    /// clock_getres, clock_gettime, clock_settime - clock and timer functions
    ///
    /// The function clock_getres() finds the resolution (precision) of the specified clock clk_id, and, if res is non-NULL, stores it in the struct timespec pointed to by res.
    /// The functions clock_gettime() and clock_settime() retrieve and set the time of the specified clock clk_id.
    fn clock_gettime(&mut self, proc: &CapturedProcess, clk_id: libc::clockid_t) -> nix::Result<c_int>;

    /// fork - create a child process
    ///
    /// fork() creates a new process by duplicating the calling process.
    fn fork(&mut self, proc: &CapturedProcess) -> nix::Result<(nix::unistd::Pid, Box<dyn Linux<Fd> + Send>)>;

    /// vfork - create a child process and block parent
    ///
    /// vfork() differs from fork(2) in that the calling thread is suspended until the child terminates (either normally, by calling _exit(2), or abnormally, after delivery of a fatal signal), or it makes a call to execve(2).
    fn vfork(&mut self, proc: &CapturedProcess) -> nix::Result<(nix::unistd::Pid, Box<dyn Linux<Fd> + Send>)>;

    /// clone, __clone2, clone3 - create a child process
    ///
    /// These system calls create a new ("child") process, in a manner similar to fork(2).
    fn clone(&mut self, proc: &CapturedProcess, flags: c_int, tid_address: Option<*mut c_int>) -> nix::Result<(nix::unistd::Pid, Box<dyn Linux<Fd> + Send>)>;

    /// socket - create an endpoint for communication
    fn socket(&mut self, proc: &CapturedProcess, domain: c_int, ty: c_int, protocol: c_int) -> nix::Result<Fd>;

    /// bind - bind a name to a socket
    fn bind(&mut self, proc: &CapturedProcess, fd: &mut Fd, addr: *const libc::sockaddr, len: libc::socklen_t) -> nix::Result<c_int>;

    /// listen - listen for connections on a socket
    fn listen(&mut self, proc: &CapturedProcess, fd: &mut Fd, backlog: c_int) -> nix::Result<c_int>;

    /// accept - accept a connection on a socket
    fn accept(&mut self, proc: &CapturedProcess, fd: &mut Fd, addr: *mut libc::sockaddr, len: *mut libc::socklen_t) -> nix::Result<Fd>;

    /// accept4 - accept a connection on a socket
    fn accept4(&mut self, proc: &CapturedProcess, fd: &mut Fd, addr: *mut libc::sockaddr, len: *mut libc::socklen_t, flags: c_int) -> nix::Result<Fd>;

    /// connect - initiate a connection on a socket
    fn connect(&mut self, proc: &CapturedProcess, fd: &mut Fd, addr: *const libc::sockaddr, len: libc::socklen_t) -> nix::Result<c_int>;

    /// setsockopt - set options on sockets
    fn setsockopt(&mut self, proc: &CapturedProcess, fd: &mut Fd, level: c_int, optname: c_int, optval: *const c_void, optlen: libc::socklen_t) -> nix::Result<c_int>;

    /// getsockname - get socket name
    fn getsockname(&mut self, proc: &CapturedProcess, fd: &mut Fd, addr: *mut libc::sockaddr, len: *mut libc::socklen_t) -> nix::Result<c_int>;

    /// pread - read from or write to a file descriptor at a given offset
    fn pread(&mut self, proc: &CapturedProcess, fd: &mut Fd, count: usize, offset: off_t) -> nix::Result<Vec<u8>>;

    /// poll - wait for some event on a file descriptor
    fn poll(&mut self, proc: &CapturedProcess, fds: &mut [PollFd<Fd>], timeout: c_int) -> nix::Result<c_int>;

    /// sendto - send a message on a socket
    fn sendto(&mut self, proc: &CapturedProcess, fd: &mut Fd, buf: &[u8], flags: c_int, addr: *const libc::sockaddr, len: libc::socklen_t) -> nix::Result<usize>;

    /// recvfrom - receive a message from a socket
    fn recvfrom(&mut self, proc: &CapturedProcess, fd: &mut Fd, count: usize, flags: c_int, addr: *mut libc::sockaddr, len: *mut libc::socklen_t) -> nix::Result<Vec<u8>>;

    /// fcntl - manipulate file descriptor
    fn fcntl(&mut self, proc: &CapturedProcess, fd: &mut Fd, cmd: c_int, arg: libc::c_ulong) -> nix::Result<c_int>;

    /// lseek - reposition read/write file offset
    fn lseek(&mut self, proc: &CapturedProcess, fd: &mut Fd, offset: off_t, whence: c_int) -> nix::Result<off_t>;

    /// unlink - delete a name and possibly the file it refers to
    fn unlink(&mut self, proc: &CapturedProcess, pathname: &str) -> nix::Result<c_int>;

    /// pwrite64 - write to a file descriptor at a given offset
    fn pwrite(&mut self, proc: &CapturedProcess, fd: &mut Fd, buf: &[u8], offset: off_t) -> nix::Result<usize>;

    /// fsync - synchronize a file's in-core state with storage device
    fn fsync(&mut self, proc: &CapturedProcess, fd: &mut Fd) -> nix::Result<c_int>;

    /// fdatasync - synchronize a file's in-core state with storage device
    fn fdatasync(&mut self, proc: &CapturedProcess, fd: &mut Fd) -> nix::Result<c_int>;

    /// getcwd - get current working directory
    fn getcwd(&mut self, proc: &CapturedProcess, size: usize) -> nix::Result<Vec<u8>>;

    /// getpid - get process identification
    fn getpid(&mut self, proc: &CapturedProcess) -> nix::Result<c_int>;

    /// gettid - get thread identification
    fn gettid(&mut self, proc: &CapturedProcess) -> nix::Result<c_int>;

    /// getuid - get user identification
    fn getuid(&mut self, proc: &CapturedProcess) -> nix::Result<c_int>;

    /// geteuid - get effective user identification
    fn geteuid(&mut self, proc: &CapturedProcess) -> nix::Result<c_int>;

    /// getrandom - obtain a series of random bytes
    fn getrandom(&mut self, proc: &CapturedProcess, buf: &mut [u8], flags: i32) -> nix::Result<usize>;

    /// gettimeofday - get time
    fn gettimeofday(&mut self, proc: &CapturedProcess) -> nix::Result<c_int>;

    /// time - get time in seconds
    fn time(&mut self, proc: &CapturedProcess, tloc: *mut libc::time_t) -> nix::Result<libc::time_t>;

    /// getppid - get parent process identification
    fn getppid(&mut self, proc: &CapturedProcess) -> nix::Result<c_int>;

    /// getpgrp - get process group
    fn getpgrp(&mut self, proc: &CapturedProcess) -> nix::Result<c_int>;

    /// uname - get name and information about current kernel
    fn uname(&mut self, proc: &CapturedProcess) -> nix::Result<c_int>;

    /// sysinfo - return system information
    fn sysinfo(&mut self, proc: &CapturedProcess) -> nix::Result<c_int>;

    /// getgid - get group identification
    fn getgid(&mut self, proc: &CapturedProcess) -> nix::Result<c_int>;

    /// getegid - get effective group identification
    fn getegid(&mut self, proc: &CapturedProcess) -> nix::Result<c_int>;

    /// times - get process times
    fn times(&mut self, proc: &CapturedProcess) -> nix::Result<c_int>;

    /// writev - write data from multiple buffers
    fn writev(&mut self, proc: &CapturedProcess, fd: &mut Fd, iov: u64, iovcnt: i32) -> nix::Result<usize>;

    /// readv - read data into multiple buffers
    fn readv(&mut self, proc: &CapturedProcess, fd: &mut Fd, iov: u64, iovcnt: i32) -> nix::Result<usize>;

    /// preadv - read data into multiple buffers at a given offset
    fn preadv(&mut self, proc: &CapturedProcess, fd: &mut Fd, iov: u64, iovcnt: i32, offset: off_t) -> nix::Result<usize>;

    /// futex - fast user-space locking
    fn futex(&mut self, proc: &CapturedProcess, uaddr: *mut u32, op: c_int, val: u32, timeout: *const libc::timespec, uaddr2: *mut u32, val3: u32) -> nix::Result<c_int>;

    /// set_tid_address - set pointer to thread ID
    fn set_tid_address(&mut self, proc: &CapturedProcess, tidptr: *mut c_int) -> nix::Result<c_int>;

    /// on_start - called when a new child process/thread is actually created
    fn on_start(&mut self, _pid: nix::unistd::Pid) {}

    /// on_child_created - called on PTRACE_EVENT_FORK/VFORK/CLONE with new child PID; may return deterministic PID for parent rax
    fn on_child_created(&mut self, _parent_proc: &CapturedProcess, _child_pid: nix::unistd::Pid, _parent_tidptr: Option<u64>, _child_tidptr: Option<u64>) -> Option<i64> {
        None
    }

    /// on_exec - called when a tracee stops at initial exec or PTRACE_EVENT_EXEC
    fn on_exec(&mut self, _proc: &CapturedProcess, _sp: u64) {}

    /// on_exit - called when the tracee process/thread exits
    fn on_exit(&mut self, proc: &CapturedProcess);

    /// nanosleep - high-resolution sleep
    fn nanosleep(&mut self, proc: &CapturedProcess, req: *const libc::timespec, rem: *mut libc::timespec) -> nix::Result<c_int>;

    /// clock_nanosleep - high-resolution sleep with a specified clock
    fn clock_nanosleep(&mut self, proc: &CapturedProcess, clk_id: libc::clockid_t, flags: c_int, req: *const libc::timespec, rem: *mut libc::timespec) -> nix::Result<c_int>;

    /// wait4 - wait for process to change state
    fn wait4(&mut self, proc: &CapturedProcess, wpid: c_int, status_addr: u64, options: c_int, rusage_addr: u64) -> nix::Result<c_int> {
        let res = proc.syscall(libc::SYS_wait4 as u64, wpid as i64 as u64, status_addr, options as u64, rusage_addr, 0, 0)?;
        Ok(res as c_int)
    }

    /// kill - send signal to a process
    fn kill(&mut self, proc: &CapturedProcess, pid: c_int, sig: c_int) -> nix::Result<c_int> {
        let res = proc.syscall(libc::SYS_kill as u64, pid as i64 as u64, sig as u64, 0, 0, 0, 0)?;
        Ok(res as c_int)
    }

    /// tkill - send signal to a thread
    fn tkill(&mut self, proc: &CapturedProcess, tid: c_int, sig: c_int) -> nix::Result<c_int> {
        let res = proc.syscall(libc::SYS_tkill as u64, tid as i64 as u64, sig as u64, 0, 0, 0, 0)?;
        Ok(res as c_int)
    }

    /// tgkill - send signal to a thread in a specific thread group
    fn tgkill(&mut self, proc: &CapturedProcess, tgid: c_int, tid: c_int, sig: c_int) -> nix::Result<c_int> {
        let res = proc.syscall(libc::SYS_tgkill as u64, tgid as i64 as u64, tid as i64 as u64, sig as u64, 0, 0, 0)?;
        Ok(res as c_int)
    }

    /// getpgid - get process group ID
    fn getpgid(&mut self, proc: &CapturedProcess, pid: c_int) -> nix::Result<c_int> {
        let res = proc.syscall(libc::SYS_getpgid as u64, pid as i64 as u64, 0, 0, 0, 0, 0)?;
        Ok(res as c_int)
    }

    /// getsid - get session ID
    fn getsid(&mut self, proc: &CapturedProcess, pid: c_int) -> nix::Result<c_int> {
        let res = proc.syscall(libc::SYS_getsid as u64, pid as i64 as u64, 0, 0, 0, 0, 0)?;
        Ok(res as c_int)
    }

    /// adjtimex - tune kernel clock
    fn adjtimex(&mut self, proc: &CapturedProcess, buf_addr: u64) -> nix::Result<c_int> {
        let res = proc.syscall(libc::SYS_adjtimex as u64, buf_addr, 0, 0, 0, 0, 0)?;
        Ok(res as c_int)
    }

    /// clock_adjtime - tune a specific clock
    fn clock_adjtime(&mut self, proc: &CapturedProcess, clk_id: libc::clockid_t, buf_addr: u64) -> nix::Result<c_int> {
        let res = proc.syscall(libc::SYS_clock_adjtime as u64, clk_id as u64, buf_addr, 0, 0, 0, 0)?;
        Ok(res as c_int)
    }

    /// getrusage - get resource usage
    fn getrusage(&mut self, proc: &CapturedProcess, who: c_int, usage_addr: u64) -> nix::Result<c_int> {
        let res = proc.syscall(libc::SYS_getrusage as u64, who as i64 as u64, usage_addr, 0, 0, 0, 0)?;
        Ok(res as c_int)
    }

    /// getcpu - determine CPU and NUMA node on which the calling thread is running
    fn getcpu(&mut self, proc: &CapturedProcess, cpu_addr: u64, node_addr: u64, tcache_addr: u64) -> nix::Result<c_int> {
        let res = proc.syscall(libc::SYS_getcpu as u64, cpu_addr, node_addr, tcache_addr, 0, 0, 0)?;
        Ok(res as c_int)
    }

    /// clock_getres - find the resolution (precision) of the specified clock
    fn clock_getres(&mut self, proc: &CapturedProcess, clk_id: libc::clockid_t, res_addr: u64) -> nix::Result<c_int> {
        let res = proc.syscall(libc::SYS_clock_getres as u64, clk_id as u64, res_addr, 0, 0, 0, 0)?;
        Ok(res as c_int)
    }

    /// getresuid - get real, effective, and saved user IDs
    fn getresuid(&mut self, proc: &CapturedProcess, ruid_addr: u64, euid_addr: u64, suid_addr: u64) -> nix::Result<c_int> {
        let res = proc.syscall(libc::SYS_getresuid as u64, ruid_addr, euid_addr, suid_addr, 0, 0, 0)?;
        Ok(res as c_int)
    }

    /// getresgid - get real, effective, and saved group IDs
    fn getresgid(&mut self, proc: &CapturedProcess, rgid_addr: u64, egid_addr: u64, sgid_addr: u64) -> nix::Result<c_int> {
        let res = proc.syscall(libc::SYS_getresgid as u64, rgid_addr, egid_addr, sgid_addr, 0, 0, 0)?;
        Ok(res as c_int)
    }

    /// getpeername - get name of connected peer socket
    fn getpeername(&mut self, proc: &CapturedProcess, fd: &mut Fd, addr: *mut libc::sockaddr, len: *mut libc::socklen_t) -> nix::Result<c_int>
    where
        Fd: std::os::unix::io::AsRawFd,
    {
        let res = proc.syscall(libc::SYS_getpeername as u64, fd.as_raw_fd() as u64, addr as u64, len as u64, 0, 0, 0)?;
        Ok(res as c_int)
    }

    /// getsockopt - get options on sockets
    fn getsockopt(&mut self, proc: &CapturedProcess, fd: &mut Fd, level: c_int, optname: c_int, optval: u64, optlen: u64) -> nix::Result<c_int>
    where
        Fd: std::os::unix::io::AsRawFd,
    {
        let res = proc.syscall(libc::SYS_getsockopt as u64, fd.as_raw_fd() as u64, level as u64, optname as u64, optval, optlen, 0)?;
        Ok(res as c_int)
    }

    /// shutdown - shut down part of a full-duplex connection
    fn shutdown(&mut self, proc: &CapturedProcess, fd: &mut Fd, how: c_int) -> nix::Result<c_int>
    where
        Fd: std::os::unix::io::AsRawFd,
    {
        let res = proc.syscall(libc::SYS_shutdown as u64, fd.as_raw_fd() as u64, how as u64, 0, 0, 0, 0)?;
        Ok(res as c_int)
    }

    /// sendmsg - send a message on a socket using a message structure
    fn sendmsg(&mut self, proc: &CapturedProcess, fd: &mut Fd, msg_addr: u64, flags: c_int) -> nix::Result<usize>
    where
        Fd: std::os::unix::io::AsRawFd,
    {
        let res = proc.syscall(libc::SYS_sendmsg as u64, fd.as_raw_fd() as u64, msg_addr, flags as u64, 0, 0, 0)?;
        Ok(res as usize)
    }

    /// recvmsg - receive a message from a socket using a message structure
    fn recvmsg(&mut self, proc: &CapturedProcess, fd: &mut Fd, msg_addr: u64, flags: c_int) -> nix::Result<usize>
    where
        Fd: std::os::unix::io::AsRawFd,
    {
        let res = proc.syscall(libc::SYS_recvmsg as u64, fd.as_raw_fd() as u64, msg_addr, flags as u64, 0, 0, 0)?;
        Ok(res as usize)
    }

    /// epoll_ctl - control interface for an epoll file descriptor
    fn epoll_ctl(&mut self, proc: &CapturedProcess, epfd: c_int, op: c_int, fd: c_int, target: Option<&Fd>, event_addr: u64) -> nix::Result<c_int>
    where
        Fd: std::os::unix::io::AsRawFd,
    {
        let actual_fd = target.map(|t| t.as_raw_fd()).unwrap_or(fd);
        let res = proc.syscall(libc::SYS_epoll_ctl as u64, epfd as u64, op as u64, actual_fd as u64, event_addr, 0, 0)?;
        Ok(res as c_int)
    }

    /// epoll_wait / epoll_pwait - wait for an I/O event on an epoll file descriptor
    fn epoll_wait(&mut self, proc: &CapturedProcess, epfd: c_int, events_addr: u64, maxevents: c_int, timeout_ms: c_int) -> nix::Result<c_int> {
        let res = proc.syscall(libc::SYS_epoll_wait as u64, epfd as u64, events_addr, maxevents as u64, timeout_ms as i64 as u64, 0, 0)?;
        Ok(res as c_int)
    }

    /// is_verbose - check if verbose logging is enabled
    fn is_verbose(&self) -> bool;

    /// is_deterministic - check if running in deterministic sandbox mode
    fn is_deterministic(&self) -> bool {
        false
    }

    /// emulate_rdtsc - check if a SIGSEGV at current RIP is caused by rdtsc/rdtscp/cpuid and emulate it
    fn emulate_rdtsc(&mut self, _proc: &CapturedProcess) -> bool {
        false
    }
}


#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct PollFd<Fd> {
    pub fd: Option<Fd>,
    pub raw_fd: c_int,
    pub events: i16,
    pub revents: i16,
}


