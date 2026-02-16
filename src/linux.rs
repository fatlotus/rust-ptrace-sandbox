use libc::{c_int, c_void, mode_t, off_t};
use crate::captured::CapturedProcess;

pub trait Linux<Fd> {
    /// Get default file descriptors for stdin, stdout, stderr
    fn default_fds(&mut self) -> (Fd, Fd, Fd);
    
    /// Create a new Fd object for the same underlying file descriptor.
    /// Used for fork/clone where child inherits file descriptors.
    fn dup_fd(&mut self, fd: &Fd) -> Fd;

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

    /// stat, fstat, lstat, fstatat - get file status
    ///
    /// These functions return information about a file, in the buffer pointed to by statbuf.
    fn fstat(&mut self, proc: &CapturedProcess, fd: &mut Fd) -> nix::Result<c_int>;

    /// newfstatat - get file status relative to a directory file descriptor
    /// dirfd: None means AT_FDCWD
    fn newfstatat(&mut self, proc: &CapturedProcess, dirfd: Option<&mut Fd>, pathname: &str, flags: c_int) -> nix::Result<c_int>;

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
    fn clone(&mut self, proc: &CapturedProcess, flags: c_int) -> nix::Result<(nix::unistd::Pid, Box<dyn Linux<Fd> + Send>)>;

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

    /// getuid - get user identification
    fn getuid(&mut self, proc: &CapturedProcess) -> nix::Result<c_int>;

    /// geteuid - get effective user identification
    fn geteuid(&mut self, proc: &CapturedProcess) -> nix::Result<c_int>;

    /// getrandom - obtain a series of random bytes
    fn getrandom(&mut self, proc: &CapturedProcess, buf: &mut [u8], flags: i32) -> nix::Result<usize>;

    /// gettimeofday - get time
    fn gettimeofday(&mut self, proc: &CapturedProcess) -> nix::Result<c_int>;

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

    /// futex - fast user-space locking
    fn futex(&mut self, proc: &CapturedProcess, uaddr: *mut u32, op: c_int, val: u32, timeout: *const libc::timespec, uaddr2: *mut u32, val3: u32) -> nix::Result<c_int>;

    /// is_verbose - check if verbose logging is enabled
    fn is_verbose(&self) -> bool;
}

#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct PollFd<Fd> {
    pub fd: Fd,
    pub events: i16,
    pub revents: i16,
}


