use libc::{c_int, c_void, mode_t, off_t};

pub trait Linux {
    /// write - write to a file descriptor
    ///
    /// write() writes up to count bytes from the buffer starting at buf to the file referred to by the file descriptor fd.
    fn write(&mut self, fd: c_int, buf: &[u8]) -> nix::Result<usize>;

    /// read - read from a file descriptor
    ///
    /// read() attempts to read up to count bytes from file descriptor fd into the buffer starting at buf.
    fn read(&mut self, fd: c_int, count: usize) -> nix::Result<Vec<u8>>;

    /// open, openat, creat - open and possibly create a file
    ///
    /// The open() system call opens the file specified by pathname. If the specified file does not exist, it may optionally (if O_CREAT is specified in flags) be created by open().
    fn open(&mut self, pathname: &str, flags: c_int, mode: mode_t) -> nix::Result<c_int>;

    /// openat - open and possibly create a file relative to a directory file descriptor
    fn openat(&mut self, dirfd: c_int, pathname: &str, flags: c_int, mode: mode_t) -> nix::Result<c_int>;

    /// close - close a file descriptor
    ///
    /// close() closes a file descriptor, so that it no longer refers to any file and may be reused.
    fn close(&mut self, fd: c_int) -> nix::Result<c_int>;

    /// stat, fstat, lstat, fstatat - get file status
    ///
    /// These functions return information about a file, in the buffer pointed to by statbuf.
    fn fstat(&mut self, fd: c_int) -> nix::Result<c_int>;

    /// newfstatat - get file status relative to a directory file descriptor
    fn newfstatat(&mut self, dirfd: c_int, pathname: &str, flags: c_int) -> nix::Result<c_int>;

    /// mmap, munmap - map or unmap files or devices into memory
    ///
    /// mmap() creates a new mapping in the virtual address space of the calling process.
    fn mmap(&mut self, addr: *mut c_void, length: usize, prot: c_int, flags: c_int, fd: c_int, offset: off_t) -> nix::Result<*mut c_void>;

    /// munmap - unmap a file or device from memory
    ///
    /// The munmap() system call deletes the mappings for the specified address range.
    fn munmap(&mut self, addr: *mut c_void, length: usize) -> nix::Result<c_int>;

    /// _exit, _Exit - terminate the calling process
    ///
    /// The function _exit() terminates the calling process "immediately".
    fn exit(&mut self, status: c_int) -> nix::Result<()>;

    /// exit_group - exit all threads in a process
    ///
    /// This system call is equivalent to _exit(2) except that it terminates not only the calling thread, but all threads in the calling process's thread group.
    fn exit_group(&mut self, status: c_int) -> nix::Result<()>;

    /// brk, sbrk - change data segment size
    ///
    /// brk() and sbrk() change the location of the program break, which defines the end of the process's data segment.
    fn brk(&mut self, addr: *mut c_void) -> nix::Result<*mut c_void>;

    /// clock_getres, clock_gettime, clock_settime - clock and timer functions
    ///
    /// The function clock_getres() finds the resolution (precision) of the specified clock clk_id, and, if res is non-NULL, stores it in the struct timespec pointed to by res.
    /// The functions clock_gettime() and clock_settime() retrieve and set the time of the specified clock clk_id.
    fn clock_gettime(&mut self, clk_id: libc::clockid_t) -> nix::Result<c_int>;

    /// fork - create a child process
    ///
    /// fork() creates a new process by duplicating the calling process.
    fn fork(&mut self) -> nix::Result<nix::unistd::Pid>;

    /// vfork - create a child process and block parent
    ///
    /// vfork() differs from fork(2) in that the calling thread is suspended until the child terminates (either normally, by calling _exit(2), or abnormally, after delivery of a fatal signal), or it makes a call to execve(2).
    fn vfork(&mut self) -> nix::Result<nix::unistd::Pid>;

    /// clone, __clone2, clone3 - create a child process
    ///
    /// These system calls create a new ("child") process, in a manner similar to fork(2).
    fn clone(&mut self, flags: c_int) -> nix::Result<nix::unistd::Pid>;

    /// socket - create an endpoint for communication
    fn socket(&mut self, domain: c_int, ty: c_int, protocol: c_int) -> nix::Result<c_int>;

    /// bind - bind a name to a socket
    fn bind(&mut self, fd: c_int, addr: *const libc::sockaddr, len: libc::socklen_t) -> nix::Result<c_int>;

    /// listen - listen for connections on a socket
    fn listen(&mut self, fd: c_int, backlog: c_int) -> nix::Result<c_int>;

    /// accept - accept a connection on a socket
    fn accept(&mut self, fd: c_int, addr: *mut libc::sockaddr, len: *mut libc::socklen_t) -> nix::Result<c_int>;

    /// accept4 - accept a connection on a socket
    fn accept4(&mut self, fd: c_int, addr: *mut libc::sockaddr, len: *mut libc::socklen_t, flags: c_int) -> nix::Result<c_int>;

    /// connect - initiate a connection on a socket
    fn connect(&mut self, fd: c_int, addr: *const libc::sockaddr, len: libc::socklen_t) -> nix::Result<c_int>;

    /// setsockopt - set options on sockets
    fn setsockopt(&mut self, fd: c_int, level: c_int, optname: c_int, optval: *const c_void, optlen: libc::socklen_t) -> nix::Result<c_int>;

    /// getsockname - get socket name
    fn getsockname(&mut self, fd: c_int, addr: *mut libc::sockaddr, len: *mut libc::socklen_t) -> nix::Result<c_int>;
}
