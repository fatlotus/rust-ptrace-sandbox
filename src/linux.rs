use libc::{c_int, c_void, ssize_t, mode_t, off_t};

pub trait Linux {
    fn write(&mut self, fd: c_int, buf: &[u8]) -> ssize_t;
    fn read(&mut self, fd: c_int, count: usize) -> Vec<u8>;
    fn open(&mut self, pathname: &str, flags: c_int, mode: mode_t) -> c_int;
    fn openat(&mut self, dirfd: c_int, pathname: &str, flags: c_int, mode: mode_t) -> c_int;
    fn close(&mut self, fd: c_int) -> c_int;
    fn fstat(&mut self, fd: c_int) -> c_int;
    fn newfstatat(&mut self, dirfd: c_int, pathname: &str, flags: c_int) -> c_int;
    fn mmap(&mut self, addr: *mut c_void, length: usize, prot: c_int, flags: c_int, fd: c_int, offset: off_t) -> *mut c_void;
    fn munmap(&mut self, addr: *mut c_void, length: usize) -> c_int;
    fn exit(&mut self, status: c_int);
    fn exit_group(&mut self, status: c_int);
    fn brk(&mut self, addr: *mut c_void) -> *mut c_void;
    fn clock_gettime(&mut self, clk_id: libc::clockid_t) -> c_int;
    fn fork(&mut self) -> nix::unistd::Pid;
    fn vfork(&mut self) -> nix::unistd::Pid;
    fn clone(&mut self, flags: c_int) -> nix::unistd::Pid;
}
