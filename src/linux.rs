use libc::{c_int, c_void, ssize_t};

pub trait Linux {
    fn write(&mut self, fd: c_int, buf: &[u8]) -> ssize_t;
    fn exit(&mut self, status: c_int);
    fn exit_group(&mut self, status: c_int);
    fn brk(&mut self, addr: *mut c_void) -> *mut c_void;
}
