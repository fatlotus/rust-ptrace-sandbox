use crate::linux::Linux;
use libc::{c_int, c_void, ssize_t};

pub struct Passthru;

impl Linux for Passthru {
    fn write(&mut self, fd: c_int, buf: &[u8]) -> ssize_t {
        unsafe {
            let res = libc::write(fd, buf.as_ptr() as *const c_void, buf.len());
            println!("write({}, {:?}, {}) = {}", fd, String::from_utf8_lossy(buf), buf.len(), res);
            res
        }
    }

    fn exit(&mut self, status: c_int) {
        println!("exit({})", status);
        unsafe { libc::exit(status) }
    }

    fn exit_group(&mut self, status: c_int) {
        println!("exit_group({})", status);
        unsafe { libc::syscall(libc::SYS_exit_group, status); }
    }

    fn brk(&mut self, addr: *mut c_void) -> *mut c_void {
        unsafe {
            let res = libc::brk(addr);
            println!("brk({:?}) = {}", addr, res);
            // brk is a bit weird, it returns 0 on success (or new brk) depending on the glibc wrapper vs syscall
            // The raw syscall returns the new program break.
            // For now, let's just use the libc wrapper.
            if res == 0 {
                addr // This is not strictly correct for "get current brk" but enough for passthru trace
            } else {
                -1isize as *mut c_void
            }
        }
    }
}
