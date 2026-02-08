use crate::linux::Linux;
use libc::{c_int, c_void, ssize_t, mode_t, off_t};
use std::ffi::CString;

pub struct Passthru;

impl Linux for Passthru {
    fn write(&mut self, fd: c_int, buf: &[u8]) -> ssize_t {
        unsafe {
            let res = libc::write(fd, buf.as_ptr() as *const c_void, buf.len());
            println!("write({}, {:?}, {}) = {}", fd, String::from_utf8_lossy(buf), buf.len(), res);
            res
        }
    }

    fn read(&mut self, fd: c_int, count: usize) -> Vec<u8> {
        unsafe {
            let mut buf = vec![0u8; count];
            let res = libc::read(fd, buf.as_mut_ptr() as *mut c_void, count);
            if res > 0 {
                buf.truncate(res as usize);
                println!("read({}, ..., {}) = {}", fd, count, res);
                buf
            } else {
                println!("read({}, ..., {}) = {}", fd, count, res);
                Vec::new()
            }
        }
    }

    fn open(&mut self, pathname: &str, flags: c_int, mode: mode_t) -> c_int {
        unsafe {
            let c_path = CString::new(pathname).unwrap();
            let res = libc::open(c_path.as_ptr(), flags, mode as c_int);
            println!("open({:?}, {}, {}) = {}", pathname, flags, mode, res);
            res
        }
    }

    fn openat(&mut self, dirfd: c_int, pathname: &str, flags: c_int, mode: mode_t) -> c_int {
        unsafe {
            let c_path = CString::new(pathname).unwrap();
            let res = libc::openat(dirfd, c_path.as_ptr(), flags, mode as c_int);
            println!("openat({}, {:?}, {}, {}) = {}", dirfd, pathname, flags, mode, res);
            res
        }
    }

    fn close(&mut self, fd: c_int) -> c_int {
        unsafe {
            let res = libc::close(fd);
            println!("close({}) = {}", fd, res);
            res
        }
    }

    fn fstat(&mut self, fd: c_int) -> c_int {
        unsafe {
            let mut stat_buf: libc::stat = std::mem::zeroed();
            let res = libc::fstat(fd, &mut stat_buf);
            println!("fstat({}, ...) = {}", fd, res);
            res
        }
    }

    fn newfstatat(&mut self, dirfd: c_int, pathname: &str, flags: c_int) -> c_int {
        unsafe {
            let c_path = CString::new(pathname).unwrap();
            let mut stat_buf: libc::stat = std::mem::zeroed();
            let res = libc::fstatat(dirfd, c_path.as_ptr(), &mut stat_buf, flags);
            println!("newfstatat({}, {:?}, ..., {}) = {}", dirfd, pathname, flags, res);
            res
        }
    }

    fn mmap(&mut self, addr: *mut c_void, length: usize, prot: c_int, flags: c_int, fd: c_int, offset: off_t) -> *mut c_void {
        unsafe {
            let res = libc::mmap(addr, length, prot, flags, fd, offset);
            println!("mmap({:?}, {}, {}, {}, {}, {}) = {:?}", addr, length, prot, flags, fd, offset, res);
            res
        }
    }

    fn munmap(&mut self, addr: *mut c_void, length: usize) -> c_int {
        unsafe {
            let res = libc::munmap(addr, length);
            println!("munmap({:?}, {}) = {}", addr, length, res);
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
            if res == 0 {
                addr
            } else {
                -1isize as *mut c_void
            }
        }
    }

    fn clock_gettime(&mut self, clk_id: libc::clockid_t) -> c_int {
        unsafe {
            let mut tp: libc::timespec = std::mem::zeroed();
            let res = libc::clock_gettime(clk_id, &mut tp);
            println!("clock_gettime({}, ...) = {}", clk_id, res);
            res
        }
    }
}
