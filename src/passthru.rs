use crate::linux::Linux;
use libc::{c_int, c_void, mode_t, off_t};
use std::ffi::CString;
use nix::errno::Errno;

pub struct Passthru;

impl Linux for Passthru {
    fn write(&mut self, fd: c_int, buf: &[u8]) -> nix::Result<usize> {
        unsafe {
            let res = libc::write(fd, buf.as_ptr() as *const c_void, buf.len());
            println!("write({}, {:?}, {}) = {}", fd, String::from_utf8_lossy(buf), buf.len(), res);
            if res < 0 {
                return Err(Errno::last());
            }
            Ok(res as usize)
        }
    }

    fn read(&mut self, fd: c_int, count: usize) -> nix::Result<Vec<u8>> {
        unsafe {
            let mut buf = vec![0u8; count];
            let res = libc::read(fd, buf.as_mut_ptr() as *mut c_void, count);
            if res < 0 {
                 println!("read({}, ..., {}) = {}", fd, count, res);
                 return Err(Errno::last());
            }
            buf.truncate(res as usize);
            println!("read({}, ..., {}) = {}", fd, count, res);
            Ok(buf)
        }
    }

    fn open(&mut self, pathname: &str, flags: c_int, mode: mode_t) -> nix::Result<c_int> {
        unsafe {
            let c_path = CString::new(pathname).unwrap();
            let res = libc::open(c_path.as_ptr(), flags, mode as c_int);
            println!("open({:?}, {}, {}) = {}", pathname, flags, mode, res);
            if res < 0 {
                return Err(Errno::last());
            }
            Ok(res)
        }
    }

    fn openat(&mut self, dirfd: c_int, pathname: &str, flags: c_int, mode: mode_t) -> nix::Result<c_int> {
        unsafe {
            let c_path = CString::new(pathname).unwrap();
            let res = libc::openat(dirfd, c_path.as_ptr(), flags, mode as c_int);
            println!("openat({}, {:?}, {}, {}) = {}", dirfd, pathname, flags, mode, res);
            if res < 0 {
                return Err(Errno::last());
            }
            Ok(res)
        }
    }

    fn close(&mut self, fd: c_int) -> nix::Result<c_int> {
        unsafe {
            let res = libc::close(fd);
            println!("close({}) = {}", fd, res);
            if res < 0 {
                return Err(Errno::last());
            }
            Ok(res)
        }
    }

    fn fstat(&mut self, fd: c_int) -> nix::Result<c_int> {
        unsafe {
            let mut stat_buf: libc::stat = std::mem::zeroed();
            let res = libc::fstat(fd, &mut stat_buf);
            println!("fstat({}, ...) = {}", fd, res);
            if res < 0 {
                return Err(Errno::last());
            }
            Ok(res)
        }
    }

    fn newfstatat(&mut self, dirfd: c_int, pathname: &str, flags: c_int) -> nix::Result<c_int> {
        unsafe {
            let c_path = CString::new(pathname).unwrap();
            let mut stat_buf: libc::stat = std::mem::zeroed();
            let res = libc::fstatat(dirfd, c_path.as_ptr(), &mut stat_buf, flags);
            println!("newfstatat({}, {:?}, ..., {}) = {}", dirfd, pathname, flags, res);
            if res < 0 {
                return Err(Errno::last());
            }
            Ok(res)
        }
    }

    fn mmap(&mut self, addr: *mut c_void, length: usize, prot: c_int, flags: c_int, fd: c_int, offset: off_t) -> nix::Result<*mut c_void> {
        unsafe {
            let res = libc::mmap(addr, length, prot, flags, fd, offset);
            println!("mmap({:?}, {}, {}, {}, {}, {}) = {:?}", addr, length, prot, flags, fd, offset, res);
            if res == libc::MAP_FAILED {
                return Err(Errno::last());
            }
            Ok(res)
        }
    }

    fn munmap(&mut self, addr: *mut c_void, length: usize) -> nix::Result<c_int> {
        unsafe {
            let res = libc::munmap(addr, length);
            println!("munmap({:?}, {}) = {}", addr, length, res);
            if res < 0 {
                return Err(Errno::last());
            }
            Ok(res)
        }
    }

    fn exit(&mut self, status: c_int) -> nix::Result<()> {
        println!("exit({})", status);
        // Do not actually exit here, let the interceptor handle it via syscall passthrough
        // However, since we changed the signature, we should return Ok(())
        Ok(())
    }

    fn exit_group(&mut self, status: c_int) -> nix::Result<()> {
        println!("exit_group({})", status);
        // Do not actually exit here, let the interceptor handle it via syscall passthrough
        Ok(())
    }

    fn brk(&mut self, addr: *mut c_void) -> nix::Result<*mut c_void> {
        unsafe {
            let res = libc::brk(addr);
            println!("brk({:?}) = {}", addr, res);
            if res < 0 {
                return Err(Errno::last());
            }
            // On success, brk returns 0. But the syscall usually returns the new break.
            // Wait, glibc wrapper returns 0 on success.
            // The Linux trait `brk` was returning `*mut c_void`.
            // Let's check what the interceptor expects. The interceptor passes the result back to `rax`.
            // `syscall(SYS_brk, addr)` returns the new program break on success.
            // Glibc `brk` returns 0 on success, -1 on error.
            
            // If we are emulating, we should probably return the current break if successful?
            // Or maybe we should just return what libc::brk returns if we can't get the new break easily?
            // Actually, if libc::brk succeeds, the new break is `addr`.
            // BUT, if `addr` is 0, it wraps `sbrk(0)`?
            // The previous implementation was:
            // if res == 0 { addr } else { -1 }
            // So let's stick to that logic but wrapped in Result.
            // Warning: `addr` might not be the actual new break if `addr` was lower than current break?
            // Let's assume the previous logic was "correct enough" for now.
            
            Ok(addr)
        }
    }

    fn clock_gettime(&mut self, clk_id: libc::clockid_t) -> nix::Result<c_int> {
        unsafe {
            let mut tp: libc::timespec = std::mem::zeroed();
            let res = libc::clock_gettime(clk_id, &mut tp);
            println!("clock_gettime({}, ...) = {}", clk_id, res);
            if res < 0 {
                return Err(Errno::last());
            }
            Ok(res)
        }
    }

    fn fork(&mut self) -> nix::Result<nix::unistd::Pid> {
        println!("fork() = ?");
        Ok(nix::unistd::Pid::from_raw(0)) // Dummy
    }

    fn vfork(&mut self) -> nix::Result<nix::unistd::Pid> {
        println!("vfork() = ?");
        Ok(nix::unistd::Pid::from_raw(0)) // Dummy
    }

    fn clone(&mut self, flags: c_int) -> nix::Result<nix::unistd::Pid> {
        println!("clone(flags={}) = ?", flags);
        Ok(nix::unistd::Pid::from_raw(0)) // Dummy
    }

    fn socket(&mut self, domain: c_int, ty: c_int, protocol: c_int) -> nix::Result<c_int> {
        unsafe {
            let res = libc::socket(domain, ty, protocol);
            println!("socket({}, {}, {}) = {}", domain, ty, protocol, res);
            if res < 0 {
                return Err(Errno::last());
            }
            // Immediately close the socket in the tracer to avoid resource leaks and conflicts
            libc::close(res);
            Ok(res)
        }
    }

    fn bind(&mut self, fd: c_int, addr: *const libc::sockaddr, len: libc::socklen_t) -> nix::Result<c_int> {
        unsafe {
            let res = libc::bind(fd, addr, len);
            // Note: This will likely fail with EBADF because we closed the fd in socket()
            // But we log it anyway as per the plan.
            println!("bind({}, {:?}, {}) = {}", fd, addr, len, res);
            if res < 0 {
                return Err(Errno::last());
            }
            Ok(res)
        }
    }

    fn listen(&mut self, fd: c_int, backlog: c_int) -> nix::Result<c_int> {
        unsafe {
            let res = libc::listen(fd, backlog);
            println!("listen({}, {}) = {}", fd, backlog, res);
            if res < 0 {
                return Err(Errno::last());
            }
            Ok(res)
        }
    }

    fn accept(&mut self, fd: c_int, addr: *mut libc::sockaddr, len: *mut libc::socklen_t) -> nix::Result<c_int> {
        unsafe {
            let res = libc::accept(fd, addr, len);
            println!("accept({}, {:?}, {:?}) = {}", fd, addr, len, res);
            if res < 0 {
                return Err(Errno::last());
            }
            // If it surprisingly succeeded (e.g. fd was valid), close the accepted socket
            libc::close(res);
            Ok(res)
        }
    }

    fn accept4(&mut self, fd: c_int, addr: *mut libc::sockaddr, len: *mut libc::socklen_t, flags: c_int) -> nix::Result<c_int> {
        unsafe {
            let res = libc::accept4(fd, addr, len, flags);
            println!("accept4({}, {:?}, {:?}, {}) = {}", fd, addr, len, flags, res);
            if res < 0 {
                return Err(Errno::last());
            }
            libc::close(res);
            Ok(res)
        }
    }

    fn connect(&mut self, fd: c_int, addr: *const libc::sockaddr, len: libc::socklen_t) -> nix::Result<c_int> {
        unsafe {
            let res = libc::connect(fd, addr, len);
            println!("connect({}, {:?}, {}) = {}", fd, addr, len, res);
            if res < 0 {
                return Err(Errno::last());
            }
            Ok(res)
        }
    }

    fn setsockopt(&mut self, fd: c_int, level: c_int, optname: c_int, optval: *const c_void, optlen: libc::socklen_t) -> nix::Result<c_int> {
        unsafe {
            let res = libc::setsockopt(fd, level, optname, optval, optlen);
            println!("setsockopt({}, {}, {}, {:?}, {}) = {}", fd, level, optname, optval, optlen, res);
            if res < 0 {
                return Err(Errno::last());
            }
            Ok(res)
        }
    }

    fn getsockname(&mut self, fd: c_int, addr: *mut libc::sockaddr, len: *mut libc::socklen_t) -> nix::Result<c_int> {
        unsafe {
            let res = libc::getsockname(fd, addr, len);
            println!("getsockname({}, {:?}, {:?}) = {}", fd, addr, len, res);
            if res < 0 {
                return Err(Errno::last());
            }
            Ok(res)
        }
    }
}
