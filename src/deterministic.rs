use crate::linux::{Linux, PollFd};
use crate::captured::CapturedProcess;
use crate::passthru::{Passthru, PassthruFd};
use libc::{c_int, c_void, mode_t, off_t};

pub struct Deterministic {
    passthru: Passthru,
}

impl Deterministic {
    pub fn new(verbose: bool) -> Self {
        Self {
            passthru: Passthru::new(verbose),
        }
    }

    fn patch_stat(&self, proc: &CapturedProcess, addr: usize) {
        // struct stat on x86_64:
        // atime (72..88), mtime (88..104), ctime (104..120)
        
        let mut bytes = proc.read_memory(addr, 120); // Only need up to ctime
        if bytes.len() < 120 { return; }
        
        // Zero out timestamps (atim 72..88, mtim 88..104, ctim 104..120)
        for i in 72..120 { bytes[i] = 0; }
        
        proc.write_memory(addr, &bytes);
        if self.passthru.verbose {
            println!("path_stat({:#x}) (DETERMINISTIC)", addr);
        }
    }
}

impl Linux<PassthruFd> for Deterministic {
    fn default_fds(&mut self) -> (PassthruFd, PassthruFd, PassthruFd) {
        self.passthru.default_fds()
    }

    fn dup_fd(&mut self, fd: &PassthruFd) -> PassthruFd {
        self.passthru.dup_fd(fd)
    }

    fn write(&mut self, proc: &CapturedProcess, fd: &mut PassthruFd, buf: &[u8]) -> nix::Result<usize> {
        self.passthru.write(proc, fd, buf)
    }

    fn read(&mut self, proc: &CapturedProcess, fd: &mut PassthruFd, count: usize) -> nix::Result<Vec<u8>> {
        self.passthru.read(proc, fd, count)
    }

    fn open(&mut self, proc: &CapturedProcess, pathname: &str, flags: c_int, mode: mode_t) -> nix::Result<PassthruFd> {
        self.passthru.open(proc, pathname, flags, mode)
    }

    fn openat(&mut self, proc: &CapturedProcess, dirfd: Option<&mut PassthruFd>, pathname: &str, flags: c_int, mode: mode_t) -> nix::Result<PassthruFd> {
        self.passthru.openat(proc, dirfd, pathname, flags, mode)
    }

    fn close(&mut self, proc: &CapturedProcess, fd: PassthruFd) -> nix::Result<c_int> {
        self.passthru.close(proc, fd)
    }

    fn fstat(&mut self, proc: &CapturedProcess, fd: &mut PassthruFd) -> nix::Result<c_int> {
        let regs = proc.get_regs()?;
        let res = self.passthru.fstat(proc, fd)?;
        if res == 0 {
            self.patch_stat(proc, regs.rsi as usize);
        }
        Ok(res)
    }

    fn newfstatat(&mut self, proc: &CapturedProcess, dirfd: Option<&mut PassthruFd>, pathname: &str, flags: c_int) -> nix::Result<c_int> {
        let regs = proc.get_regs()?;
        let res = self.passthru.newfstatat(proc, dirfd, pathname, flags)?;
        if res == 0 {
            self.patch_stat(proc, regs.rdx as usize);
        }
        Ok(res)
    }

    fn mmap(&mut self, proc: &CapturedProcess, addr: *mut c_void, length: usize, prot: c_int, flags: c_int, fd: Option<&mut PassthruFd>, offset: off_t) -> nix::Result<*mut c_void> {
        self.passthru.mmap(proc, addr, length, prot, flags, fd, offset)
    }

    fn munmap(&mut self, proc: &CapturedProcess, addr: *mut c_void, length: usize) -> nix::Result<c_int> {
        self.passthru.munmap(proc, addr, length)
    }

    fn exit(&mut self, proc: &CapturedProcess, status: c_int) -> nix::Result<()> {
        self.passthru.exit(proc, status)
    }

    fn exit_group(&mut self, proc: &CapturedProcess, status: c_int) -> nix::Result<()> {
        self.passthru.exit_group(proc, status)
    }

    fn brk(&mut self, proc: &CapturedProcess, addr: *mut c_void) -> nix::Result<*mut c_void> {
        self.passthru.brk(proc, addr)
    }

    fn clock_gettime(&mut self, proc: &CapturedProcess, clk_id: libc::clockid_t) -> nix::Result<c_int> {
        let regs = proc.get_regs()?;
        let tp_addr = regs.rsi as usize;
        
        // Return a fixed timestamp: 2000-01-01 00:00:00 UTC
        // Unix timestamp for 2000-01-01 00:00:00 is 946684800
        let tv_sec: i64 = 946684800;
        let tv_nsec: i64 = 0;
        
        let mut bytes = Vec::with_capacity(16);
        bytes.extend_from_slice(&tv_sec.to_ne_bytes());
        bytes.extend_from_slice(&tv_nsec.to_ne_bytes());
        
        proc.write_memory(tp_addr, &bytes);
        
        if self.passthru.verbose {
            println!("clock_gettime({}, ...) = 0 (DETERMINISTIC)", clk_id);
        }
        Ok(0)
    }

    fn fork(&mut self, proc: &CapturedProcess) -> nix::Result<(nix::unistd::Pid, Box<dyn Linux<PassthruFd> + Send>)> {
        let (pid, _) = self.passthru.fork(proc)?;
        Ok((pid, Box::new(Deterministic::new(self.passthru.verbose))))
    }

    fn vfork(&mut self, proc: &CapturedProcess) -> nix::Result<(nix::unistd::Pid, Box<dyn Linux<PassthruFd> + Send>)> {
        let (pid, _) = self.passthru.vfork(proc)?;
        Ok((pid, Box::new(Deterministic::new(self.passthru.verbose))))
    }

    fn clone(&mut self, proc: &CapturedProcess, flags: c_int) -> nix::Result<(nix::unistd::Pid, Box<dyn Linux<PassthruFd> + Send>)> {
        let (pid, _) = self.passthru.clone(proc, flags)?;
        Ok((pid, Box::new(Deterministic::new(self.passthru.verbose))))
    }

    fn socket(&mut self, proc: &CapturedProcess, domain: c_int, ty: c_int, protocol: c_int) -> nix::Result<PassthruFd> {
        self.passthru.socket(proc, domain, ty, protocol)
    }

    fn bind(&mut self, proc: &CapturedProcess, fd: &mut PassthruFd, addr: *const libc::sockaddr, len: libc::socklen_t) -> nix::Result<c_int> {
        self.passthru.bind(proc, fd, addr, len)
    }

    fn listen(&mut self, proc: &CapturedProcess, fd: &mut PassthruFd, backlog: c_int) -> nix::Result<c_int> {
        self.passthru.listen(proc, fd, backlog)
    }

    fn accept(&mut self, proc: &CapturedProcess, fd: &mut PassthruFd, addr: *mut libc::sockaddr, len: *mut libc::socklen_t) -> nix::Result<PassthruFd> {
        self.passthru.accept(proc, fd, addr, len)
    }

    fn accept4(&mut self, proc: &CapturedProcess, fd: &mut PassthruFd, addr: *mut libc::sockaddr, len: *mut libc::socklen_t, flags: c_int) -> nix::Result<PassthruFd> {
        self.passthru.accept4(proc, fd, addr, len, flags)
    }

    fn connect(&mut self, proc: &CapturedProcess, fd: &mut PassthruFd, addr: *const libc::sockaddr, len: libc::socklen_t) -> nix::Result<c_int> {
        self.passthru.connect(proc, fd, addr, len)
    }

    fn setsockopt(&mut self, proc: &CapturedProcess, fd: &mut PassthruFd, level: c_int, optname: c_int, optval: *const c_void, optlen: libc::socklen_t) -> nix::Result<c_int> {
        self.passthru.setsockopt(proc, fd, level, optname, optval, optlen)
    }

    fn getsockname(&mut self, proc: &CapturedProcess, fd: &mut PassthruFd, addr: *mut libc::sockaddr, len: *mut libc::socklen_t) -> nix::Result<c_int> {
        self.passthru.getsockname(proc, fd, addr, len)
    }

    fn pread(&mut self, proc: &CapturedProcess, fd: &mut PassthruFd, count: usize, offset: off_t) -> nix::Result<Vec<u8>> {
        self.passthru.pread(proc, fd, count, offset)
    }

    fn poll(&mut self, proc: &CapturedProcess, fds: &mut [PollFd<PassthruFd>], timeout: c_int) -> nix::Result<c_int> {
        self.passthru.poll(proc, fds, timeout)
    }

    fn sendto(&mut self, proc: &CapturedProcess, fd: &mut PassthruFd, buf: &[u8], flags: c_int, addr: *const libc::sockaddr, len: libc::socklen_t) -> nix::Result<usize> {
        self.passthru.sendto(proc, fd, buf, flags, addr, len)
    }

    fn recvfrom(&mut self, proc: &CapturedProcess, fd: &mut PassthruFd, count: usize, flags: c_int, addr: *mut libc::sockaddr, len: *mut libc::socklen_t) -> nix::Result<Vec<u8>> {
        self.passthru.recvfrom(proc, fd, count, flags, addr, len)
    }

    fn fcntl(&mut self, proc: &CapturedProcess, fd: &mut PassthruFd, cmd: c_int, arg: libc::c_ulong) -> nix::Result<c_int> {
        self.passthru.fcntl(proc, fd, cmd, arg)
    }

    fn lseek(&mut self, proc: &CapturedProcess, fd: &mut PassthruFd, offset: off_t, whence: c_int) -> nix::Result<off_t> {
        self.passthru.lseek(proc, fd, offset, whence)
    }

    fn unlink(&mut self, proc: &CapturedProcess, pathname: &str) -> nix::Result<c_int> {
        self.passthru.unlink(proc, pathname)
    }

    fn pwrite(&mut self, proc: &CapturedProcess, fd: &mut PassthruFd, buf: &[u8], offset: off_t) -> nix::Result<usize> {
        self.passthru.pwrite(proc, fd, buf, offset)
    }

    fn fsync(&mut self, proc: &CapturedProcess, fd: &mut PassthruFd) -> nix::Result<c_int> {
        self.passthru.fsync(proc, fd)
    }

    fn fdatasync(&mut self, proc: &CapturedProcess, fd: &mut PassthruFd) -> nix::Result<c_int> {
        self.passthru.fdatasync(proc, fd)
    }

    fn getcwd(&mut self, proc: &CapturedProcess, size: usize) -> nix::Result<Vec<u8>> {
        self.passthru.getcwd(proc, size)
    }

    fn getpid(&mut self, _proc: &CapturedProcess) -> nix::Result<c_int> {
        if self.passthru.verbose {
            println!("getpid() = 1234 (DETERMINISTIC)");
        }
        Ok(1234)
    }

    fn getuid(&mut self, _proc: &CapturedProcess) -> nix::Result<c_int> {
        if self.passthru.verbose {
            println!("getuid() = 1000 (DETERMINISTIC)");
        }
        Ok(1000)
    }

    fn geteuid(&mut self, _proc: &CapturedProcess) -> nix::Result<c_int> {
        if self.passthru.verbose {
            println!("geteuid() = 1000 (DETERMINISTIC)");
        }
        Ok(1000)
    }

    fn getrandom(&mut self, _proc: &CapturedProcess, buf: &mut [u8], _flags: c_int) -> nix::Result<usize> {
        for i in 0..buf.len() {
            buf[i] = 0x42;
        }
        if self.passthru.verbose {
            println!("getrandom(..., {}, ...) = {} (DETERMINISTIC)", buf.len(), buf.len());
        }
        Ok(buf.len())
    }

    fn gettimeofday(&mut self, proc: &CapturedProcess) -> nix::Result<c_int> {
        let regs = proc.get_regs()?;
        let tv_addr = regs.rdi as usize;
        
        // Return a fixed timestamp: 2000-01-01 00:00:00 UTC
        let tv_sec: i64 = 946684800;
        let tv_usec: i64 = 0;
        
        let mut bytes = Vec::with_capacity(16);
        bytes.extend_from_slice(&tv_sec.to_ne_bytes());
        bytes.extend_from_slice(&tv_usec.to_ne_bytes());
        
        proc.write_memory(tv_addr, &bytes);
        
        if self.passthru.verbose {
            println!("gettimeofday(..., ...) = 0 (DETERMINISTIC)");
        }
        Ok(0)
    }

    fn getppid(&mut self, _proc: &CapturedProcess) -> nix::Result<c_int> {
        if self.passthru.verbose {
            println!("getppid() = 1 (DETERMINISTIC)");
        }
        Ok(1)
    }

    fn getpgrp(&mut self, _proc: &CapturedProcess) -> nix::Result<c_int> {
        if self.passthru.verbose {
            println!("getpgrp() = 1 (DETERMINISTIC)");
        }
        Ok(1)
    }

    fn uname(&mut self, proc: &CapturedProcess) -> nix::Result<c_int> {
        self.passthru.uname(proc)
    }

    fn sysinfo(&mut self, proc: &CapturedProcess) -> nix::Result<c_int> {
        self.passthru.sysinfo(proc)
    }

    fn getgid(&mut self, _proc: &CapturedProcess) -> nix::Result<c_int> {
        if self.passthru.verbose {
            println!("getgid() = 1000 (DETERMINISTIC)");
        }
        Ok(1000)
    }

    fn getegid(&mut self, _proc: &CapturedProcess) -> nix::Result<c_int> {
        if self.passthru.verbose {
            println!("getegid() = 1000 (DETERMINISTIC)");
        }
        Ok(1000)
    }

    fn times(&mut self, proc: &CapturedProcess) -> nix::Result<c_int> {
        let regs = proc.get_regs()?;
        let addr = regs.rdi as usize;
        let res = self.passthru.times(proc)?;
        if res != -1 {
            // Zero out the tms struct (4 fields of 8 bytes)
            let buf = vec![0u8; 32];
            proc.write_memory(addr, &buf);
        }
        if self.passthru.verbose {
            println!("times(...) = 0 (DETERMINISTIC)");
        }
        Ok(0) // Return 0 ticks
    }

    fn writev(&mut self, proc: &CapturedProcess, fd: &mut PassthruFd, iov: u64, iovcnt: i32) -> nix::Result<usize> {
        self.passthru.writev(proc, fd, iov, iovcnt)
    }

    fn is_verbose(&self) -> bool {
        self.passthru.verbose
    }
}
