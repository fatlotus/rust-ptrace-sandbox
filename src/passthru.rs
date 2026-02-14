use crate::linux::{Linux, PollFd};
use crate::captured::CapturedProcess;
use libc::{c_int, c_void, mode_t, off_t};

pub struct PassthruFd(pub c_int);

impl std::os::unix::io::AsRawFd for PassthruFd {
    fn as_raw_fd(&self) -> c_int {
        self.0
    }
}

pub struct Passthru {
    pub verbose: bool,
}

impl Passthru {
    pub fn new(verbose: bool) -> Self {
        Self { verbose }
    }
}

impl Default for Passthru {
    fn default() -> Self {
        Self { verbose: false }
    }
}

impl Linux<PassthruFd> for Passthru {
    fn default_fds(&mut self) -> (PassthruFd, PassthruFd, PassthruFd) {
        (PassthruFd(0), PassthruFd(1), PassthruFd(2))
    }
    
    fn dup_fd(&mut self, fd: &PassthruFd) -> PassthruFd {
        PassthruFd(fd.0)
    }

    fn write(&mut self, proc: &CapturedProcess, fd: &mut PassthruFd, buf: &[u8]) -> nix::Result<usize> {
        let regs = proc.get_regs()?;
        let res = proc.write(fd.0, regs.rsi, buf.len())?;
        if self.verbose {
            println!("write({}, {:?}, {}) = {}", fd.0, String::from_utf8_lossy(buf), buf.len(), res);
        }
        Ok(res as usize)
    }

    fn read(&mut self, proc: &CapturedProcess, fd: &mut PassthruFd, count: usize) -> nix::Result<Vec<u8>> {
        let regs = proc.get_regs()?;
        let res = proc.read(fd.0, regs.rsi, count)?;
        let buf = proc.read_memory(regs.rsi as usize, res as usize);
        if self.verbose {
            println!("read({}, ..., {}) = {}", fd.0, count, res);
        }
        Ok(buf)
    }

    fn open(&mut self, proc: &CapturedProcess, pathname: &str, flags: c_int, mode: mode_t) -> nix::Result<PassthruFd> {
        let regs = proc.get_regs()?;
        let res = proc.open(regs.rdi, flags, mode)?;
        if self.verbose {
            println!("open({:?}, {}, {}) = {}", pathname, flags, mode, res);
        }
        Ok(PassthruFd(res as c_int))
    }

    fn openat(&mut self, proc: &CapturedProcess, dirfd: Option<&mut PassthruFd>, pathname: &str, flags: c_int, mode: mode_t) -> nix::Result<PassthruFd> {
        let regs = proc.get_regs()?;
        let dirfd_val = dirfd.map(|fd| fd.0).unwrap_or(libc::AT_FDCWD);
        let res = proc.openat(dirfd_val, regs.rsi, flags, mode)?;
        if self.verbose {
            println!("openat({}, {:?}, {}, {}) = {}", dirfd_val, pathname, flags, mode, res);
        }
        Ok(PassthruFd(res as c_int))
    }

    fn close(&mut self, proc: &CapturedProcess, fd: PassthruFd) -> nix::Result<c_int> {
        let res = proc.close(fd.0)?;
        if self.verbose {
            println!("close({}) = {}", fd.0, res);
        }
        Ok(res as c_int)
    }

    fn fstat(&mut self, proc: &CapturedProcess, fd: &mut PassthruFd) -> nix::Result<c_int> {
        let regs = proc.get_regs()?;
        let res = proc.fstat(fd.0, regs.rsi)?;
        if self.verbose {
            println!("fstat({}, ...) = {}", fd.0, res);
        }
        Ok(res as c_int)
    }

    fn newfstatat(&mut self, proc: &CapturedProcess, dirfd: Option<&mut PassthruFd>, pathname: &str, flags: c_int) -> nix::Result<c_int> {
        let regs = proc.get_regs()?;
        let dirfd_val = dirfd.map(|fd| fd.0).unwrap_or(libc::AT_FDCWD);
        let res = proc.newfstatat(dirfd_val, regs.rsi, regs.rdx, flags)?;
        if self.verbose {
            println!("newfstatat({}, {:?}, ..., {}) = {}", dirfd_val, pathname, flags, res);
        }
        Ok(res as c_int)
    }

    fn mmap(&mut self, proc: &CapturedProcess, addr: *mut c_void, length: usize, prot: c_int, flags: c_int, fd: Option<&mut PassthruFd>, offset: off_t) -> nix::Result<*mut c_void> {
        let fd_val = fd.map(|f| f.0).unwrap_or(-1);
        let res = proc.mmap(addr, length, prot, flags, fd_val, offset)?;
        if self.verbose {
            println!("mmap({:?}, {}, {}, {}, {}, {}) = {:?}", addr, length, prot, flags, fd_val, offset, res as *mut c_void);
        }
        Ok(res as *mut c_void)
    }

    fn munmap(&mut self, proc: &CapturedProcess, addr: *mut c_void, length: usize) -> nix::Result<c_int> {
        let res = proc.munmap(addr, length)?;
        if self.verbose {
            println!("munmap({:?}, {}) = {}", addr, length, res);
        }
        Ok(res as c_int)
    }

    fn exit(&mut self, proc: &CapturedProcess, status: c_int) -> nix::Result<()> {
        if self.verbose {
            println!("exit({})", status);
        }
        let _ = proc.exit(status);
        Ok(())
    }

    fn exit_group(&mut self, proc: &CapturedProcess, status: c_int) -> nix::Result<()> {
        if self.verbose {
            println!("exit_group({})", status);
        }
        let _ = proc.exit_group(status);
        Ok(())
    }

    fn brk(&mut self, proc: &CapturedProcess, addr: *mut c_void) -> nix::Result<*mut c_void> {
        let res = proc.brk(addr)?;
        if self.verbose {
            println!("brk({:?}) = {}", addr, res);
        }
        Ok(res as *mut c_void)
    }

    fn clock_gettime(&mut self, proc: &CapturedProcess, clk_id: libc::clockid_t) -> nix::Result<c_int> {
        let regs = proc.get_regs()?;
        let res = proc.clock_gettime(clk_id, regs.rsi)?;
        if self.verbose {
            println!("clock_gettime({}, ...) = {}", clk_id, res);
        }
        Ok(res as c_int)
    }

    fn fork(&mut self, _proc: &CapturedProcess) -> nix::Result<(nix::unistd::Pid, Box<dyn Linux<PassthruFd> + Send>)> {
        if self.verbose {
            println!("fork() = ?");
        }
        Ok((nix::unistd::Pid::from_raw(0), Box::new(Passthru::new(self.verbose))))
    }

    fn vfork(&mut self, _proc: &CapturedProcess) -> nix::Result<(nix::unistd::Pid, Box<dyn Linux<PassthruFd> + Send>)> {
        if self.verbose {
            println!("vfork() = ?");
        }
        Ok((nix::unistd::Pid::from_raw(0), Box::new(Passthru::new(self.verbose))))
    }

    fn clone(&mut self, _proc: &CapturedProcess, flags: i32) -> nix::Result<(nix::unistd::Pid, Box<dyn Linux<PassthruFd> + Send>)> {
        if self.verbose {
            println!("clone(flags={}) = ?", flags);
        }
        Ok((nix::unistd::Pid::from_raw(0), Box::new(Passthru::new(self.verbose))))
    }

    fn socket(&mut self, proc: &CapturedProcess, domain: c_int, ty: c_int, protocol: c_int) -> nix::Result<PassthruFd> {
        let res = proc.socket(domain, ty, protocol)?;
        if self.verbose {
            println!("socket({}, {}, {}) = {}", domain, ty, protocol, res);
        }
        Ok(PassthruFd(res as c_int))
    }

    fn bind(&mut self, proc: &CapturedProcess, fd: &mut PassthruFd, addr: *const libc::sockaddr, len: libc::socklen_t) -> nix::Result<c_int> {
        let regs = proc.get_regs()?;
        let res = proc.bind(fd.0, regs.rsi, len)?;
        if self.verbose {
            println!("bind({}, {:?}, {}) = {}", fd.0, addr, len, res);
        }
        Ok(res as c_int)
    }

    fn listen(&mut self, proc: &CapturedProcess, fd: &mut PassthruFd, backlog: c_int) -> nix::Result<c_int> {
        let res = proc.listen(fd.0, backlog)?;
        if self.verbose {
            println!("listen({}, {}) = {}", fd.0, backlog, res);
        }
        Ok(res as c_int)
    }

    fn accept(&mut self, proc: &CapturedProcess, fd: &mut PassthruFd, addr: *mut libc::sockaddr, len: *mut libc::socklen_t) -> nix::Result<PassthruFd> {
        let regs = proc.get_regs()?;
        let res = proc.accept(fd.0, regs.rsi, regs.rdx)?;
        if self.verbose {
            println!("accept({}, {:?}, {:?}) = {}", fd.0, addr, len, res);
        }
        Ok(PassthruFd(res as c_int))
    }

    fn accept4(&mut self, proc: &CapturedProcess, fd: &mut PassthruFd, addr: *mut libc::sockaddr, len: *mut libc::socklen_t, flags: c_int) -> nix::Result<PassthruFd> {
        let regs = proc.get_regs()?;
        let res = proc.accept4(fd.0, regs.rsi, regs.rdx, flags)?;
        if self.verbose {
            println!("accept4({}, {:?}, {:?}, {}) = {}", fd.0, addr, len, flags, res);
        }
        Ok(PassthruFd(res as c_int))
    }

    fn connect(&mut self, proc: &CapturedProcess, fd: &mut PassthruFd, addr: *const libc::sockaddr, len: libc::socklen_t) -> nix::Result<c_int> {
        let regs = proc.get_regs()?;
        let res = proc.connect(fd.0, regs.rsi, len)?;
        if self.verbose {
            println!("connect({}, {:?}, {}) = {}", fd.0, addr, len, res);
        }
        Ok(res as c_int)
    }

    fn setsockopt(&mut self, proc: &CapturedProcess, fd: &mut PassthruFd, level: c_int, optname: c_int, optval: *const c_void, optlen: libc::socklen_t) -> nix::Result<c_int> {
        let regs = proc.get_regs()?;
        let res = proc.setsockopt(fd.0, level, optname, regs.r10, optlen)?;
        if self.verbose {
            println!("setsockopt({}, {}, {}, {:?}, {}) = {}", fd.0, level, optname, optval, optlen, res);
        }
        Ok(res as c_int)
    }

    fn getsockname(&mut self, proc: &CapturedProcess, fd: &mut PassthruFd, addr: *mut libc::sockaddr, len: *mut libc::socklen_t) -> nix::Result<c_int> {
        let regs = proc.get_regs()?;
        let res = proc.getsockname(fd.0, regs.rsi, regs.rdx)?;
        if self.verbose {
            println!("getsockname({}, {:?}, {:?}) = {}", fd.0, addr, len, res);
        }
        Ok(res as c_int)
    }

    fn pread(&mut self, proc: &CapturedProcess, fd: &mut PassthruFd, count: usize, offset: off_t) -> nix::Result<Vec<u8>> {
        let regs = proc.get_regs()?;
        let res = proc.pread(fd.0, regs.rsi, count, offset)?;
        let buf = proc.read_memory(regs.rsi as usize, res as usize);
        if self.verbose {
            println!("pread({}, ..., {}, {}) = {}", fd.0, count, offset, res);
        }
        Ok(buf)
    }

    fn poll(&mut self, proc: &CapturedProcess, fds: &mut [PollFd<PassthruFd>], timeout: c_int) -> nix::Result<c_int> {
        let regs = proc.get_regs()?;
        let res = proc.poll(regs.rdi, fds.len() as libc::nfds_t, timeout)?;
        
        // Update fds from guest memory to ensure revents are captured
        let addr = regs.rdi as usize;
        let pollfd_size = std::mem::size_of::<libc::pollfd>();
        for (i, fd) in fds.iter_mut().enumerate() {
            let fd_addr = addr + i * pollfd_size;
            // revents is at offset 6 (4 bytes fd + 2 bytes events)
            let revents_bytes = proc.read_memory(fd_addr + 6, 2);
            if revents_bytes.len() == 2 {
                fd.revents = i16::from_ne_bytes([revents_bytes[0], revents_bytes[1]]);
            }
        }
        if self.verbose {
            println!("poll(..., {}, {}) = {}", fds.len(), timeout, res);
        }
        Ok(res as c_int)
    }

    fn sendto(&mut self, proc: &CapturedProcess, fd: &mut PassthruFd, buf: &[u8], flags: c_int, _addr: *const libc::sockaddr, _len: libc::socklen_t) -> nix::Result<usize> {
        let regs = proc.get_regs()?;
        let res = proc.sendto(fd.0, regs.rsi, buf.len(), flags, regs.r8, regs.r9 as libc::socklen_t)?;
        if self.verbose {
            println!("sendto({}, ..., {}, ...) = {}", fd.0, buf.len(), res);
        }
        Ok(res as usize)
    }

    fn recvfrom(&mut self, proc: &CapturedProcess, fd: &mut PassthruFd, count: usize, flags: c_int, _addr: *mut libc::sockaddr, _len: *mut libc::socklen_t) -> nix::Result<Vec<u8>> {
        let regs = proc.get_regs()?;
        let res = proc.recvfrom(fd.0, regs.rsi, count, flags, regs.r8, regs.r9)?;
        let buf = proc.read_memory(regs.rsi as usize, res as usize);
        if self.verbose {
            println!("recvfrom({}, ..., {}) = {}", fd.0, count, res);
        }
        Ok(buf)
    }

    fn fcntl(&mut self, proc: &CapturedProcess, fd: &mut PassthruFd, cmd: c_int, arg: libc::c_ulong) -> nix::Result<c_int> {
        let res = proc.fcntl(fd.0, cmd, arg)?;
        if self.verbose {
            println!("fcntl({}, {}, {}) = {}", fd.0, cmd, arg, res);
        }
        Ok(res as c_int)
    }

    fn lseek(&mut self, proc: &CapturedProcess, fd: &mut PassthruFd, offset: off_t, whence: c_int) -> nix::Result<off_t> {
        let res = proc.lseek(fd.0, offset, whence)?;
        if self.verbose {
            println!("lseek({}, {}, {}) = {}", fd.0, offset, whence, res);
        }
        Ok(res as off_t)
    }

    fn unlink(&mut self, proc: &CapturedProcess, pathname: &str) -> nix::Result<c_int> {
        let regs = proc.get_regs()?;
        let res = proc.unlink(regs.rdi as u64)?;
        if self.verbose {
            println!("unlink({:?}) = {}", pathname, res);
        }
        Ok(res as c_int)
    }

    fn pwrite(&mut self, proc: &CapturedProcess, fd: &mut PassthruFd, buf: &[u8], offset: off_t) -> nix::Result<usize> {
        let regs = proc.get_regs()?;
        let res = proc.pwrite(fd.0, regs.rsi, buf.len(), offset)?;
        if self.verbose {
            println!("pwrite({}, ..., {}) = {}", fd.0, buf.len(), res);
        }
        Ok(res as usize)
    }

    fn fsync(&mut self, proc: &CapturedProcess, fd: &mut PassthruFd) -> nix::Result<c_int> {
        let res = proc.fsync(fd.0)?;
        if self.verbose {
            println!("fsync({}) = {}", fd.0, res);
        }
        Ok(res as c_int)
    }

    fn fdatasync(&mut self, proc: &CapturedProcess, fd: &mut PassthruFd) -> nix::Result<c_int> {
        let res = proc.fdatasync(fd.0)?;
        if self.verbose {
            println!("fdatasync({}) = {}", fd.0, res);
        }
        Ok(res as c_int)
    }

    fn getcwd(&mut self, proc: &CapturedProcess, size: usize) -> nix::Result<Vec<u8>> {
        let regs = proc.get_regs()?;
        let res = proc.getcwd(regs.rdi, size)?;
        if self.verbose {
            println!("getcwd({:?}...) = {}", regs.rdi, res);
        }
        if res > 0 {
             Ok(proc.read_memory(regs.rdi as usize, res as usize))
        } else {
             Ok(Vec::new())
        }
    }

    fn getpid(&mut self, proc: &CapturedProcess) -> nix::Result<c_int> {
        let res = proc.getpid()?;
        if self.verbose {
            println!("getpid() = {}", res);
        }
        Ok(res as c_int)
    }

    fn getuid(&mut self, proc: &CapturedProcess) -> nix::Result<c_int> {
        let res = proc.getuid()?;
        if self.verbose {
            println!("getuid() = {}", res);
        }
        Ok(res as c_int)
    }

    fn geteuid(&mut self, proc: &CapturedProcess) -> nix::Result<c_int> {
        let res = proc.geteuid()?;
        if self.verbose {
            println!("geteuid() = {}", res);
        }
        Ok(res as c_int)
    }

    fn getrandom(&mut self, proc: &CapturedProcess, buf: &mut [u8], flags: c_int) -> nix::Result<usize> {
        let regs = proc.get_regs()?;
        let res = proc.getrandom(regs.rdi, buf.len(), flags)?;
        let read_buf = proc.read_memory(regs.rdi as usize, res as usize);
        buf[..res as usize].copy_from_slice(&read_buf);
        if self.verbose {
            println!("getrandom(..., {}, {}) = {}", buf.len(), flags, res);
        }
        Ok(res as usize)
    }

    fn is_verbose(&self) -> bool {
        self.verbose
    }
}
