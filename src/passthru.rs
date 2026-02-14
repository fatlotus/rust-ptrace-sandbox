use crate::linux::{Linux, PollFd};
use crate::captured::CapturedProcess;
use libc::{c_int, c_void, mode_t, off_t};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PassthruFd(pub c_int);

impl From<c_int> for PassthruFd {
    fn from(fd: c_int) -> Self {
        PassthruFd(fd)
    }
}

pub struct Passthru;

impl Linux<PassthruFd> for Passthru {
    fn write(&mut self, proc: &CapturedProcess, fd: PassthruFd, buf: &[u8]) -> nix::Result<usize> {
        let regs = proc.get_regs()?;
        let res = proc.write(fd.0, regs.rsi, buf.len())?;
        println!("write({}, {:?}, {}) = {}", fd.0, String::from_utf8_lossy(buf), buf.len(), res);
        Ok(res as usize)
    }

    fn read(&mut self, proc: &CapturedProcess, fd: PassthruFd, count: usize) -> nix::Result<Vec<u8>> {
        let regs = proc.get_regs()?;
        let res = proc.read(fd.0, regs.rsi, count)?;
        let buf = proc.read_memory(regs.rsi as usize, res as usize);
        println!("read({}, ..., {}) = {}", fd.0, count, res);
        Ok(buf)
    }

    fn open(&mut self, proc: &CapturedProcess, pathname: &str, flags: c_int, mode: mode_t) -> nix::Result<PassthruFd> {
        let regs = proc.get_regs()?;
        let res = proc.open(regs.rdi, flags, mode)?;
        println!("open({:?}, {}, {}) = {}", pathname, flags, mode, res);
        Ok(PassthruFd(res as c_int))
    }

    fn openat(&mut self, proc: &CapturedProcess, dirfd: PassthruFd, pathname: &str, flags: c_int, mode: mode_t) -> nix::Result<PassthruFd> {
        let regs = proc.get_regs()?;
        let res = proc.openat(dirfd.0, regs.rsi, flags, mode)?;
        println!("openat({}, {:?}, {}, {}) = {}", dirfd.0, pathname, flags, mode, res);
        Ok(PassthruFd(res as c_int))
    }

    fn close(&mut self, proc: &CapturedProcess, fd: PassthruFd) -> nix::Result<c_int> {
        let res = proc.close(fd.0)?;
        println!("close({}) = {}", fd.0, res);
        Ok(res as c_int)
    }

    fn fstat(&mut self, proc: &CapturedProcess, fd: PassthruFd) -> nix::Result<c_int> {
        let regs = proc.get_regs()?;
        let res = proc.fstat(fd.0, regs.rsi)?;
        println!("fstat({}, ...) = {}", fd.0, res);
        Ok(res as c_int)
    }

    fn newfstatat(&mut self, proc: &CapturedProcess, dirfd: PassthruFd, pathname: &str, flags: c_int) -> nix::Result<c_int> {
        let regs = proc.get_regs()?;
        let res = proc.newfstatat(dirfd.0, regs.rsi, regs.rdx, flags)?;
        println!("newfstatat({}, {:?}, ..., {}) = {}", dirfd.0, pathname, flags, res);
        Ok(res as c_int)
    }

    fn mmap(&mut self, proc: &CapturedProcess, addr: *mut c_void, length: usize, prot: c_int, flags: c_int, fd: PassthruFd, offset: off_t) -> nix::Result<*mut c_void> {
        let res = proc.mmap(addr, length, prot, flags, fd.0, offset)?;
        println!("mmap({:?}, {}, {}, {}, {}, {}) = {:?}", addr, length, prot, flags, fd.0, offset, res as *mut c_void);
        Ok(res as *mut c_void)
    }

    fn munmap(&mut self, proc: &CapturedProcess, addr: *mut c_void, length: usize) -> nix::Result<c_int> {
        let res = proc.munmap(addr, length)?;
        println!("munmap({:?}, {}) = {}", addr, length, res);
        Ok(res as c_int)
    }

    fn exit(&mut self, proc: &CapturedProcess, status: c_int) -> nix::Result<()> {
        println!("exit({})", status);
        let _ = proc.exit(status);
        Ok(())
    }

    fn exit_group(&mut self, proc: &CapturedProcess, status: c_int) -> nix::Result<()> {
        println!("exit_group({})", status);
        let _ = proc.exit_group(status);
        Ok(())
    }

    fn brk(&mut self, proc: &CapturedProcess, addr: *mut c_void) -> nix::Result<*mut c_void> {
        let res = proc.brk(addr)?;
        println!("brk({:?}) = {}", addr, res);
        Ok(res as *mut c_void)
    }

    fn clock_gettime(&mut self, proc: &CapturedProcess, clk_id: libc::clockid_t) -> nix::Result<c_int> {
        let regs = proc.get_regs()?;
        let res = proc.clock_gettime(clk_id, regs.rsi)?;
        println!("clock_gettime({}, ...) = {}", clk_id, res);
        Ok(res as c_int)
    }

    fn fork(&mut self, _proc: &CapturedProcess) -> nix::Result<(nix::unistd::Pid, Box<dyn Linux<PassthruFd> + Send>)> {
        println!("fork() = ?");
        Ok((nix::unistd::Pid::from_raw(0), Box::new(Passthru)))
    }

    fn vfork(&mut self, _proc: &CapturedProcess) -> nix::Result<(nix::unistd::Pid, Box<dyn Linux<PassthruFd> + Send>)> {
        println!("vfork() = ?");
        Ok((nix::unistd::Pid::from_raw(0), Box::new(Passthru)))
    }

    fn clone(&mut self, _proc: &CapturedProcess, flags: i32) -> nix::Result<(nix::unistd::Pid, Box<dyn Linux<PassthruFd> + Send>)> {
        println!("clone(flags={}) = ?", flags);
        Ok((nix::unistd::Pid::from_raw(0), Box::new(Passthru)))
    }

    fn socket(&mut self, proc: &CapturedProcess, domain: c_int, ty: c_int, protocol: c_int) -> nix::Result<PassthruFd> {
        let res = proc.socket(domain, ty, protocol)?;
        println!("socket({}, {}, {}) = {}", domain, ty, protocol, res);
        Ok(PassthruFd(res as c_int))
    }

    fn bind(&mut self, proc: &CapturedProcess, fd: PassthruFd, addr: *const libc::sockaddr, len: libc::socklen_t) -> nix::Result<c_int> {
        let regs = proc.get_regs()?;
        let res = proc.bind(fd.0, regs.rsi, len)?;
        println!("bind({}, {:?}, {}) = {}", fd.0, addr, len, res);
        Ok(res as c_int)
    }

    fn listen(&mut self, proc: &CapturedProcess, fd: PassthruFd, backlog: c_int) -> nix::Result<c_int> {
        let res = proc.listen(fd.0, backlog)?;
        println!("listen({}, {}) = {}", fd.0, backlog, res);
        Ok(res as c_int)
    }

    fn accept(&mut self, proc: &CapturedProcess, fd: PassthruFd, addr: *mut libc::sockaddr, len: *mut libc::socklen_t) -> nix::Result<PassthruFd> {
        let regs = proc.get_regs()?;
        let res = proc.accept(fd.0, regs.rsi, regs.rdx)?;
        println!("accept({}, {:?}, {:?}) = {}", fd.0, addr, len, res);
        Ok(PassthruFd(res as c_int))
    }

    fn accept4(&mut self, proc: &CapturedProcess, fd: PassthruFd, addr: *mut libc::sockaddr, len: *mut libc::socklen_t, flags: c_int) -> nix::Result<PassthruFd> {
        let regs = proc.get_regs()?;
        let res = proc.accept4(fd.0, regs.rsi, regs.rdx, flags)?;
        println!("accept4({}, {:?}, {:?}, {}) = {}", fd.0, addr, len, flags, res);
        Ok(PassthruFd(res as c_int))
    }

    fn connect(&mut self, proc: &CapturedProcess, fd: PassthruFd, addr: *const libc::sockaddr, len: libc::socklen_t) -> nix::Result<c_int> {
        let regs = proc.get_regs()?;
        let res = proc.connect(fd.0, regs.rsi, len)?;
        println!("connect({}, {:?}, {}) = {}", fd.0, addr, len, res);
        Ok(res as c_int)
    }

    fn setsockopt(&mut self, proc: &CapturedProcess, fd: PassthruFd, level: c_int, optname: c_int, optval: *const c_void, optlen: libc::socklen_t) -> nix::Result<c_int> {
        let regs = proc.get_regs()?;
        let res = proc.setsockopt(fd.0, level, optname, regs.r10, optlen)?;
        println!("setsockopt({}, {}, {}, {:?}, {}) = {}", fd.0, level, optname, optval, optlen, res);
        Ok(res as c_int)
    }

    fn getsockname(&mut self, proc: &CapturedProcess, fd: PassthruFd, addr: *mut libc::sockaddr, len: *mut libc::socklen_t) -> nix::Result<c_int> {
        let regs = proc.get_regs()?;
        let res = proc.getsockname(fd.0, regs.rsi, regs.rdx)?;
        println!("getsockname({}, {:?}, {:?}) = {}", fd.0, addr, len, res);
        Ok(res as c_int)
    }

    fn pread(&mut self, proc: &CapturedProcess, fd: PassthruFd, count: usize, offset: off_t) -> nix::Result<Vec<u8>> {
        let regs = proc.get_regs()?;
        let res = proc.pread(fd.0, regs.rsi, count, offset)?;
        let buf = proc.read_memory(regs.rsi as usize, res as usize);
        println!("pread({}, ..., {}, {}) = {}", fd.0, count, offset, res);
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
        println!("poll(..., {}, {}) = {}", fds.len(), timeout, res);
        Ok(res as c_int)
    }

    fn sendto(&mut self, proc: &CapturedProcess, fd: PassthruFd, buf: &[u8], flags: c_int, _addr: *const libc::sockaddr, _len: libc::socklen_t) -> nix::Result<usize> {
        let regs = proc.get_regs()?;
        let res = proc.sendto(fd.0, regs.rsi, buf.len(), flags, regs.r8, regs.r9 as libc::socklen_t)?;
        println!("sendto({}, ..., {}, ...) = {}", fd.0, buf.len(), res);
        Ok(res as usize)
    }

    fn recvfrom(&mut self, proc: &CapturedProcess, fd: PassthruFd, count: usize, flags: c_int, _addr: *mut libc::sockaddr, _len: *mut libc::socklen_t) -> nix::Result<Vec<u8>> {
        let regs = proc.get_regs()?;
        let res = proc.recvfrom(fd.0, regs.rsi, count, flags, regs.r8, regs.r9)?;
        let buf = proc.read_memory(regs.rsi as usize, res as usize);
        println!("recvfrom({}, ..., {}) = {}", fd.0, count, res);
        Ok(buf)
    }

    fn fcntl(&mut self, proc: &CapturedProcess, fd: PassthruFd, cmd: c_int, arg: libc::c_ulong) -> nix::Result<c_int> {
        let res = proc.fcntl(fd.0, cmd, arg)?;
        println!("fcntl({}, {}, {}) = {}", fd.0, cmd, arg, res);
        Ok(res as c_int)
    }


}


