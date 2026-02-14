use nix::sys::ptrace;
use nix::sys::wait::waitpid;
use nix::unistd::Pid;
use libc::{c_int, c_void, mode_t, off_t};
use nix::Result;

pub struct CapturedProcess {
    pid: Pid,
}

impl CapturedProcess {
    pub fn new(pid: Pid) -> Self {
        Self { pid }
    }

    pub fn get_regs(&self) -> Result<libc::user_regs_struct> {
        ptrace::getregs(self.pid)
    }

    pub fn set_regs(&self, regs: libc::user_regs_struct) -> Result<()> {
        ptrace::setregs(self.pid, regs)
    }

    pub fn syscall(&self, nr: u64, arg1: u64, arg2: u64, arg3: u64, arg4: u64, arg5: u64, arg6: u64) -> Result<i64> {
        let mut regs = self.get_regs()?;
        regs.rax = nr;
        regs.rdi = arg1;
        regs.rsi = arg2;
        regs.rdx = arg3;
        regs.r10 = arg4;
        regs.r8 = arg5;
        regs.r9 = arg6;
        self.set_regs(regs)?;
        
        ptrace::syscall(self.pid, None)?;
        let status = waitpid(self.pid, None)?;
        if let nix::sys::wait::WaitStatus::Exited(_, _) | nix::sys::wait::WaitStatus::Signaled(_, _, _) = status {
            return Ok(0);
        }
        
        let result_regs = self.get_regs()?;
        if (result_regs.rax as i64) < 0 && (result_regs.rax as i64) > -4096 {
            Err(nix::errno::Errno::from_raw(-(result_regs.rax as i32)))
        } else {
            Ok(result_regs.rax as i64)
        }
    }

    pub fn read_memory(&self, addr: usize, count: usize) -> Vec<u8> {
        let mut data = Vec::with_capacity(count);
        let mut read = 0;
        while read < count {
            let word = ptrace::read(self.pid, (addr + read) as *mut _).unwrap_or(0);
            let to_copy = std::cmp::min(count - read, std::mem::size_of::<libc::c_long>());
            let bytes: [u8; 8] = word.to_ne_bytes();
            data.extend_from_slice(&bytes[..to_copy]);
            read += to_copy;
        }
        data
    }

    pub fn write_memory(&self, addr: usize, bytes: &[u8]) {
        let mut current_addr = addr;
        let mut i = 0;
        while i < bytes.len() {
            let word_addr = (current_addr & !7) as *mut libc::c_void;
            let offset = current_addr & 7;
            
            if let Ok(orig_word) = ptrace::read(self.pid, word_addr) {
                let mut word_bytes = orig_word.to_ne_bytes();
                let mut j = 0;
                while j < 8 - offset && i < bytes.len() {
                    word_bytes[offset + j] = bytes[i];
                    i += 1;
                    j += 1;
                }
                let new_word = i64::from_ne_bytes(word_bytes);
                ptrace::write(self.pid, word_addr, new_word).unwrap_or(());
                current_addr += j;
            } else {
                 break;
            }
        }
    }


    // Syscall wrappers
    pub fn write(&self, fd: c_int, addr: u64, count: usize) -> Result<i64> {
        self.syscall(libc::SYS_write as u64, fd as u64, addr, count as u64, 0, 0, 0)
    }

    pub fn read(&self, fd: c_int, addr: u64, count: usize) -> Result<i64> {
        self.syscall(libc::SYS_read as u64, fd as u64, addr, count as u64, 0, 0, 0)
    }

    pub fn open(&self, addr: u64, flags: c_int, mode: mode_t) -> Result<i64> {
        self.syscall(libc::SYS_open as u64, addr, flags as u64, mode as u64, 0, 0, 0)
    }

    pub fn openat(&self, dirfd: c_int, addr: u64, flags: c_int, mode: mode_t) -> Result<i64> {
        self.syscall(libc::SYS_openat as u64, dirfd as u64, addr, flags as u64, mode as u64, 0, 0)
    }

    pub fn close(&self, fd: c_int) -> Result<i64> {
        self.syscall(libc::SYS_close as u64, fd as u64, 0, 0, 0, 0, 0)
    }

    pub fn fstat(&self, fd: c_int, addr: u64) -> Result<i64> {
        self.syscall(libc::SYS_fstat as u64, fd as u64, addr, 0, 0, 0, 0)
    }

    pub fn newfstatat(&self, dirfd: c_int, addr: u64, statbuf: u64, flags: c_int) -> Result<i64> {
        self.syscall(libc::SYS_newfstatat as u64, dirfd as u64, addr, statbuf, flags as u64, 0, 0)
    }

    pub fn mmap(&self, addr: *mut c_void, length: usize, prot: c_int, flags: c_int, fd: c_int, offset: off_t) -> Result<i64> {
        self.syscall(libc::SYS_mmap as u64, addr as u64, length as u64, prot as u64, flags as u64, fd as u64, offset as u64)
    }

    pub fn munmap(&self, addr: *mut c_void, length: usize) -> Result<i64> {
        self.syscall(libc::SYS_munmap as u64, addr as u64, length as u64, 0, 0, 0, 0)
    }

    pub fn brk(&self, addr: *mut c_void) -> Result<i64> {
        self.syscall(libc::SYS_brk as u64, addr as u64, 0, 0, 0, 0, 0)
    }

    pub fn clock_gettime(&self, clk_id: libc::clockid_t, tp_addr: u64) -> Result<i64> {
        self.syscall(libc::SYS_clock_gettime as u64, clk_id as u64, tp_addr, 0, 0, 0, 0)
    }

    pub fn exit(&self, status: c_int) -> Result<i64> {
        self.syscall(libc::SYS_exit as u64, status as u64, 0, 0, 0, 0, 0)
    }

    pub fn exit_group(&self, status: c_int) -> Result<i64> {
        self.syscall(libc::SYS_exit_group as u64, status as u64, 0, 0, 0, 0, 0)
    }

    pub fn socket(&self, domain: c_int, ty: c_int, protocol: c_int) -> Result<i64> {
        self.syscall(libc::SYS_socket as u64, domain as u64, ty as u64, protocol as u64, 0, 0, 0)
    }

    pub fn bind(&self, fd: c_int, addr: u64, len: libc::socklen_t) -> Result<i64> {
        self.syscall(libc::SYS_bind as u64, fd as u64, addr, len as u64, 0, 0, 0)
    }

    pub fn listen(&self, fd: c_int, backlog: c_int) -> Result<i64> {
        self.syscall(libc::SYS_listen as u64, fd as u64, backlog as u64, 0, 0, 0, 0)
    }

    pub fn accept(&self, fd: c_int, addr: u64, len_addr: u64) -> Result<i64> {
        self.syscall(libc::SYS_accept as u64, fd as u64, addr, len_addr, 0, 0, 0)
    }

    pub fn accept4(&self, fd: c_int, addr: u64, len_addr: u64, flags: c_int) -> Result<i64> {
        self.syscall(libc::SYS_accept4 as u64, fd as u64, addr, len_addr, flags as u64, 0, 0)
    }

    pub fn connect(&self, fd: c_int, addr: u64, len: libc::socklen_t) -> Result<i64> {
        self.syscall(libc::SYS_connect as u64, fd as u64, addr, len as u64, 0, 0, 0)
    }

    pub fn setsockopt(&self, fd: c_int, level: c_int, optname: c_int, optval: u64, optlen: libc::socklen_t) -> Result<i64> {
        self.syscall(libc::SYS_setsockopt as u64, fd as u64, level as u64, optname as u64, optval, optlen as u64, 0)
    }

    pub fn getsockname(&self, fd: c_int, addr: u64, len_addr: u64) -> nix::Result<i64> {
        self.syscall(libc::SYS_getsockname as u64, fd as u64, addr, len_addr, 0, 0, 0)
    }

    pub fn pread(&self, fd: c_int, addr: u64, count: usize, offset: off_t) -> Result<i64> {
        self.syscall(libc::SYS_pread64 as u64, fd as u64, addr, count as u64, offset as u64, 0, 0)
    }

    pub fn poll(&self, fds_addr: u64, nfds: libc::nfds_t, timeout: c_int) -> Result<i64> {
        self.syscall(libc::SYS_poll as u64, fds_addr, nfds as u64, timeout as u64, 0, 0, 0)
    }

    pub fn sendto(&self, fd: c_int, buf_addr: u64, len: usize, flags: c_int, dest_addr: u64, addrlen: libc::socklen_t) -> Result<i64> {
        self.syscall(libc::SYS_sendto as u64, fd as u64, buf_addr, len as u64, flags as u64, dest_addr, addrlen as u64)
    }

    pub fn recvfrom(&self, fd: c_int, buf_addr: u64, len: usize, flags: c_int, src_addr: u64, addrlen: u64) -> Result<i64> {
        self.syscall(libc::SYS_recvfrom as u64, fd as u64, buf_addr, len as u64, flags as u64, src_addr, addrlen)
    }

    pub fn fcntl(&self, fd: c_int, cmd: c_int, arg: libc::c_ulong) -> Result<i64> {
        self.syscall(libc::SYS_fcntl as u64, fd as u64, cmd as u64, arg as u64, 0, 0, 0)
    }

    pub fn lseek(&self, fd: c_int, offset: off_t, whence: c_int) -> Result<i64> {
        self.syscall(libc::SYS_lseek as u64, fd as u64, offset as u64, whence as u64, 0, 0, 0)
    }

    pub fn unlink(&self, addr: u64) -> Result<i64> {
        self.syscall(libc::SYS_unlink as u64, addr, 0, 0, 0, 0, 0)
    }

    pub fn pwrite(&self, fd: c_int, addr: u64, count: usize, offset: off_t) -> Result<i64> {
        self.syscall(libc::SYS_pwrite64 as u64, fd as u64, addr, count as u64, offset as u64, 0, 0)
    }

    pub fn fsync(&self, fd: c_int) -> Result<i64> {
        self.syscall(libc::SYS_fsync as u64, fd as u64, 0, 0, 0, 0, 0)
    }

    pub fn fdatasync(&self, fd: c_int) -> Result<i64> {
        self.syscall(libc::SYS_fdatasync as u64, fd as u64, 0, 0, 0, 0, 0)
    }

    pub fn getcwd(&self, buf: u64, size: usize) -> Result<i64> {
        self.syscall(libc::SYS_getcwd as u64, buf, size as u64, 0, 0, 0, 0)
    }

    pub fn getpid(&self) -> Result<i64> {
        self.syscall(libc::SYS_getpid as u64, 0, 0, 0, 0, 0, 0)
    }

    pub fn getuid(&self) -> Result<i64> {
        self.syscall(libc::SYS_getuid as u64, 0, 0, 0, 0, 0, 0)
    }

    pub fn geteuid(&self) -> Result<i64> {
        self.syscall(libc::SYS_geteuid as u64, 0, 0, 0, 0, 0, 0)
    }

    pub fn getgid(&self) -> Result<i64> {
        self.syscall(libc::SYS_getgid as u64, 0, 0, 0, 0, 0, 0)
    }

    pub fn getegid(&self) -> Result<i64> {
        self.syscall(libc::SYS_getegid as u64, 0, 0, 0, 0, 0, 0)
    }

    pub fn getrandom(&self, addr: u64, count: usize, flags: c_int) -> Result<i64> {
        self.syscall(libc::SYS_getrandom as u64, addr, count as u64, flags as u64, 0, 0, 0)
    }

    pub fn gettimeofday(&self, tv_addr: u64, tz_addr: u64) -> Result<i64> {
        self.syscall(libc::SYS_gettimeofday as u64, tv_addr, tz_addr, 0, 0, 0, 0)
    }

    pub fn getppid(&self) -> Result<i64> {
        self.syscall(libc::SYS_getppid as u64, 0, 0, 0, 0, 0, 0)
    }

    pub fn getpgrp(&self) -> Result<i64> {
        self.syscall(libc::SYS_getpgrp as u64, 0, 0, 0, 0, 0, 0)
    }

    pub fn uname(&self, addr: u64) -> Result<i64> {
        self.syscall(libc::SYS_uname as u64, addr, 0, 0, 0, 0, 0)
    }

    pub fn sysinfo(&self, addr: u64) -> Result<i64> {
        self.syscall(libc::SYS_sysinfo as u64, addr, 0, 0, 0, 0, 0)
    }

    pub fn times(&self, addr: u64) -> Result<i64> {
        self.syscall(libc::SYS_times as u64, addr, 0, 0, 0, 0, 0)
    }

    pub fn writev(&self, fd: c_int, iov: u64, iovcnt: c_int) -> Result<i64> {
        self.syscall(libc::SYS_writev as u64, fd as u64, iov, iovcnt as u64, 0, 0, 0)
    }
}
