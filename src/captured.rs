use nix::sys::ptrace;
use nix::sys::wait::waitpid;
use nix::unistd::Pid;
use libc::{c_int, c_void, mode_t, off_t};
use nix::Result;

pub trait ArchRegs {
    fn syscall_nr(&self) -> u64;
    fn arg1(&self) -> u64;
    fn arg2(&self) -> u64;
    fn arg3(&self) -> u64;
    fn arg4(&self) -> u64;
    fn arg5(&self) -> u64;
    fn arg6(&self) -> u64;
    fn set_args(&mut self, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64);
    fn ret(&self) -> u64;
    fn set_ret(&mut self, val: u64);
    fn sp(&self) -> u64;
    fn pc(&self) -> u64;
    fn set_pc(&mut self, val: u64);
}

#[cfg(target_arch = "x86_64")]
impl ArchRegs for libc::user_regs_struct {
    fn syscall_nr(&self) -> u64 { self.orig_rax }
    fn arg1(&self) -> u64 { self.rdi }
    fn arg2(&self) -> u64 { self.rsi }
    fn arg3(&self) -> u64 { self.rdx }
    fn arg4(&self) -> u64 { self.r10 }
    fn arg5(&self) -> u64 { self.r8 }
    fn arg6(&self) -> u64 { self.r9 }
    fn set_args(&mut self, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) {
        self.rdi = a1;
        self.rsi = a2;
        self.rdx = a3;
        self.r10 = a4;
        self.r8 = a5;
        self.r9 = a6;
    }
    fn ret(&self) -> u64 { self.rax }
    fn set_ret(&mut self, val: u64) { self.rax = val; }
    fn sp(&self) -> u64 { self.rsp }
    fn pc(&self) -> u64 { self.rip }
    fn set_pc(&mut self, val: u64) { self.rip = val; }
}

#[cfg(target_arch = "aarch64")]
impl ArchRegs for libc::user_regs_struct {
    fn syscall_nr(&self) -> u64 { self.regs[8] }
    fn arg1(&self) -> u64 { self.regs[0] }
    fn arg2(&self) -> u64 { self.regs[1] }
    fn arg3(&self) -> u64 { self.regs[2] }
    fn arg4(&self) -> u64 { self.regs[3] }
    fn arg5(&self) -> u64 { self.regs[4] }
    fn arg6(&self) -> u64 { self.regs[5] }
    fn set_args(&mut self, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) {
        self.regs[0] = a1;
        self.regs[1] = a2;
        self.regs[2] = a3;
        self.regs[3] = a4;
        self.regs[4] = a5;
        self.regs[5] = a6;
    }
    fn ret(&self) -> u64 { self.regs[0] }
    fn set_ret(&mut self, val: u64) { self.regs[0] = val; }
    fn sp(&self) -> u64 { self.sp }
    fn pc(&self) -> u64 { self.pc }
    fn set_pc(&mut self, val: u64) { self.pc = val; }
}

pub struct CapturedProcess {
    pub pid: Pid,
}

impl CapturedProcess {
    pub fn new(pid: Pid) -> Self {
        Self { pid }
    }

    pub fn get_regs(&self) -> Result<libc::user_regs_struct> {
        ptrace::getregs(self.pid)
    }
    
    pub fn is_alive(&self) -> bool {
        match waitpid(self.pid, Some(nix::sys::wait::WaitPidFlag::WNOHANG)) {
            Ok(nix::sys::wait::WaitStatus::StillAlive) => true,
            Ok(nix::sys::wait::WaitStatus::Stopped(_, _)) => true,
            Ok(nix::sys::wait::WaitStatus::PtraceSyscall(_)) => true,
            Ok(nix::sys::wait::WaitStatus::PtraceEvent(_, _, _)) => true,
            _ => false,
        }
    }

    pub fn set_regs(&self, regs: libc::user_regs_struct) -> Result<()> {
        ptrace::setregs(self.pid, regs)
    }

    #[cfg(target_arch = "x86_64")]
    fn set_syscall_regs(&self, regs: &mut libc::user_regs_struct, nr: i32) -> Result<()> {
        regs.orig_rax = nr as i64 as u64;
        regs.rax = nr as i64 as u64;
        self.set_regs(*regs)
    }

    #[cfg(target_arch = "aarch64")]
    fn set_syscall_regs(&self, regs: &mut libc::user_regs_struct, nr: i32) -> Result<()> {
        regs.regs[8] = nr as i64 as u64;
        self.set_regs(*regs)?;
        const NT_ARM_SYSTEM_CALL: libc::c_int = 0x404;
        let mut sysno: libc::c_int = nr;
        let mut iov = libc::iovec {
            iov_base: (&mut sysno as *mut libc::c_int).cast(),
            iov_len: std::mem::size_of::<libc::c_int>(),
        };
        let res = unsafe {
            libc::ptrace(
                libc::PTRACE_SETREGSET,
                libc::pid_t::from(self.pid),
                NT_ARM_SYSTEM_CALL as *mut libc::c_void,
                (&mut iov as *mut libc::iovec).cast::<libc::c_void>(),
            )
        };
        nix::errno::Errno::result(res).map(drop)
    }

    #[cfg(target_arch = "x86_64")]
    fn restore_caller_regs(dst: &mut libc::user_regs_struct, orig: &libc::user_regs_struct, restore_arg1: bool) {
        if restore_arg1 {
            dst.rdi = orig.rdi;
        }
        dst.rsi = orig.rsi;
        dst.rdx = orig.rdx;
        dst.r10 = orig.r10;
        dst.r8 = orig.r8;
        dst.r9 = orig.r9;
        dst.rcx = orig.rcx;
        dst.r11 = orig.r11;
    }

    #[cfg(target_arch = "aarch64")]
    fn restore_caller_regs(dst: &mut libc::user_regs_struct, orig: &libc::user_regs_struct, restore_arg1: bool) {
        if restore_arg1 {
            dst.regs[0] = orig.regs[0];
        }
        dst.regs[1] = orig.regs[1];
        dst.regs[2] = orig.regs[2];
        dst.regs[3] = orig.regs[3];
        dst.regs[4] = orig.regs[4];
        dst.regs[5] = orig.regs[5];
        dst.regs[8] = orig.regs[8];
    }

    pub fn syscall(&self, nr: u64, arg1: u64, arg2: u64, arg3: u64, arg4: u64, arg5: u64, arg6: u64) -> Result<i64> {
        let orig_regs = self.get_regs()?;
        let mut regs = orig_regs;
        regs.set_args(arg1, arg2, arg3, arg4, arg5, arg6);
        self.set_syscall_regs(&mut regs, nr as i32)?;
        
        let mut pending_sig = None;
        let mut in_syscall = true;
        let mut result_regs;
        let mut res;
        loop {
            ptrace::syscall(self.pid, pending_sig.take())?;
            let status = waitpid(self.pid, None)?;
            match status {
                nix::sys::wait::WaitStatus::Exited(_, _) | nix::sys::wait::WaitStatus::Signaled(_, _, _) => {
                    return Ok(0);
                }
                nix::sys::wait::WaitStatus::PtraceSyscall(_) => {
                    if !in_syscall {
                        // Restarted syscall entry stop
                        self.set_syscall_regs(&mut regs, nr as i32)?;
                        in_syscall = true;
                        continue;
                    }
                    in_syscall = false;
                    result_regs = self.get_regs()?;
                    res = result_regs.ret() as i64;
                    if matches!(res, -512 | -513 | -514 | -516) {
                        // Syscall was interrupted by a pending signal (ERESTARTSYS etc.);
                        // let the kernel dequeue the signal and restart the syscall.
                        continue;
                    }
                    break;
                }
                nix::sys::wait::WaitStatus::Stopped(_, sig) => {
                    if sig == nix::sys::signal::Signal::SIGTRAP {
                        // Probably another Ptrace event or just a trap, continue
                        continue;
                    }
                    // If it's another signal, pass it to the child on the next iteration
                    pending_sig = Some(sig);
                }
                _ => {
                    // Unexpected status, try to continue
                    continue;
                }
            }
        }
        if nr != orig_regs.syscall_nr() {
            Self::restore_caller_regs(&mut result_regs, &orig_regs, cfg!(target_arch = "x86_64"));
            let _ = self.set_regs(result_regs);
        }
        if res < 0 && res > -4096 {
            Err(nix::errno::Errno::from_raw(-(res as i32)))
        } else {
            Ok(res)
        }
    }

    pub fn skip_syscall(&self) -> Result<i64> {
        let orig_regs = self.get_regs()?;
        let mut regs = orig_regs;
        self.set_syscall_regs(&mut regs, -1)?;
        
        let mut pending_sig = None;
        loop {
            ptrace::syscall(self.pid, pending_sig.take())?;
            let status = waitpid(self.pid, None)?;
            match status {
                nix::sys::wait::WaitStatus::Exited(_, _) | nix::sys::wait::WaitStatus::Signaled(_, _, _) => {
                    return Ok(0);
                }
                nix::sys::wait::WaitStatus::PtraceSyscall(_) => {
                    break;
                }
                nix::sys::wait::WaitStatus::Stopped(_, sig) => {
                    if sig == nix::sys::signal::Signal::SIGTRAP {
                        continue;
                    }
                    pending_sig = Some(sig);
                }
                _ => continue,
            }
        }
        
        if let Ok(mut current_regs) = self.get_regs() {
            Self::restore_caller_regs(&mut current_regs, &orig_regs, true);
            let _ = self.set_regs(current_regs);
        }
        Ok(0)
    }

    pub fn read_memory(&self, addr: usize, count: usize) -> Vec<u8> {
        let mut data = Vec::with_capacity(std::cmp::min(count, 65536));
        let mut read = 0;
        while read < count {
            let Some(cur_addr) = addr.checked_add(read) else {
                break;
            };
            let word_addr = (cur_addr & !7) as *mut libc::c_void;
            let offset = cur_addr & 7;
            let Ok(word) = ptrace::read(self.pid, word_addr) else {
                break;
            };
            let to_copy = std::cmp::min(count - read, 8 - offset);
            let bytes: [u8; 8] = word.to_ne_bytes();
            data.extend_from_slice(&bytes[offset..offset + to_copy]);
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
        #[cfg(target_arch = "x86_64")]
        {
            self.syscall(libc::SYS_open as u64, addr, flags as u64, mode as u64, 0, 0, 0)
        }
        #[cfg(target_arch = "aarch64")]
        {
            self.openat(libc::AT_FDCWD, addr, flags, mode)
        }
    }

    pub fn openat(&self, dirfd: c_int, addr: u64, flags: c_int, mode: mode_t) -> Result<i64> {
        self.syscall(libc::SYS_openat as u64, dirfd as u64, addr, flags as u64, mode as u64, 0, 0)
    }

    pub fn close(&self, fd: c_int) -> Result<i64> {
        self.syscall(libc::SYS_close as u64, fd as u64, 0, 0, 0, 0, 0)
    }

    pub fn eventfd2(&self, initval: libc::c_uint, flags: c_int) -> Result<i64> {
        self.syscall(libc::SYS_eventfd2 as u64, initval as u64, flags as u64, 0, 0, 0, 0)
    }

    pub fn dup(&self, oldfd: c_int) -> Result<i64> {
        self.syscall(libc::SYS_dup as u64, oldfd as u64, 0, 0, 0, 0, 0)
    }

    pub fn dup2(&self, oldfd: c_int, newfd: c_int) -> Result<i64> {
        #[cfg(target_arch = "x86_64")]
        {
            self.syscall(libc::SYS_dup2 as u64, oldfd as u64, newfd as u64, 0, 0, 0, 0)
        }
        #[cfg(target_arch = "aarch64")]
        {
            self.dup3(oldfd, newfd, 0)
        }
    }

    pub fn dup3(&self, oldfd: c_int, newfd: c_int, flags: c_int) -> Result<i64> {
        self.syscall(libc::SYS_dup3 as u64, oldfd as u64, newfd as u64, flags as u64, 0, 0, 0)
    }

    pub fn stat(&self, addr: u64, statbuf: u64) -> Result<i64> {
        #[cfg(target_arch = "x86_64")]
        {
            self.syscall(libc::SYS_stat as u64, addr, statbuf, 0, 0, 0, 0)
        }
        #[cfg(target_arch = "aarch64")]
        {
            self.newfstatat(libc::AT_FDCWD, addr, statbuf, 0)
        }
    }

    pub fn lstat(&self, addr: u64, statbuf: u64) -> Result<i64> {
        #[cfg(target_arch = "x86_64")]
        {
            self.syscall(libc::SYS_lstat as u64, addr, statbuf, 0, 0, 0, 0)
        }
        #[cfg(target_arch = "aarch64")]
        {
            self.newfstatat(libc::AT_FDCWD, addr, statbuf, libc::AT_SYMLINK_NOFOLLOW)
        }
    }

    pub fn fstat(&self, fd: c_int, addr: u64) -> Result<i64> {
        self.syscall(libc::SYS_fstat as u64, fd as u64, addr, 0, 0, 0, 0)
    }

    pub fn newfstatat(&self, dirfd: c_int, addr: u64, statbuf: u64, flags: c_int) -> Result<i64> {
        self.syscall(libc::SYS_newfstatat as u64, dirfd as u64, addr, statbuf, flags as u64, 0, 0)
    }

    pub fn statx(&self, dirfd: c_int, addr: u64, flags: c_int, mask: libc::c_uint, statxbuf: u64) -> Result<i64> {
        self.syscall(libc::SYS_statx as u64, dirfd as u64, addr, flags as u64, mask as u64, statxbuf, 0)
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

    pub fn poll(&self, fds_addr: u64, nfds: libc::nfds_t, _timeout: c_int) -> Result<i64> {
        #[cfg(target_arch = "x86_64")]
        {
            self.syscall(libc::SYS_poll as u64, fds_addr, nfds as u64, _timeout as u64, 0, 0, 0)
        }
        #[cfg(target_arch = "aarch64")]
        {
            let regs = self.get_regs()?;
            self.syscall(libc::SYS_ppoll as u64, fds_addr, nfds as u64, regs.arg3(), regs.arg4(), regs.arg5(), 0)
        }
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
        #[cfg(target_arch = "x86_64")]
        {
            self.syscall(libc::SYS_unlink as u64, addr, 0, 0, 0, 0, 0)
        }
        #[cfg(target_arch = "aarch64")]
        {
            self.unlinkat(libc::AT_FDCWD, addr, 0)
        }
    }

    pub fn unlinkat(&self, dirfd: c_int, addr: u64, flags: c_int) -> Result<i64> {
        self.syscall(libc::SYS_unlinkat as u64, dirfd as i64 as u64, addr, flags as u64, 0, 0, 0)
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

    pub fn gettid(&self) -> Result<i64> {
        self.syscall(libc::SYS_gettid as u64, 0, 0, 0, 0, 0, 0)
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

    pub fn time(&self, _tloc_addr: u64) -> Result<i64> {
        #[cfg(target_arch = "x86_64")]
        {
            self.syscall(libc::SYS_time as u64, _tloc_addr, 0, 0, 0, 0, 0)
        }
        #[cfg(target_arch = "aarch64")]
        {
            Err(nix::errno::Errno::ENOSYS)
        }
    }

    pub fn getppid(&self) -> Result<i64> {
        self.syscall(libc::SYS_getppid as u64, 0, 0, 0, 0, 0, 0)
    }

    pub fn getpgrp(&self) -> Result<i64> {
        #[cfg(target_arch = "x86_64")]
        {
            self.syscall(libc::SYS_getpgrp as u64, 0, 0, 0, 0, 0, 0)
        }
        #[cfg(target_arch = "aarch64")]
        {
            self.syscall(libc::SYS_getpgid as u64, 0, 0, 0, 0, 0, 0)
        }
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

    pub fn futex(&self, uaddr: u64, op: c_int, val: u32, timeout: u64, uaddr2: u64, val3: u32) -> Result<i64> {
        self.syscall(libc::SYS_futex as u64, uaddr, op as u64, val as u64, timeout, uaddr2, val3 as u64)
    }

    pub fn set_tid_address(&self, tidptr: u64) -> Result<i64> {
        self.syscall(libc::SYS_set_tid_address as u64, tidptr, 0, 0, 0, 0, 0)
    }
}
