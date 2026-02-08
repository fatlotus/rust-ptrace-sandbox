use nix::sys::ptrace;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{execvp, fork, ForkResult, Pid};
use std::ffi::CString;
use crate::linux::Linux;

pub fn run_with_interceptor<L: Linux>(cmd: &str, args: &[&str], mut handler: L) {
    match unsafe { fork() } {
        Ok(ForkResult::Parent { child }) => {
            parent_loop(child, &mut handler);
        }
        Ok(ForkResult::Child) => {
            ptrace::traceme().expect("Failed to traceme");
            let c_cmd = CString::new(cmd).unwrap();
            let mut c_args: Vec<CString> = Vec::new();
            c_args.push(c_cmd.clone());
            for arg in args {
                c_args.push(CString::new(*arg).unwrap());
            }
            
            let _ = execvp(&c_cmd, &c_args);
            panic!("Failed to execvp");
        }
        Err(e) => panic!("Fork failed: {}", e),
    }
}

fn parent_loop<L: Linux>(child: Pid, handler: &mut L) {
    waitpid(child, None).expect("Initial wait failed");
    ptrace::setoptions(child, ptrace::Options::PTRACE_O_TRACESYSGOOD).expect("Failed to set options");

    let mut in_syscall = false;
    let mut saved_result: i64 = 0;

    loop {
        ptrace::syscall(child, None).expect("PTRACE_SYSCALL failed");
        match waitpid(child, None).expect("Wait failed") {
            WaitStatus::PtraceSyscall(_) => {
                if !in_syscall {
                    // Syscall Entry
                    if let Some(res) = handle_syscall_entry(child, handler) {
                        saved_result = res;
                        // To "replace" the syscall, we change the syscall number to an invalid one
                        // some use -1, but some kernels might treat that specially. 
                        // Let's try something like 999 or just keep it and overwrite at exit.
                        // Actually, if we want to SKIP it, we should change it to something harmless or -1.
                        let mut regs = ptrace::getregs(child).expect("Failed to get regs");
                        regs.orig_rax = u64::MAX; // -1 as u64
                        ptrace::setregs(child, regs).expect("Failed to set regs");
                    } else {
                        saved_result = -123456; // Sentinel for "did not replace"
                    }
                    in_syscall = true;
                } else {
                    // Syscall Exit
                    if saved_result != -123456 {
                        let mut regs = ptrace::getregs(child).expect("Failed to get regs");
                        regs.rax = saved_result as u64;
                        ptrace::setregs(child, regs).expect("Failed to set regs");
                    }
                    in_syscall = false;
                }
            }
            WaitStatus::Exited(_, status) => {
                println!("Child exited with status {}", status);
                break;
            }
            WaitStatus::Signaled(_, sig, _) => {
                println!("Child signaled with {}", sig);
                break;
            }
            _other => {}
        }
    }
}

fn handle_syscall_entry<L: Linux>(pid: Pid, handler: &mut L) -> Option<i64> {
    let regs = ptrace::getregs(pid).expect("Failed to get regs");
    let syscall_no = regs.orig_rax;

    match syscall_no {
        1 => { // write
            let fd = regs.rdi as i32;
            let addr = regs.rsi as usize;
            let count = regs.rdx as usize;
            let buf = read_memory(pid, addr, count);
            Some(handler.write(fd, &buf) as i64)
        }
        60 | 231 => { // exit | exit_group
            let status = regs.rdi as i32;
            if syscall_no == 60 {
                handler.exit(status);
            } else {
                handler.exit_group(status);
            }
            Some(0) // Doesn't really matter as it exits
        }
        12 => { // brk
            let addr = regs.rdi as *mut libc::c_void;
            Some(handler.brk(addr) as i64)
        }
        _ => None,
    }
}

fn read_memory(pid: Pid, addr: usize, count: usize) -> Vec<u8> {
    let mut data = Vec::with_capacity(count);
    let mut read = 0;
    while read < count {
        let word = ptrace::read(pid, (addr + read) as *mut _).unwrap_or(0);
        let to_copy = std::cmp::min(count - read, std::mem::size_of::<libc::c_long>());
        let bytes: [u8; 8] = word.to_ne_bytes();
        data.extend_from_slice(&bytes[..to_copy]);
        read += to_copy;
    }
    data
}
