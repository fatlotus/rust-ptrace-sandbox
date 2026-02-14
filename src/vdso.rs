use nix::sys::ptrace;
use nix::unistd::Pid;
use std::ffi::c_void;

pub fn disable_vdso(child: Pid, sp: u64) {
    let mut addr = sp;
    
    // argc
    let argc = match ptrace::read(child, addr as *mut c_void) {
        Ok(val) => val as u64,
        Err(_) => return,
    };
    
    addr += 8; // skip argc
    addr += (argc + 1) * 8; // skip argv and NULL
    
    // Skip envp
    loop {
        match ptrace::read(child, addr as *mut c_void) {
            Ok(0) => {
                addr += 8;
                break;
            }
            Ok(_) => addr += 8,
            Err(_) => break,
        }
    }

    let mut vdso_addr = 0u64;
    // Search auxv
    while let Ok(key) = ptrace::read(child, addr as *mut c_void) {
        let key = key as u64;
        if key == 0 { break; }
        
        let val_addr = (addr + 8) as *mut c_void;
        if let Ok(val) = ptrace::read(child, val_addr) {
            let val = val as u64;
            if key == 33 { // AT_SYSINFO_EHDR
                vdso_addr = val;
                let _ = ptrace::write(child, val_addr, 0i64);
                break;
            }
        } else {
            break;
        }
        addr += 16;
    }

    if vdso_addr != 0 {
        // Scan stack to zero out other references
        for i in 0..1024 {
            let test_addr = (sp + i * 8) as *mut c_void;
            if let Ok(val) = ptrace::read(child, test_addr) {
                if val as u64 == vdso_addr {
                    let _ = ptrace::write(child, test_addr, 0i64);
                }
            }
        }
    }
}
