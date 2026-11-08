use rand::RngCore;
use std::ffi::CStr;

fn main() {
    let mut rng = rand::thread_rng();
    let mut buf = [0u8; 16];
    rng.fill_bytes(&mut buf);
    println!("Random bytes: {:?}", buf);

    unsafe {
        let mut t: libc::time_t = 0;
        let ret_t = libc::syscall(libc::SYS_time, &mut t as *mut libc::time_t);
        println!("Time: {} ({})", ret_t, t);

        let mut info: libc::sysinfo = std::mem::zeroed();
        if libc::sysinfo(&mut info) == 0 {
            println!("Sysinfo: uptime={} freeram={} procs={}", info.uptime, info.freeram, info.procs);
        }

        let mut uts: libc::utsname = std::mem::zeroed();
        if libc::uname(&mut uts) == 0 {
            let nodename = CStr::from_ptr(uts.nodename.as_ptr()).to_string_lossy();
            let release = CStr::from_ptr(uts.release.as_ptr()).to_string_lossy();
            println!("Uname: nodename={} release={}", nodename, release);
        }

        let bad_rand = libc::syscall(libc::SYS_getrandom, std::ptr::null_mut::<u8>(), usize::MAX, 0);
        let bad_sleep = libc::syscall(libc::SYS_nanosleep, std::ptr::null::<libc::timespec>(), std::ptr::null_mut::<libc::timespec>());
        println!("Faults: getrandom={} nanosleep={}", bad_rand, bad_sleep);
    }
}
