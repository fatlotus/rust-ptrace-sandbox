use rand::RngCore;
use std::ffi::CStr;
use std::io::Read;

fn main() {
    let mut rng = rand::thread_rng();
    let mut buf = [0u8; 16];
    rng.fill_bytes(&mut buf);
    println!("Random bytes: {:?}", buf);

    let mut urand_buf = [0u8; 8];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        let _ = f.read_exact(&mut urand_buf);
    }
    println!("Urandom: {:?}", urand_buf);

    unsafe {
        let at_rand = libc::getauxval(libc::AT_RANDOM) as *const u8;
        if !at_rand.is_null() {
            let slice = std::slice::from_raw_parts(at_rand, 16);
            println!("AT_RANDOM: {:?}", slice);
        }

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

        let mut st: libc::stat = std::mem::zeroed();
        if libc::syscall(libc::SYS_stat, b"/etc/hosts\0".as_ptr(), &mut st as *mut libc::stat) == 0 {
            println!("Stat: ino={} mtime={}", st.st_ino, st.st_mtime);
        }

        let tid = libc::syscall(libc::SYS_gettid);
        println!("Tid: {}", tid);
    }

    if let Ok(meta) = std::fs::metadata("/etc/hosts") {
        use std::os::unix::fs::MetadataExt;
        println!("Statx: ino={} mtime={}", meta.ino(), meta.mtime());
    }

    // Test unintercepted FD syscall (getdents64 via read_dir)
    let dir_ok = std::fs::read_dir("/etc").map(|mut d| d.next().is_some()).unwrap_or(false);
    println!("ReadDir: {}", dir_ok);

    // Test dup2 on virtualized socket and poll with fd=-1 + POLLOUT
    unsafe {
        let sfd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
        let dup_sfd = libc::dup2(sfd, 42);
        let mut pfds = [
            libc::pollfd { fd: -1, events: libc::POLLIN, revents: 99 },
            libc::pollfd { fd: dup_sfd, events: libc::POLLOUT, revents: 0 },
            libc::pollfd { fd: 9999, events: libc::POLLIN, revents: 0 },
        ];
        let pret = libc::poll(pfds.as_mut_ptr(), pfds.len() as libc::nfds_t, 0);
        let close1 = libc::close(sfd);
        let close2 = libc::close(dup_sfd);
        let bad_close = libc::close(9999);
        println!(
            "FdTest: dup={} poll={} rev0={} rev1={} rev2={} close={},{},{}",
            dup_sfd, pret, pfds[0].revents, pfds[1].revents, pfds[2].revents, close1, close2, bad_close
        );

        #[cfg(target_arch = "x86_64")]
        {
            let tsc = core::arch::x86_64::_rdtsc();
            let mut aux: u32 = 123;
            let tscp = core::arch::x86_64::__rdtscp(&mut aux);
            println!("Rdtsc: tsc={} tscp={} aux={}", tsc, tscp, aux);
        }

        // Verify FUTEX_WAIT with mismatched value (EAGAIN) does not advance virtual time
        let fword: u32 = 10;
        let ts_rel = libc::timespec { tv_sec: 100, tv_nsec: 0 };
        let r_eagain = libc::syscall(
            libc::SYS_futex,
            &fword as *const u32,
            libc::FUTEX_WAIT,
            999u32,
            &ts_rel as *const libc::timespec,
            std::ptr::null::<u32>(),
            0u32,
        );
        let t_after = libc::syscall(libc::SYS_time, std::ptr::null_mut::<libc::time_t>());
        let ts_abs = libc::timespec { tv_sec: 1, tv_nsec: 0 };
        let r_bitset = libc::syscall(
            libc::SYS_futex,
            &fword as *const u32,
            libc::FUTEX_WAIT_BITSET,
            10u32,
            &ts_abs as *const libc::timespec,
            std::ptr::null::<u32>(),
            u32::MAX,
        );
        println!("FutexCheck: eagain={} bitset={} time_after={}", r_eagain, r_bitset, t_after);
    }
}
