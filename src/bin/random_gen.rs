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
            println!("Rdtsc: tsc={} tscp={} aux={} mono={}", tsc, tscp, aux, tscp > tsc);
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

        // 1. /dev//urandom alias, openat relative urandom, readv/preadv, and /proc/sys/kernel/random/uuid
        let mut alias_buf = [0u8; 4];
        if let Ok(mut f) = std::fs::File::open("/dev//urandom") {
            let _ = f.read_exact(&mut alias_buf);
        }
        let dev_dir = libc::open(b"/dev\0".as_ptr() as *const _, libc::O_RDONLY | libc::O_DIRECTORY);
        let rel_ufd = libc::openat(dev_dir, b"urandom\0".as_ptr() as *const _, libc::O_RDONLY);
        let mut iov_buf = [0u8; 4];
        let mut iov = libc::iovec {
            iov_base: iov_buf.as_mut_ptr() as *mut libc::c_void,
            iov_len: iov_buf.len(),
        };
        let rv = libc::readv(rel_ufd, &mut iov as *mut libc::iovec, 1);
        libc::close(rel_ufd);
        libc::close(dev_dir);
        let uuid_str = std::fs::read_to_string("/proc/sys/kernel/random/uuid").unwrap_or_default();
        println!(
            "RandomAliases: alias={:?} readv={}({}) uuid={}",
            alias_buf,
            rv,
            iov_buf[0],
            uuid_str.trim()
        );

        // 2. adjtimex, getrusage, getcpu, getpgid, getsid
        let mut tx: libc::timex = std::mem::zeroed();
        let adj_ret = libc::adjtimex(&mut tx);
        let mut ru: libc::rusage = std::mem::zeroed();
        ru.ru_utime.tv_usec = 999;
        let ru_ret = libc::getrusage(libc::RUSAGE_SELF, &mut ru);
        let mut cpu_id: u32 = 999;
        let mut node_id: u32 = 999;
        let cpu_ret = libc::syscall(
            libc::SYS_getcpu,
            &mut cpu_id as *mut u32,
            &mut node_id as *mut u32,
            0usize,
        );
        let pgid = libc::getpgid(0);
        let sid = libc::getsid(0);
        println!(
            "SysIds: adj={}:{} ru={}:{} cpu={}:{}:{} pgid={} sid={}",
            adj_ret,
            tx.time.tv_sec,
            ru_ret,
            ru.ru_utime.tv_usec,
            cpu_ret,
            cpu_id,
            node_id,
            pgid,
            sid
        );

        // 3. fork + waitpid deterministic PID, and raise(SIGUSR1) with custom handler
        static USR1_COUNT: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);
        extern "C" fn handle_usr1(_: i32) {
            USR1_COUNT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
        libc::signal(libc::SIGUSR1, handle_usr1 as *const () as usize);
        let raise_ret = libc::raise(libc::SIGUSR1);
        let cpid = libc::fork();
        if cpid == 0 {
            libc::_exit(0);
        }
        let mut wstatus: i32 = 0;
        let wpid = libc::waitpid(cpid, &mut wstatus, 0);
        println!(
            "ProcCheck: cpid={} wpid={} raise={} usr1={}",
            cpid,
            wpid,
            raise_ret,
            USR1_COUNT.load(std::sync::atomic::Ordering::SeqCst)
        );

        // 4. Page-boundary unaligned buffer read/write/getrandom
        let map_ptr = libc::mmap(
            std::ptr::null_mut(),
            8192,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        ) as *mut u8;
        libc::munmap(map_ptr.add(4096) as *mut libc::c_void, 4096);
        let tail_ptr = map_ptr.add(4096 - 5);
        std::ptr::copy_nonoverlapping(b"hello".as_ptr(), tail_ptr, 5);
        let gr_tail = libc::syscall(libc::SYS_getrandom, tail_ptr, 5usize, 0);
        let tail_slice = std::slice::from_raw_parts(tail_ptr, 5);
        println!("PageBoundary: gr={} bytes={:?}", gr_tail, tail_slice);
        libc::munmap(map_ptr as *mut libc::c_void, 4096);

        // 5. socketpair + Virtual socket INADDR_ANY connect + small addrlen + AT_EMPTY_PATH + SOCK_NONBLOCK
        let mut sv = [-1i32; 2];
        let sp_ret = libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr());
        let sp_w = libc::write(sv[0], b"ok".as_ptr() as *const _, 2);
        let mut sp_buf = [0u8; 2];
        let sp_r = libc::read(sv[1], sp_buf.as_mut_ptr() as *mut _, 2);
        libc::close(sv[0]);
        libc::close(sv[1]);

        let lsock = libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_NONBLOCK, 0);
        let eagain_acc = libc::accept(lsock, std::ptr::null_mut(), std::ptr::null_mut());
        let mut sin: libc::sockaddr_in = std::mem::zeroed();
        sin.sin_family = libc::AF_INET as u16;
        sin.sin_addr.s_addr = 0; // INADDR_ANY (0.0.0.0)
        sin.sin_port = 0;
        libc::bind(
            lsock,
            &sin as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as u32,
        );
        libc::listen(lsock, 1);
        let mut bound_sin: libc::sockaddr_in = std::mem::zeroed();
        let mut bound_len: u32 = std::mem::size_of::<libc::sockaddr_in>() as u32;
        libc::getsockname(
            lsock,
            &mut bound_sin as *mut _ as *mut libc::sockaddr,
            &mut bound_len,
        );

        let csock = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
        let mut dst_sin: libc::sockaddr_in = std::mem::zeroed();
        dst_sin.sin_family = libc::AF_INET as u16;
        dst_sin.sin_addr.s_addr = u32::from_ne_bytes([127, 0, 0, 1]);
        dst_sin.sin_port = bound_sin.sin_port;
        let conn_ret = libc::connect(
            csock,
            &dst_sin as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as u32,
        );

        // Accept with a 4-byte buffer and sentinel bytes after it to verify no buffer overflow
        let mut tiny_buf = [0xAAu8; 16];
        let mut tiny_len: u32 = 4;
        let asock = libc::accept(
            lsock,
            tiny_buf.as_mut_ptr() as *mut libc::sockaddr,
            &mut tiny_len,
        );

        let mut sock_st: libc::stat = std::mem::zeroed();
        let fstatat_sock = libc::syscall(
            libc::SYS_newfstatat,
            asock,
            b"\0".as_ptr(),
            &mut sock_st as *mut libc::stat,
            libc::AT_EMPTY_PATH,
        );
        libc::close(asock);
        libc::close(csock);
        libc::close(lsock);
        println!(
            "SockCheck: sp={}:{}:{} eagain={} conn={} tiny_len={} sentinel={:#x} fstatat={}:{}",
            sp_ret,
            sp_w,
            sp_r,
            eagain_acc,
            conn_ret,
            tiny_len,
            tiny_buf[4],
            fstatat_sock,
            sock_st.st_mode & libc::S_IFMT
        );
    }
}
