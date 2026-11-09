#[macro_use]
mod common;

use std::ffi::CStr;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::io::AsRawFd;

nondeterminism_test!(
    getrandom_syscall,
    || {
        let mut buf = [0u8; 16];
        let ret = unsafe { libc::getrandom(buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
        assert_eq!(ret, 16);
        buf
    },
    |buf| {
        assert_eq!(buf, &[0x42u8; 16]);
    }
);

nondeterminism_test!(
    dev_urandom_and_random,
    || {
        let mut urandom = [0u8; 8];
        File::open("/dev/urandom")
            .unwrap()
            .read_exact(&mut urandom)
            .unwrap();

        let mut random = [0u8; 8];
        File::open("/dev/random")
            .unwrap()
            .read_exact(&mut random)
            .unwrap();

        let mut rel_urandom = [0u8; 4];
        File::open("./../../../../../dev/urandom")
            .unwrap()
            .read_exact(&mut rel_urandom)
            .unwrap();

        (urandom, random, rel_urandom)
    },
    |&(urandom, random, rel_urandom)| {
        assert_eq!(urandom, [0x42u8; 8]);
        assert_eq!(random, [0x42u8; 8]);
        assert_eq!(rel_urandom, [0x42u8; 4]);
    }
);

nondeterminism_test!(
    urandom_scatter_gather_io,
    || {
        let f = File::open("/dev/urandom").unwrap();
        let fd = f.as_raw_fd();

        // pread64
        let mut pread_buf = [0u8; 4];
        let n_pread = unsafe {
            libc::pread(
                fd,
                pread_buf.as_mut_ptr() as *mut libc::c_void,
                pread_buf.len(),
                16,
            )
        };
        assert_eq!(n_pread, 4);

        // readv
        let mut v1 = [0u8; 4];
        let mut v2 = [0u8; 4];
        let mut iov = [
            libc::iovec {
                iov_base: v1.as_mut_ptr() as *mut libc::c_void,
                iov_len: v1.len(),
            },
            libc::iovec {
                iov_base: v2.as_mut_ptr() as *mut libc::c_void,
                iov_len: v2.len(),
            },
        ];
        let n_readv = unsafe { libc::readv(fd, iov.as_mut_ptr(), 2) };
        assert_eq!(n_readv, 8);

        // preadv
        let mut pv1 = [0u8; 4];
        let mut piov = [libc::iovec {
            iov_base: pv1.as_mut_ptr() as *mut libc::c_void,
            iov_len: pv1.len(),
        }];
        let n_preadv = unsafe { libc::preadv(fd, piov.as_mut_ptr(), 1, 0) };
        assert_eq!(n_preadv, 4);

        // preadv2 with offset == -1 (uses current file position via readv)
        let mut pv2 = [0u8; 4];
        let mut piov2 = [libc::iovec {
            iov_base: pv2.as_mut_ptr() as *mut libc::c_void,
            iov_len: pv2.len(),
        }];
        let n_preadv2 = unsafe {
            libc::syscall(
                libc::SYS_preadv2,
                fd,
                piov2.as_mut_ptr(),
                1,
                -1isize,
                0,
                0,
            )
        };
        assert_eq!(n_preadv2, 4);

        (pread_buf, v1, v2, pv1, pv2)
    },
    |&(pread_buf, v1, v2, pv1, pv2)| {
        assert_eq!(pread_buf, [0x42u8; 4]);
        assert_eq!(v1, [0x42u8; 4]);
        assert_eq!(v2, [0x42u8; 4]);
        assert_eq!(pv1, [0x42u8; 4]);
        assert_eq!(pv2, [0x42u8; 4]);
    }
);

nondeterminism_test!(
    proc_random_uuid_and_seek,
    || {
        let mut f = File::open("/proc/sys/kernel/random/uuid").unwrap();
        let mut uuid1 = String::new();
        f.read_to_string(&mut uuid1).unwrap();

        // Seek back to offset 9 and read 4 chars
        f.seek(SeekFrom::Start(9)).unwrap();
        let mut slice = [0u8; 4];
        f.read_exact(&mut slice).unwrap();

        // Also test pread64 at offset 0
        let mut pread_slice = [0u8; 8];
        let n = unsafe {
            libc::pread(
                f.as_raw_fd(),
                pread_slice.as_mut_ptr() as *mut libc::c_void,
                pread_slice.len(),
                0,
            )
        };
        assert_eq!(n, 8);

        (uuid1.trim().to_string(), slice, pread_slice)
    },
    |(uuid, slice, pread_slice)| {
        assert_eq!(uuid, "42424242-4242-4242-4242-424242424242");
        assert_eq!(slice, b"4242");
        assert_eq!(pread_slice, b"42424242");
    }
);

virtualized_test!(
    boot_id_and_machine_id,
    || {
        let boot_id = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .unwrap()
            .trim()
            .to_string();
        let machine_id = std::fs::read_to_string("/etc/machine-id")
            .ok()
            .map(|s| s.trim().to_string());
        (boot_id, machine_id)
    },
    |(boot_id, machine_id)| {
        assert_eq!(boot_id, "42424242-4242-4242-4242-424242424242");
        if let Some(mid) = machine_id {
            assert_eq!(mid, "42424242-4242-4242-4242-424242424242");
        }
    }
);

nondeterminism_test!(
    auxv_at_random_scrubbed,
    || {
        let ptr = unsafe { libc::getauxval(libc::AT_RANDOM) as *const u8 };
        assert!(!ptr.is_null());
        let slice = unsafe { std::slice::from_raw_parts(ptr, 16) };
        slice.to_vec()
    },
    |bytes| {
        assert_eq!(bytes.as_slice(), &[0x42u8; 16]);
    }
);

nondeterminism_test!(
    clocks_and_gettimeofday,
    || {
        let mut rt = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        let mut mono = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        let mut tv = libc::timeval {
            tv_sec: 0,
            tv_usec: 0,
        };
        unsafe {
            assert_eq!(libc::clock_gettime(libc::CLOCK_REALTIME, &mut rt), 0);
            assert_eq!(libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut mono), 0);
            assert_eq!(libc::gettimeofday(&mut tv, std::ptr::null_mut()), 0);
        }
        (rt.tv_sec, rt.tv_nsec, mono.tv_sec, mono.tv_nsec, tv.tv_sec, tv.tv_usec)
    },
    |&(rt_s, rt_ns, mono_s, mono_ns, tv_s, tv_us)| {
        assert_eq!(rt_s, 946684800);
        assert_eq!(rt_ns, 0);
        assert_eq!(mono_s, 946684800);
        assert_eq!(mono_ns, 0);
        assert_eq!(tv_s, 946684800);
        assert_eq!(tv_us, 0);
    }
);

virtualized_test!(
    time_and_clock_getres,
    || {
        let mut tloc: libc::time_t = 0;
        let t_ret = unsafe { libc::time(&mut tloc) };
        let t_null = unsafe { libc::time(std::ptr::null_mut()) };
        assert_eq!(t_ret, tloc);
        assert_eq!(t_ret, t_null);

        let mut res = libc::timespec {
            tv_sec: 99,
            tv_nsec: 99,
        };
        let r = unsafe { libc::clock_getres(libc::CLOCK_REALTIME, &mut res) };
        assert_eq!(r, 0);
        (t_ret, res.tv_sec, res.tv_nsec)
    },
    |&(t_ret, res_sec, res_nsec)| {
        assert_eq!(t_ret, 946684800);
        assert_eq!(res_sec, 0);
        assert_eq!(res_nsec, 1);
    }
);

nondeterminism_test!(
    adjtimex_and_clock_adjtime,
    || {
        let mut tx1: libc::timex = unsafe { std::mem::zeroed() };
        let r1 = unsafe { libc::syscall(libc::SYS_adjtimex, &mut tx1 as *mut libc::timex) };
        assert!(r1 >= 0);

        let mut tx2: libc::timex = unsafe { std::mem::zeroed() };
        let r2 = unsafe {
            libc::syscall(
                libc::SYS_clock_adjtime,
                libc::CLOCK_REALTIME,
                &mut tx2 as *mut libc::timex,
            )
        };
        assert!(r2 >= 0);

        (tx1.time.tv_sec, tx1.time.tv_usec, tx2.time.tv_sec, tx2.time.tv_usec)
    },
    |&(s1, u1, s2, u2)| {
        assert_eq!(s1, 946684800);
        assert_eq!(u1, 0);
        assert_eq!(s2, 946684800);
        assert_eq!(u2, 0);
    }
);

virtualized_test!(
    sysinfo_times_and_getrusage,
    || {
        let mut info: libc::sysinfo = unsafe { std::mem::zeroed() };
        assert_eq!(unsafe { libc::sysinfo(&mut info) }, 0);

        let mut tms: libc::tms = unsafe { std::mem::zeroed() };
        let ticks = unsafe { libc::times(&mut tms) };

        let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
        assert_eq!(unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut ru) }, 0);

        (
            info.uptime,
            info.totalram,
            info.freeram,
            info.procs,
            ticks,
            tms.tms_utime,
            tms.tms_stime,
            ru.ru_utime.tv_sec,
            ru.ru_utime.tv_usec,
        )
    },
    |&(uptime, totalram, freeram, procs, ticks, utime, stime, ru_sec, ru_usec)| {
        assert_eq!(uptime, 0);
        assert_eq!(totalram, 1024 * 1024 * 1024);
        assert_eq!(freeram, 512 * 1024 * 1024);
        assert_eq!(procs, 1);
        assert_eq!(ticks, 0);
        assert_eq!(utime, 0);
        assert_eq!(stime, 0);
        assert_eq!(ru_sec, 0);
        assert_eq!(ru_usec, 0);
    }
);

virtualized_test!(
    uname_virtualization,
    || {
        let mut uts: libc::utsname = unsafe { std::mem::zeroed() };
        assert_eq!(unsafe { libc::uname(&mut uts) }, 0);
        let sysname = unsafe { CStr::from_ptr(uts.sysname.as_ptr()).to_string_lossy().into_owned() };
        let nodename = unsafe { CStr::from_ptr(uts.nodename.as_ptr()).to_string_lossy().into_owned() };
        let release = unsafe { CStr::from_ptr(uts.release.as_ptr()).to_string_lossy().into_owned() };
        let version = unsafe { CStr::from_ptr(uts.version.as_ptr()).to_string_lossy().into_owned() };
        let machine = unsafe { CStr::from_ptr(uts.machine.as_ptr()).to_string_lossy().into_owned() };
        (sysname, nodename, release, version, machine)
    },
    |(sysname, nodename, release, version, machine)| {
        assert_eq!(sysname, "Linux");
        assert_eq!(nodename, "sandbox");
        assert_eq!(release, "6.0.0-deterministic");
        assert_eq!(version, "#1 SMP DETERMINISTIC");
        assert_eq!(machine, std::env::consts::ARCH);
    }
);

nondeterminism_test!(
    process_and_thread_ids,
    || unsafe {
        let pid = libc::getpid();
        let ppid = libc::getppid();
        let tid = libc::syscall(libc::SYS_gettid) as i32;
        let pgrp = libc::getpgrp();
        let pgid = libc::getpgid(0);
        let sid = libc::getsid(0);
        (pid, ppid, tid, pgrp, pgid, sid)
    },
    |&(pid, ppid, tid, pgrp, pgid, sid)| {
        assert_eq!(pid, 1234);
        assert_eq!(ppid, 1);
        assert_eq!(tid, 1235);
        assert_eq!(pgrp, 1);
        assert_eq!(pgid, 1);
        assert_eq!(sid, 1);
    }
);

sandbox_test!(
    user_group_and_cpu_ids,
    || unsafe {
        let uid = libc::getuid();
        let euid = libc::geteuid();
        let gid = libc::getgid();
        let egid = libc::getegid();

        let (mut ruid, mut euid2, mut suid) = (0u32, 0u32, 0u32);
        assert_eq!(libc::getresuid(&mut ruid, &mut euid2, &mut suid), 0);

        let (mut rgid, mut egid2, mut sgid) = (0u32, 0u32, 0u32);
        assert_eq!(libc::getresgid(&mut rgid, &mut egid2, &mut sgid), 0);

        let (mut cpu, mut node) = (99u32, 99u32);
        let r_cpu = libc::syscall(
            libc::SYS_getcpu,
            &mut cpu as *mut u32,
            &mut node as *mut u32,
            0usize,
        );
        assert_eq!(r_cpu, 0);

        (uid, euid, gid, egid, ruid, euid2, suid, rgid, egid2, sgid, cpu, node)
    },
    |&vals| {
        assert_eq!(vals, (1000, 1000, 1000, 1000, 1000, 1000, 1000, 1000, 1000, 1000, 0, 0));
    }
);

#[cfg(target_arch = "x86_64")]
nondeterminism_test!(
    rdtsc_and_rdtscp_emulation,
    || unsafe {
        let t1 = core::arch::x86_64::_rdtsc();
        let mut aux: u32 = 0xffff_ffff;
        let t2 = core::arch::x86_64::__rdtscp(&mut aux);
        assert!(t2 > t1, "TSC must be strictly monotonic");
        (t1, t2, aux)
    },
    |&(t1, t2, aux)| {
        assert_eq!(aux, 0);
        assert_eq!(t2 - t1, 1);
    }
);

#[cfg(target_arch = "x86_64")]
sandbox_test!(
    cpuid_feature_masking,
    || {
        let leaf1 = core::arch::x86_64::__cpuid_count(1, 0);
        let apic_id = (leaf1.ebx >> 24) & 0xff;
        let has_rdrand = (leaf1.ecx & (1 << 30)) != 0;

        let leaf7 = core::arch::x86_64::__cpuid_count(7, 0);
        let has_rdseed = (leaf7.ebx & (1 << 18)) != 0;

        let leaf_b = core::arch::x86_64::__cpuid_count(0x0b, 0);
        (apic_id, has_rdrand, has_rdseed, leaf_b.edx)
    },
    |&(apic_id, _, _, x2apic_id)| {
        assert_eq!(apic_id, 0);
        assert_eq!(x2apic_id, 0);
    }
);

#[cfg(target_arch = "aarch64")]
sandbox_test!(
    aarch64_mrs_and_hwcap2_emulation,
    || unsafe {
        // 1. AT_HWCAP2 (26) must have HWCAP2_RNG (bit 16) masked out in deterministic mode
        let hwcap2 = libc::getauxval(26);
        let has_rng_hwcap = (hwcap2 & (1 << 16)) != 0;

        // 2. MRS RNDR (s3_3_c2_c4_0 = 0xd53b2400) traps with SIGILL when FEAT_RNG is absent/disabled
        // and is emulated by Deterministic::emulate_rdtsc
        let rndr_val: u64;
        core::arch::asm!(
            ".inst 0xd53b2400",
            out("x0") rndr_val,
            options(nomem, nostack)
        );
        (has_rng_hwcap, rndr_val)
    },
    |&(has_rng_hwcap, rndr_val)| {
        assert!(!has_rng_hwcap, "HWCAP2_RNG must be masked out in deterministic sandbox");
        assert_eq!(rndr_val, 0x4242_4242_4242_4242);
    }
);

nondeterminism_test!(
    aslr_stack_and_mmap_addresses,
    || unsafe {
        let stack_local = 42u64;
        let stack_addr = &stack_local as *const u64 as usize;

        let map_ptr = libc::mmap(
            std::ptr::null_mut(),
            4096,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        assert_ne!(map_ptr, libc::MAP_FAILED);
        let map_addr = map_ptr as usize;
        libc::munmap(map_ptr, 4096);

        (stack_addr, map_addr)
    }
);

sandbox_test!(
    efault_and_cross_page_boundary,
    || unsafe {
        // Null pointers should return -1 with EFAULT without crashing the tracer
        let bad_gr = libc::getrandom(std::ptr::null_mut(), 16, 0);
        assert_eq!(bad_gr, -1);
        assert_eq!(*libc::__errno_location(), libc::EFAULT);

        let bad_ns = libc::nanosleep(std::ptr::null(), std::ptr::null_mut());
        assert_eq!(bad_ns, -1);
        assert_eq!(*libc::__errno_location(), libc::EFAULT);

        // Unaligned 5-byte slice right at the end of a page whose following page is unmapped
        let ptr = libc::mmap(
            std::ptr::null_mut(),
            8192,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        ) as *mut u8;
        assert_ne!(ptr, libc::MAP_FAILED as *mut u8);
        libc::munmap(ptr.add(4096) as *mut libc::c_void, 4096);

        let cross_ptr = ptr.add(4096 - 5);
        std::ptr::copy_nonoverlapping(b"hello".as_ptr(), cross_ptr, 5);
        let gr_ret = libc::getrandom(cross_ptr as *mut libc::c_void, 5, 0);
        let valid_prefix = std::slice::from_raw_parts(cross_ptr, 5).to_vec();
        libc::munmap(ptr as *mut libc::c_void, 4096);

        (gr_ret, valid_prefix)
    },
    |&(gr_ret, ref valid_prefix)| {
        assert_eq!(gr_ret, 5);
        assert_eq!(valid_prefix.as_slice(), &[0x42u8; 5]);
    }
);
