#[macro_use]
mod common;

use std::fs::File;
use std::os::unix::io::AsRawFd;

virtualized_test!(
    stat_lstat_fstat_and_newfstatat_normalization,
    || unsafe {
        let path = b"/etc/passwd\0";
        let mut st_stat: libc::stat = std::mem::zeroed();
        let mut st_lstat: libc::stat = std::mem::zeroed();
        let mut st_fstat: libc::stat = std::mem::zeroed();
        let mut st_fstatat: libc::stat = std::mem::zeroed();

        assert_eq!(libc::stat(path.as_ptr() as *const libc::c_char, &mut st_stat), 0);
        assert_eq!(libc::lstat(path.as_ptr() as *const libc::c_char, &mut st_lstat), 0);

        let f = File::open("/etc/passwd").unwrap();
        assert_eq!(libc::fstat(f.as_raw_fd(), &mut st_fstat), 0);
        assert_eq!(
            libc::syscall(
                libc::SYS_newfstatat,
                f.as_raw_fd(),
                b"\0".as_ptr(),
                &mut st_fstatat as *mut libc::stat,
                libc::AT_EMPTY_PATH,
            ),
            0
        );

        (
            st_stat.st_dev,
            st_stat.st_ino,
            st_lstat.st_ino,
            st_fstat.st_ino,
            st_fstatat.st_ino,
            st_stat.st_uid,
            st_stat.st_gid,
            st_stat.st_mtime,
            st_stat.st_atime,
            st_stat.st_ctime,
        )
    },
    |&(dev, ino1, ino2, ino3, ino4, uid, gid, mtime, atime, ctime)| {
        assert_eq!(dev, 1);
        assert!(ino1 > 0);
        assert_eq!(ino1, ino2);
        assert_eq!(ino1, ino3);
        assert_eq!(ino1, ino4);
        assert_eq!(uid, 1000);
        assert_eq!(gid, 1000);
        assert_eq!(mtime, 0);
        assert_eq!(atime, 0);
        assert_eq!(ctime, 0);
    }
);

virtualized_test!(
    statx_metadata_normalization,
    || unsafe {
        const STATX_BASIC_STATS: libc::c_uint = 0x000007ff;
        let mut stx_path = [0u8; 256];
        let r1 = libc::syscall(
            libc::SYS_statx,
            libc::AT_FDCWD,
            b"/etc/passwd\0".as_ptr(),
            0,
            STATX_BASIC_STATS,
            stx_path.as_mut_ptr(),
        );
        assert_eq!(r1, 0);

        let f = File::open("/etc/passwd").unwrap();
        let mut stx_fd = [0u8; 256];
        let r2 = libc::syscall(
            libc::SYS_statx,
            f.as_raw_fd(),
            b"\0".as_ptr(),
            libc::AT_EMPTY_PATH,
            STATX_BASIC_STATS,
            stx_fd.as_mut_ptr(),
        );
        assert_eq!(r2, 0);

        let ino1 = u64::from_ne_bytes(stx_path[32..40].try_into().unwrap());
        let ino2 = u64::from_ne_bytes(stx_fd[32..40].try_into().unwrap());
        let uid = u32::from_ne_bytes(stx_path[20..24].try_into().unwrap());
        let gid = u32::from_ne_bytes(stx_path[24..28].try_into().unwrap());
        let btime = i64::from_ne_bytes(stx_path[80..88].try_into().unwrap());
        let mtime = i64::from_ne_bytes(stx_path[112..120].try_into().unwrap());
        let dev_maj = u32::from_ne_bytes(stx_path[136..140].try_into().unwrap());
        let dev_min = u32::from_ne_bytes(stx_path[140..144].try_into().unwrap());

        (ino1, ino2, uid, gid, mtime, btime, dev_maj, dev_min)
    },
    |&(ino1, ino2, uid, gid, mtime, btime, dev_maj, dev_min)| {
        assert!(ino1 > 0);
        assert_eq!(ino1, ino2);
        assert_eq!(uid, 1000);
        assert_eq!(gid, 1000);
        assert_eq!(mtime, 0);
        assert_eq!(btime, 0);
        assert_eq!(dev_maj, 0);
        assert_eq!(dev_min, 1);
    }
);

nondeterminism_test!(
    newly_created_file_metadata_is_deterministic,
    || unsafe {
        let path = "/tmp/ptrace_sandbox_inode_test.tmp";
        let _ = std::fs::remove_file(path);
        std::fs::write(path, b"deterministic content").unwrap();

        let mut st: libc::stat = std::mem::zeroed();
        let c_path = std::ffi::CString::new(path).unwrap();
        assert_eq!(libc::stat(c_path.as_ptr(), &mut st), 0);
        let _ = std::fs::remove_file(path);

        (st.st_ino, st.st_mtime, st.st_mtime_nsec)
    },
    |&(ino, mtime, mtime_nsec)| {
        assert!(ino > 0);
        assert_eq!(mtime, 0);
        assert_eq!(mtime_nsec, 0);
    }
);

sandbox_test!(
    openat2_and_creat_syscalls,
    || unsafe {
        #[repr(C)]
        struct OpenHow {
            flags: u64,
            mode: u64,
            resolve: u64,
        }

        // 1. Open /dev/urandom via openat2 (resolve = 0) -> should be classified as VirtualRandom
        let how_zero = OpenHow {
            flags: libc::O_RDONLY as u64,
            mode: 0,
            resolve: 0,
        };
        let urand_fd = libc::syscall(
            libc::SYS_openat2,
            libc::AT_FDCWD,
            b"/dev/urandom\0".as_ptr(),
            &how_zero as *const OpenHow,
            std::mem::size_of::<OpenHow>(),
        ) as i32;
        assert!(urand_fd >= 0);
        let mut urand_buf = [0u8; 4];
        assert_eq!(
            libc::read(urand_fd, urand_buf.as_mut_ptr() as *mut libc::c_void, 4),
            4
        );
        libc::close(urand_fd);

        // 2. Open /dev/urandom via openat2 with RESOLVE_NO_SYMLINKS (0x04) -> wrapped via wrap_raw_fd
        let how_nosym = OpenHow {
            flags: libc::O_RDONLY as u64,
            mode: 0,
            resolve: 0x04,
        };
        let urand_fd2 = libc::syscall(
            libc::SYS_openat2,
            libc::AT_FDCWD,
            b"/dev/urandom\0".as_ptr(),
            &how_nosym as *const OpenHow,
            std::mem::size_of::<OpenHow>(),
        ) as i32;
        assert!(urand_fd2 >= 0);
        let mut urand_buf2 = [0u8; 4];
        assert_eq!(
            libc::read(urand_fd2, urand_buf2.as_mut_ptr() as *mut libc::c_void, 4),
            4
        );
        libc::close(urand_fd2);

        // 3. creat and unlink
        let tmp_path = b"/tmp/ptrace_creat_test.txt\0";
        #[cfg(target_arch = "x86_64")]
        let cfd = libc::syscall(libc::SYS_creat, tmp_path.as_ptr(), 0o600) as i32;
        #[cfg(not(target_arch = "x86_64"))]
        let cfd = libc::creat(tmp_path.as_ptr() as *const libc::c_char, 0o600);
        assert!(cfd >= 0);
        assert_eq!(libc::write(cfd, b"abc".as_ptr() as *const libc::c_void, 3), 3);
        libc::close(cfd);
        assert_eq!(libc::unlink(tmp_path.as_ptr() as *const libc::c_char), 0);

        (urand_buf, urand_buf2)
    },
    |&(b1, b2)| {
        assert_eq!(b1, [0x42u8; 4]);
        assert_eq!(b2, [0x42u8; 4]);
    }
);

sandbox_test!(
    fd_duplication_and_close_lifecycle,
    || unsafe {
        let mut pfd = [-1i32; 2];
        assert_eq!(libc::pipe(pfd.as_mut_ptr()), 0);
        assert_eq!(libc::write(pfd[1], b"Z".as_ptr() as *const libc::c_void, 1), 1);

        // dup2(fd, fd) is a no-op returning fd
        assert_eq!(libc::dup2(pfd[0], pfd[0]), pfd[0]);
        // dup3(fd, fd, 0) must return -1 with EINVAL
        assert_eq!(libc::dup3(pfd[0], pfd[0], 0), -1);
        assert_eq!(*libc::__errno_location(), libc::EINVAL);

        let dup_fd = libc::dup3(pfd[0], 42, libc::O_CLOEXEC);
        assert_eq!(dup_fd, 42);
        let fcntl_dup = libc::fcntl(dup_fd, libc::F_DUPFD_CLOEXEC, 50);
        assert!(fcntl_dup >= 50);

        // Close original read end; duplicated FDs must still work
        assert_eq!(libc::close(pfd[0]), 0);
        // Double close must fail with EBADF
        assert_eq!(libc::close(pfd[0]), -1);
        assert_eq!(*libc::__errno_location(), libc::EBADF);

        let mut ch = 0u8;
        assert_eq!(libc::read(fcntl_dup, &mut ch as *mut u8 as *mut libc::c_void, 1), 1);
        assert_eq!(libc::close(dup_fd), 0);
        assert_eq!(libc::close(fcntl_dup), 0);
        assert_eq!(libc::close(pfd[1]), 0);

        ch
    },
    |&ch| {
        assert_eq!(ch, b'Z');
    }
);

sandbox_test!(
    poll_and_ppoll_readiness,
    || unsafe {
        let mut pfd = [-1i32; 2];
        assert_eq!(libc::pipe(pfd.as_mut_ptr()), 0);

        let mut pollfds = [
            libc::pollfd {
                fd: -1,
                events: libc::POLLIN,
                revents: 99,
            },
            libc::pollfd {
                fd: pfd[1],
                events: libc::POLLOUT,
                revents: 0,
            },
            libc::pollfd {
                fd: 999,
                events: libc::POLLIN,
                revents: 0,
            },
        ];

        let ready = libc::poll(pollfds.as_mut_ptr(), pollfds.len() as libc::nfds_t, 0);
        assert_eq!(ready, 2);

        // Also test ppoll with a zero timespec
        let ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        let mut ppollfds = [libc::pollfd {
            fd: pfd[1],
            events: libc::POLLOUT,
            revents: 0,
        }];
        let pready = libc::syscall(
            libc::SYS_ppoll,
            ppollfds.as_mut_ptr(),
            1usize,
            &ts as *const libc::timespec,
            0usize,
            8usize,
        ) as i32;
        assert_eq!(pready, 1);

        // Invalid negative timespec in ppoll should return -EINVAL
        let bad_ts = libc::timespec {
            tv_sec: -1,
            tv_nsec: 0,
        };
        let bad_pready = libc::syscall(
            libc::SYS_ppoll,
            ppollfds.as_mut_ptr(),
            1usize,
            &bad_ts as *const libc::timespec,
            0usize,
            8usize,
        ) as i32;
        assert_eq!(bad_pready, -1);
        assert_eq!(*libc::__errno_location(), libc::EINVAL);

        libc::close(pfd[0]);
        libc::close(pfd[1]);

        (
            pollfds[0].revents,
            pollfds[1].revents,
            pollfds[2].revents,
            ppollfds[0].revents,
        )
    },
    |&(rev0, rev1, rev2, prev0)| {
        assert_eq!(rev0, 0);
        assert_eq!(rev1, libc::POLLOUT);
        assert_eq!(rev2, libc::POLLNVAL);
        assert_eq!(prev0, libc::POLLOUT);
    }
);

sandbox_test!(
    positional_io_sync_and_getcwd,
    || unsafe {
        let path = b"/tmp/ptrace_pio_test.dat\0";
        let fd = libc::open(
            path.as_ptr() as *const libc::c_char,
            libc::O_CREAT | libc::O_RDWR | libc::O_TRUNC,
            0o600,
        );
        assert!(fd >= 0);

        assert_eq!(
            libc::pwrite(fd, b"world".as_ptr() as *const libc::c_void, 5, 6),
            5
        );
        assert_eq!(
            libc::pwrite(fd, b"hello ".as_ptr() as *const libc::c_void, 6, 0),
            6
        );
        assert_eq!(libc::fsync(fd), 0);
        assert_eq!(libc::fdatasync(fd), 0);

        let mut buf = [0u8; 11];
        assert_eq!(
            libc::pread(fd, buf.as_mut_ptr() as *mut libc::c_void, 11, 0),
            11
        );
        assert_eq!(libc::close(fd), 0);
        assert_eq!(libc::unlink(path.as_ptr() as *const libc::c_char), 0);

        let cwd = std::env::current_dir().unwrap();
        let has_entries = std::fs::read_dir(&cwd).unwrap().next().is_some();

        (String::from_utf8(buf.to_vec()).unwrap(), has_entries)
    },
    |(content, has_entries)| {
        assert_eq!(content, "hello world");
        assert!(*has_entries);
    }
);
