#[macro_use]
mod common;

use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::thread;
use std::time::{Duration, Instant};

sandbox_test!(
    sleep_time_dilation,
    || {
        let start = Instant::now();
        thread::sleep(Duration::from_secs(10));
        let elapsed = start.elapsed();
        elapsed.as_secs()
    },
    |&secs| {
        assert_eq!(secs, 10);
    }
);

sandbox_test!(
    clock_nanosleep_relative_and_abstime,
    || unsafe {
        // 1. Relative sleep of 2 seconds
        let req_rel = libc::timespec {
            tv_sec: 2,
            tv_nsec: 0,
        };
        assert_eq!(
            libc::clock_nanosleep(
                libc::CLOCK_MONOTONIC,
                0,
                &req_rel,
                std::ptr::null_mut()
            ),
            0
        );
        let t_after_rel = libc::time(std::ptr::null_mut());

        // 2. Absolute sleep to 946684805 (3 more seconds)
        let req_abs = libc::timespec {
            tv_sec: 946684805,
            tv_nsec: 0,
        };
        assert_eq!(
            libc::clock_nanosleep(
                libc::CLOCK_REALTIME,
                libc::TIMER_ABSTIME,
                &req_abs,
                std::ptr::null_mut()
            ),
            0
        );
        let t_after_abs = libc::time(std::ptr::null_mut());

        (t_after_rel, t_after_abs)
    },
    |&(t_rel, t_abs)| {
        assert_eq!(t_rel, 946684802);
        assert_eq!(t_abs, 946684805);
    }
);

sandbox_test!(
    multithread_sleep_priority_wake_order,
    || {
        let order = Arc::new(Mutex::new(Vec::new()));

        let order1 = order.clone();
        let h1 = thread::spawn(move || {
            thread::sleep(Duration::from_secs(2));
            order1.lock().unwrap().push(1);
        });

        let order2 = order.clone();
        let h2 = thread::spawn(move || {
            thread::sleep(Duration::from_secs(1));
            order2.lock().unwrap().push(2);
        });

        let order3 = order.clone();
        let h3 = thread::spawn(move || {
            thread::sleep(Duration::from_secs(3));
            order3.lock().unwrap().push(3);
        });

        h2.join().unwrap();
        h1.join().unwrap();
        h3.join().unwrap();

        let final_order = order.lock().unwrap().clone();
        final_order
    },
    |order| {
        assert_eq!(
            order,
            &vec![2, 1, 3],
            "Threads must wake in virtual deadline order (1s, 2s, 3s)"
        );
    }
);

sandbox_test!(
    futex_wait_and_bitset_semantics,
    || unsafe {
        let futex_word = Arc::new(AtomicU32::new(10));

        // 1. Value mismatch returns -1 with EAGAIN
        let r_mismatch = libc::syscall(
            libc::SYS_futex,
            futex_word.as_ptr(),
            libc::FUTEX_WAIT | libc::FUTEX_PRIVATE_FLAG,
            999u32,
            std::ptr::null::<libc::timespec>(),
            std::ptr::null::<u32>(),
            0u32,
        );
        assert_eq!(r_mismatch, -1);
        assert_eq!(*libc::__errno_location(), libc::EAGAIN);

        // 2. FUTEX_WAIT_BITSET with bitset == 0 returns -1 with EINVAL
        let r_zero_bitset = libc::syscall(
            libc::SYS_futex,
            futex_word.as_ptr(),
            libc::FUTEX_WAIT_BITSET | libc::FUTEX_PRIVATE_FLAG,
            10u32,
            std::ptr::null::<libc::timespec>(),
            std::ptr::null::<u32>(),
            0u32,
        );
        assert_eq!(r_zero_bitset, -1);
        assert_eq!(*libc::__errno_location(), libc::EINVAL);

        // 3. Relative timeout advances virtual clock and returns ETIMEDOUT
        let ts = libc::timespec {
            tv_sec: 1,
            tv_nsec: 0,
        };
        let r_timeout = libc::syscall(
            libc::SYS_futex,
            futex_word.as_ptr(),
            libc::FUTEX_WAIT | libc::FUTEX_PRIVATE_FLAG,
            10u32,
            &ts as *const libc::timespec,
            std::ptr::null::<u32>(),
            0u32,
        );
        assert_eq!(r_timeout, -1);
        assert_eq!(*libc::__errno_location(), libc::ETIMEDOUT);
        let time_after = libc::time(std::ptr::null_mut());

        // 4. Selective wakeup with FUTEX_WAIT_BITSET / FUTEX_WAKE_BITSET
        let fw = futex_word.clone();
        let waiter = thread::spawn(move || {
            let ret = libc::syscall(
                libc::SYS_futex,
                fw.as_ptr(),
                libc::FUTEX_WAIT_BITSET | libc::FUTEX_PRIVATE_FLAG,
                10u32,
                std::ptr::null::<libc::timespec>(),
                std::ptr::null::<u32>(),
                0x02u32,
            );
            assert_eq!(ret, 0);
        });

        // Wait until the spawned thread enters FUTEX_WAIT_BITSET by sleeping 10ms in virtual time
        thread::sleep(Duration::from_millis(10));

        // Waking bit 0x01 should wake 0 threads
        let woken_wrong_bit = libc::syscall(
            libc::SYS_futex,
            futex_word.as_ptr(),
            libc::FUTEX_WAKE_BITSET | libc::FUTEX_PRIVATE_FLAG,
            1u32,
            std::ptr::null::<libc::timespec>(),
            std::ptr::null::<u32>(),
            0x01u32,
        );
        // Waking bit 0x02 should wake 1 thread
        let woken_right_bit = libc::syscall(
            libc::SYS_futex,
            futex_word.as_ptr(),
            libc::FUTEX_WAKE_BITSET | libc::FUTEX_PRIVATE_FLAG,
            1u32,
            std::ptr::null::<libc::timespec>(),
            std::ptr::null::<u32>(),
            0x02u32,
        );
        waiter.join().unwrap();

        (time_after, woken_wrong_bit, woken_right_bit)
    },
    |&(time_after, woken_wrong_bit, woken_right_bit)| {
        assert_eq!(time_after, 946684801);
        assert_eq!(woken_wrong_bit, 0);
        assert_eq!(woken_right_bit, 1);
    }
);

sandbox_test!(
    futex_cmp_requeue_and_wake_op,
    || unsafe {
        let uaddr1 = Arc::new(AtomicU32::new(1));
        let uaddr2 = Arc::new(AtomicU32::new(100));

        // 1. FUTEX_CMP_REQUEUE with wrong expected value returns EAGAIN
        let bad_req = libc::syscall(
            libc::SYS_futex,
            uaddr1.as_ptr(),
            libc::FUTEX_CMP_REQUEUE | libc::FUTEX_PRIVATE_FLAG,
            1u32,
            1usize,
            uaddr2.as_ptr(),
            999u32,
        );
        assert_eq!(bad_req, -1);
        assert_eq!(*libc::__errno_location(), libc::EAGAIN);

        // Spawn 2 threads waiting on uaddr1
        let mut handles = Vec::new();
        for _ in 0..2 {
            let f1 = uaddr1.clone();
            handles.push(thread::spawn(move || {
                let r = libc::syscall(
                    libc::SYS_futex,
                    f1.as_ptr(),
                    libc::FUTEX_WAIT | libc::FUTEX_PRIVATE_FLAG,
                    1u32,
                    std::ptr::null::<libc::timespec>(),
                    std::ptr::null::<u32>(),
                    0u32,
                );
                assert_eq!(r, 0);
            }));
        }

        thread::sleep(Duration::from_millis(10));

        // Wake 1 waiter on uaddr1 and requeue 1 waiter to uaddr2
        let req_res = libc::syscall(
            libc::SYS_futex,
            uaddr1.as_ptr(),
            libc::FUTEX_CMP_REQUEUE | libc::FUTEX_PRIVATE_FLAG,
            1u32,
            1usize,
            uaddr2.as_ptr(),
            1u32,
        );

        // Now use FUTEX_WAKE_OP to atomically set uaddr2 = 42 (FUTEX_OP_SET=0, oparg=42, FUTEX_OP_CMP_EQ=0, cmparg=100)
        // and wake the requeued waiter on uaddr2!
        let op_encoded: u32 = (0 << 28) | (0 << 24) | (42 << 12) | 100;
        let wake_op_res = libc::syscall(
            libc::SYS_futex,
            uaddr1.as_ptr(),
            libc::FUTEX_WAKE_OP | libc::FUTEX_PRIVATE_FLAG,
            1u32,
            1usize,
            uaddr2.as_ptr(),
            op_encoded,
        );

        for h in handles {
            h.join().unwrap();
        }

        (req_res, wake_op_res, uaddr2.load(Ordering::SeqCst))
    },
    |&(req_res, wake_op_res, u2_val)| {
        assert_eq!(req_res, 2);
        assert_eq!(wake_op_res, 1);
        assert_eq!(u2_val, 42);
    }
);

sandbox_test!(
    thread_spawn_and_barrier_synchronization,
    || {
        let n = 8;
        let barrier = Arc::new(Barrier::new(n));
        let counter = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::with_capacity(n);

        for i in 0..n {
            let b = barrier.clone();
            let c = counter.clone();
            handles.push(thread::spawn(move || {
                b.wait();
                c.fetch_add(i + 1, Ordering::SeqCst);
            }));
        }

        for h in handles {
            h.join().unwrap();
        }
        counter.load(Ordering::SeqCst)
    },
    |&sum| {
        assert_eq!(sum, 36);
    }
);

nondeterminism_test!(
    fork_wait4_and_signal_delivery,
    || unsafe {
        static USR1_COUNT: AtomicUsize = AtomicUsize::new(0);
        extern "C" fn on_usr1(_: i32) {
            USR1_COUNT.fetch_add(1, Ordering::SeqCst);
        }

        libc::signal(libc::SIGUSR1, on_usr1 as *const () as libc::sighandler_t);
        let raise_ret = libc::raise(libc::SIGUSR1);
        assert_eq!(raise_ret, 0);

        let cpid = libc::fork();
        if cpid == 0 {
            // Child signals itself with tkill and exits
            let my_tid = libc::syscall(libc::SYS_gettid) as i32;
            let _ = libc::syscall(libc::SYS_tkill, my_tid, libc::SIGUSR1);
            libc::_exit(7);
        }

        let mut status: i32 = 0;
        let mut ru: libc::rusage = std::mem::zeroed();
        ru.ru_utime.tv_sec = 999;
        let wpid = libc::wait4(cpid, &mut status, 0, &mut ru);
        let exit_status = libc::WEXITSTATUS(status);

        (
            cpid,
            wpid,
            exit_status,
            ru.ru_utime.tv_sec,
            USR1_COUNT.load(Ordering::SeqCst),
        )
    },
    |&(cpid, wpid, exit_status, ru_sec, usr1_count)| {
        assert_eq!(cpid, 1236);
        assert_eq!(wpid, 1236);
        assert_eq!(exit_status, 7);
        assert_eq!(ru_sec, 0);
        assert_eq!(usr1_count, 1);
    }
);
