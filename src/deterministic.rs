use crate::linux::{Linux, PollFd};
use crate::captured::CapturedProcess;
use crate::passthru::{Passthru, PassthruFd};
use libc::{c_int, c_void, mode_t, off_t};
use std::sync::{Arc, Mutex, Condvar};
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::net::SocketAddr;
use std::time::Duration;
use std::cmp::Ordering;

const DETERMINISTIC_UUID: &[u8] = b"42424242-4242-4242-4242-424242424242\n";

#[derive(Clone, Copy)]
pub enum DeterministicFd {
    Passthru(PassthruFd),
    Virtualized(c_int, usize),
    VirtualRandom(PassthruFd),
    VirtualUuid(PassthruFd, usize),
}

impl DeterministicFd {
    fn as_passthru_mut(&mut self) -> Option<&mut PassthruFd> {
        match self {
            DeterministicFd::Passthru(f)
            | DeterministicFd::VirtualRandom(f)
            | DeterministicFd::VirtualUuid(f, _) => Some(f),
            DeterministicFd::Virtualized(_, _) => None,
        }
    }
}

impl std::os::unix::io::AsRawFd for DeterministicFd {
    fn as_raw_fd(&self) -> c_int {
        match self {
            DeterministicFd::Passthru(f)
            | DeterministicFd::VirtualRandom(f)
            | DeterministicFd::VirtualUuid(f, _) => f.0,
            DeterministicFd::Virtualized(raw_fd, _) => *raw_fd,
        }
    }
}

struct VirtualSocket {
    addr: Option<SocketAddr>,
    is_listener: bool,
    backlog: Vec<usize>, // Indices of pending client sockets
    peer: Option<usize>, // Index of peer socket if connected
    read_buf: Vec<u8>,
    closed: bool,
    open_count: usize,
    nonblocking: bool,
}

struct NetworkInner {
    sockets: Vec<Arc<Mutex<VirtualSocket>>>,
    listeners: HashMap<SocketAddr, usize>,
    next_port: u16,
}

pub struct Network {
    inner: Mutex<NetworkInner>,
    condvar: Condvar,
}

impl Network {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(NetworkInner {
                sockets: Vec::new(),
                listeners: HashMap::new(),
                next_port: 1024,
            }),
            condvar: Condvar::new(),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct TimerEvent {
    target_time: Duration,
    waiter_id: usize,
}

impl Ord for TimerEvent {
    fn cmp(&self, other: &Self) -> Ordering {
        // Min-heap: smaller target_time has higher priority
        other.target_time.cmp(&self.target_time)
            .then_with(|| other.waiter_id.cmp(&self.waiter_id))
    }
}

impl PartialOrd for TimerEvent {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WaiterStatus {
    Waiting,
    TimerExpired,
    Woken,
}

#[derive(Debug, Clone, Copy)]
struct FutexWaiter {
    waiter_id: usize,
    bitset: u32,
}

struct TimeInner {
    current_time: Duration,
    tsc_ticks: u64,
    active_threads: usize,
    active_tids: HashSet<c_int>,
    blocked_threads: usize,
    next_waiter_id: usize,
    timers: BinaryHeap<TimerEvent>,
    waiters: HashMap<usize, WaiterStatus>,
    futex_waiters: HashMap<(u64, u64), Vec<FutexWaiter>>,
    ino_map: HashMap<u64, u64>,
    next_ino: u64,
    tid_map: HashMap<c_int, c_int>,
    rev_tid_map: HashMap<c_int, c_int>,
    next_tid: c_int,
    next_aspace_id: u64,
}

fn is_tid_kernel_sleeping(tid: c_int) -> bool {
    if let Ok(content) = std::fs::read_to_string(format!("/proc/{}/stat", tid)) {
        if let Some(rparen) = content.rfind(')') {
            if let Some(state_ch) = content.get(rparen + 2..rparen + 3) {
                return state_ch == "S" || state_ch == "D";
            }
        }
    }
    false
}

fn fnv1a_ino(path: &str) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for &b in path.as_bytes() {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    (hash & 0x7fff_ffff) + 1
}

pub struct TimeManager {
    inner: Mutex<TimeInner>,
    condvar: Condvar,
}

impl TimeManager {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(TimeInner {
                current_time: Duration::from_secs(946684800), // 2000-01-01 00:00:00 UTC
                tsc_ticks: 0,
                active_threads: 1,
                active_tids: HashSet::new(),
                blocked_threads: 0,
                next_waiter_id: 0,
                timers: BinaryHeap::new(),
                waiters: HashMap::new(),
                futex_waiters: HashMap::new(),
                ino_map: HashMap::new(),
                next_ino: 1,
                tid_map: HashMap::new(),
                rev_tid_map: HashMap::new(),
                next_tid: 1234,
                next_aspace_id: 2,
            }),
            condvar: Condvar::new(),
        }
    }

    pub fn allocate_aspace_id(&self) -> u64 {
        let mut inner = self.inner.lock().unwrap();
        let id = inner.next_aspace_id;
        inner.next_aspace_id += 1;
        id
    }

    fn get_or_assign_tid_locked(inner: &mut TimeInner, real_tid: c_int) -> c_int {
        if let Some(&det_tid) = inner.tid_map.get(&real_tid) {
            det_tid
        } else {
            let det_tid = inner.next_tid;
            inner.next_tid += 1;
            inner.tid_map.insert(real_tid, det_tid);
            inner.rev_tid_map.insert(det_tid, real_tid);
            det_tid
        }
    }

    pub fn register_exec_tid(&self, real_tid: c_int) -> c_int {
        let mut inner = self.inner.lock().unwrap();
        inner.active_tids.insert(real_tid);
        Self::get_or_assign_tid_locked(&mut inner, real_tid)
    }

    pub fn get_deterministic_tid(&self, real_tid: c_int) -> c_int {
        let mut inner = self.inner.lock().unwrap();
        Self::get_or_assign_tid_locked(&mut inner, real_tid)
    }

    pub fn get_real_tid(&self, det_tid: c_int) -> Option<c_int> {
        let inner = self.inner.lock().unwrap();
        inner.rev_tid_map.get(&det_tid).copied()
    }

    pub fn get_deterministic_ino(&self, orig_ino: u64, path_hint: Option<&str>) -> u64 {
        let mut inner = self.inner.lock().unwrap();
        if let Some(&det_ino) = inner.ino_map.get(&orig_ino) {
            return det_ino;
        }
        let det_ino = match path_hint.filter(|p| !p.is_empty()) {
            Some(p) => fnv1a_ino(p),
            None => {
                let ino = inner.next_ino;
                inner.next_ino += 1;
                ino
            }
        };
        inner.ino_map.insert(orig_ino, det_ino);
        det_ino
    }

    fn all_threads_blocked(inner: &TimeInner) -> bool {
        if inner.blocked_threads >= inner.active_threads {
            return true;
        }
        let kernel_sleeping = inner
            .active_tids
            .iter()
            .filter(|&&tid| is_tid_kernel_sleeping(tid))
            .count();
        inner.blocked_threads + kernel_sleeping >= inner.active_threads
    }

    fn maybe_advance_clock_locked(inner: &mut TimeInner, condvar: &Condvar) {
        if !inner.timers.is_empty() && Self::all_threads_blocked(inner) {
            if let Some(earliest) = inner.timers.peek() {
                let target = earliest.target_time;
                if target > inner.current_time {
                    inner.current_time = target;
                }
            }
            while let Some(earliest) = inner.timers.peek() {
                if earliest.target_time <= inner.current_time {
                    let timer = inner.timers.pop().unwrap();
                    if let Some(status) = inner.waiters.get_mut(&timer.waiter_id) {
                        if *status == WaiterStatus::Waiting {
                            *status = WaiterStatus::TimerExpired;
                            if inner.blocked_threads > 0 {
                                inner.blocked_threads -= 1;
                            }
                        }
                    }
                } else {
                    break;
                }
            }
            condvar.notify_all();
        }
    }

    pub fn get_time(&self) -> Duration {
        let inner = self.inner.lock().unwrap();
        inner.current_time
    }

    pub fn next_tsc(&self) -> u64 {
        let mut inner = self.inner.lock().unwrap();
        let nanos = inner.current_time.as_nanos() as u64;
        let tsc = 1_000_000_000u64
            .wrapping_add(nanos.wrapping_mul(3))
            .wrapping_add(inner.tsc_ticks);
        inner.tsc_ticks = inner.tsc_ticks.wrapping_add(1);
        tsc
    }

    pub fn register_thread(&self, real_tid: c_int) {
        let mut inner = self.inner.lock().unwrap();
        inner.active_threads += 1;
        inner.active_tids.insert(real_tid);
    }

    pub fn enter_blocking(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.blocked_threads += 1;
        Self::maybe_advance_clock_locked(&mut inner, &self.condvar);
    }

    pub fn exit_blocking(&self) {
        let mut inner = self.inner.lock().unwrap();
        if inner.blocked_threads > 0 {
            inner.blocked_threads -= 1;
        }
    }

    fn wait_for_timer_locked<'a>(
        &'a self,
        mut inner: std::sync::MutexGuard<'a, TimeInner>,
        proc: &CapturedProcess,
        target_time: Duration,
    ) -> nix::Result<()> {
        if target_time <= inner.current_time {
            return Ok(());
        }

        let waiter_id = inner.next_waiter_id;
        inner.next_waiter_id += 1;

        inner.timers.push(TimerEvent {
            target_time,
            waiter_id,
        });
        inner.waiters.insert(waiter_id, WaiterStatus::Waiting);
        inner.blocked_threads += 1;

        Self::maybe_advance_clock_locked(&mut inner, &self.condvar);

        while inner.waiters.get(&waiter_id) == Some(&WaiterStatus::Waiting) {
            if !proc.is_alive() {
                inner.waiters.remove(&waiter_id);
                if inner.blocked_threads > 0 {
                    inner.blocked_threads -= 1;
                }
                return Err(nix::Error::ESRCH);
            }

            let (new_inner, timeout_res) = self.condvar.wait_timeout(inner, Duration::from_millis(5)).unwrap();
            inner = new_inner;

            if timeout_res.timed_out() {
                if !proc.is_alive() {
                    inner.waiters.remove(&waiter_id);
                    if inner.blocked_threads > 0 {
                        inner.blocked_threads -= 1;
                    }
                    return Err(nix::Error::ESRCH);
                }
                Self::maybe_advance_clock_locked(&mut inner, &self.condvar);
            }
        }

        inner.waiters.remove(&waiter_id);
        Ok(())
    }

    pub fn sleep(&self, proc: &CapturedProcess, dur: Duration) -> nix::Result<()> {
        let inner = self.inner.lock().unwrap();
        let target_time = inner.current_time + dur;
        self.wait_for_timer_locked(inner, proc, target_time)
    }

    pub fn sleep_until(&self, proc: &CapturedProcess, target_time: Duration) -> nix::Result<()> {
        let inner = self.inner.lock().unwrap();
        self.wait_for_timer_locked(inner, proc, target_time)
    }

    fn cleanup_waiter(&self, inner: &mut TimeInner, waiter_id: usize) {
        inner.futex_waiters.retain(|_, list| {
            list.retain(|w| w.waiter_id != waiter_id);
            !list.is_empty()
        });
        if let Some(status) = inner.waiters.remove(&waiter_id) {
            if status == WaiterStatus::Waiting && inner.blocked_threads > 0 {
                inner.blocked_threads -= 1;
            }
        }
    }

    pub fn futex_wait(
        &self,
        proc: &CapturedProcess,
        key: (u64, u64),
        uaddr: u64,
        val: u32,
        bitset: u32,
        timeout: Option<Duration>,
        is_abstime: bool,
    ) -> nix::Result<c_int> {
        let mut inner = self.inner.lock().unwrap();

        // Read current value from guest memory before registering waiter or advancing clock
        let bytes = proc.read_memory(uaddr as usize, 4);
        if bytes.len() < 4 {
            return Err(nix::Error::EFAULT);
        }
        let current_val = u32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if current_val != val {
            return Err(nix::Error::EAGAIN);
        }

        if let Some(dur) = timeout {
            if is_abstime && dur <= inner.current_time {
                return Err(nix::Error::ETIMEDOUT);
            }
            if !is_abstime && dur.is_zero() {
                return Err(nix::Error::ETIMEDOUT);
            }
        }

        let waiter_id = inner.next_waiter_id;
        inner.next_waiter_id += 1;
        inner
            .futex_waiters
            .entry(key)
            .or_default()
            .push(FutexWaiter { waiter_id, bitset });
        inner.waiters.insert(waiter_id, WaiterStatus::Waiting);
        inner.blocked_threads += 1;

        if let Some(dur) = timeout {
            let target_time = if is_abstime {
                dur
            } else {
                inner.current_time + dur
            };
            inner.timers.push(TimerEvent {
                target_time,
                waiter_id,
            });
        }

        Self::maybe_advance_clock_locked(&mut inner, &self.condvar);

        while inner.waiters.get(&waiter_id) == Some(&WaiterStatus::Waiting) {
            if !proc.is_alive() {
                self.cleanup_waiter(&mut inner, waiter_id);
                return Err(nix::Error::ESRCH);
            }

            let (new_inner, timeout_res) = self.condvar.wait_timeout(inner, Duration::from_millis(5)).unwrap();
            inner = new_inner;

            if timeout_res.timed_out() {
                if !proc.is_alive() {
                    self.cleanup_waiter(&mut inner, waiter_id);
                    return Err(nix::Error::ESRCH);
                }
                Self::maybe_advance_clock_locked(&mut inner, &self.condvar);
            }
        }

        let final_status = inner.waiters.remove(&waiter_id);
        self.cleanup_waiter(&mut inner, waiter_id);

        match final_status {
            Some(WaiterStatus::Woken) => Ok(0),
            Some(WaiterStatus::TimerExpired) => Err(nix::Error::ETIMEDOUT),
            _ => Ok(0),
        }
    }

    fn wake_locked(inner: &mut TimeInner, key: (u64, u64), val: u32, bitset: u32) -> usize {
        let mut woken_ids = Vec::new();
        if let Some(list) = inner.futex_waiters.get_mut(&key) {
            let mut i = 0;
            while i < list.len() && woken_ids.len() < val as usize {
                if (list[i].bitset & bitset) != 0 {
                    let w = list.remove(i);
                    woken_ids.push(w.waiter_id);
                } else {
                    i += 1;
                }
            }
            if list.is_empty() {
                inner.futex_waiters.remove(&key);
            }
        }
        let woken_count = woken_ids.len();
        for id in woken_ids {
            if let Some(status) = inner.waiters.get_mut(&id) {
                if *status == WaiterStatus::Waiting {
                    *status = WaiterStatus::Woken;
                    if inner.blocked_threads > 0 {
                        inner.blocked_threads -= 1;
                    }
                }
            }
        }
        woken_count
    }

    pub fn futex_wake(&self, key: (u64, u64), val: u32, bitset: u32) -> nix::Result<c_int> {
        let mut inner = self.inner.lock().unwrap();
        let woken = Self::wake_locked(&mut inner, key, val, bitset);
        if woken > 0 {
            self.condvar.notify_all();
        }
        Ok(woken as c_int)
    }

    pub fn futex_requeue(
        &self,
        proc: &CapturedProcess,
        key1: (u64, u64),
        key2: (u64, u64),
        uaddr1: u64,
        nr_wake: u32,
        nr_requeue: u32,
        cmp_val: Option<u32>,
    ) -> nix::Result<c_int> {
        let mut inner = self.inner.lock().unwrap();
        if let Some(expected) = cmp_val {
            let bytes = proc.read_memory(uaddr1 as usize, 4);
            if bytes.len() < 4 {
                return Err(nix::Error::EFAULT);
            }
            let current_val = u32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            if current_val != expected {
                return Err(nix::Error::EAGAIN);
            }
        }
        let woken = Self::wake_locked(&mut inner, key1, nr_wake, u32::MAX);
        let mut requeued = Vec::new();
        if key1 != key2 && nr_requeue > 0 {
            if let Some(list1) = inner.futex_waiters.get_mut(&key1) {
                let n = std::cmp::min(nr_requeue as usize, list1.len());
                requeued = list1.drain(0..n).collect();
                if list1.is_empty() {
                    inner.futex_waiters.remove(&key1);
                }
            }
        }
        let req_count = requeued.len();
        if req_count > 0 {
            inner.futex_waiters.entry(key2).or_default().extend(requeued);
        }
        if woken > 0 {
            self.condvar.notify_all();
        }
        Ok((woken + req_count) as c_int)
    }

    pub fn on_exit(&self, real_tid: c_int, aspace_id: u64, tid_address: Option<u64>) {
        let mut inner = self.inner.lock().unwrap();
        inner.active_tids.remove(&real_tid);
        if let Some(addr) = tid_address {
            let _ = Self::wake_locked(&mut inner, (aspace_id, addr), u32::MAX, u32::MAX);
        }
        if inner.active_threads > 0 {
            inner.active_threads -= 1;
        }
        Self::maybe_advance_clock_locked(&mut inner, &self.condvar);
        self.condvar.notify_all();
    }
}

pub struct Deterministic {
    passthru: Passthru,
    network: Arc<Network>,
    time_manager: Arc<TimeManager>,
    tid_address: Option<u64>,
    aspace_id: u64,
}

impl Deterministic {
    pub fn new(verbose: bool) -> Self {
        Self {
            passthru: Passthru::new(verbose),
            network: Arc::new(Network::new()),
            time_manager: Arc::new(TimeManager::new()),
            tid_address: None,
            aspace_id: 1,
        }
    }

    pub fn with_tid(
        verbose: bool,
        network: Arc<Network>,
        time_manager: Arc<TimeManager>,
        tid_address: Option<u64>,
        aspace_id: u64,
    ) -> Self {
        Self {
            passthru: Passthru::new(verbose),
            network,
            time_manager,
            tid_address,
            aspace_id,
        }
    }

    fn patch_stat(&self, proc: &CapturedProcess, addr: usize, path_hint: Option<&str>) {
        // struct stat on x86_64:
        // st_dev (0..8), st_ino (8..16), st_uid (28..28+4), st_gid (32..36),
        // atime (72..88), mtime (88..104), ctime (104..120)
        
        let mut bytes = proc.read_memory(addr, 120); // Only need up to ctime
        if bytes.len() < 120 { return; }
        
        let orig_ino = u64::from_ne_bytes(bytes[8..16].try_into().unwrap());
        let det_ino = self.time_manager.get_deterministic_ino(orig_ino, path_hint);
        bytes[0..8].copy_from_slice(&1u64.to_ne_bytes());
        bytes[8..16].copy_from_slice(&det_ino.to_ne_bytes());
        bytes[28..32].copy_from_slice(&1000u32.to_ne_bytes());
        bytes[32..36].copy_from_slice(&1000u32.to_ne_bytes());
        // Zero out timestamps (atim 72..88, mtim 88..104, ctim 104..120)
        for i in 72..120 { bytes[i] = 0; }
        
        proc.write_memory(addr, &bytes);
        if self.passthru.verbose {
            println!("patch_stat({:#x}) (DETERMINISTIC)", addr);
        }
    }

    fn patch_statx(&self, proc: &CapturedProcess, addr: usize, path_hint: Option<&str>) {
        // struct statx on x86_64:
        // stx_uid (20..24), stx_gid (24..28), stx_ino (32..40),
        // stx_atime (64..80), stx_btime (80..96), stx_ctime (96..112), stx_mtime (112..128),
        // stx_dev_major (136..140), stx_dev_minor (140..144)
        let mut bytes = proc.read_memory(addr, 144);
        if bytes.len() < 144 { return; }

        let orig_ino = u64::from_ne_bytes(bytes[32..40].try_into().unwrap());
        let det_ino = self.time_manager.get_deterministic_ino(orig_ino, path_hint);
        bytes[20..24].copy_from_slice(&1000u32.to_ne_bytes());
        bytes[24..28].copy_from_slice(&1000u32.to_ne_bytes());
        bytes[32..40].copy_from_slice(&det_ino.to_ne_bytes());
        for i in 64..128 { bytes[i] = 0; }
        bytes[136..140].copy_from_slice(&0u32.to_ne_bytes());
        bytes[140..144].copy_from_slice(&1u32.to_ne_bytes());

        proc.write_memory(addr, &bytes);
        if self.passthru.verbose {
            println!("patch_statx({:#x}) (DETERMINISTIC)", addr);
        }
    }

    fn write_virtual_socket_stat(&self, proc: &CapturedProcess, buf_addr: u64) -> nix::Result<c_int> {
        self.skip_syscall(proc);
        if buf_addr == 0 {
            return Err(nix::Error::EFAULT);
        }
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        st.st_dev = 1;
        st.st_ino = 1;
        st.st_nlink = 1;
        st.st_mode = libc::S_IFSOCK | 0o666;
        st.st_uid = 1000;
        st.st_gid = 1000;
        st.st_blksize = 4096;
        let bytes = unsafe {
            std::slice::from_raw_parts(
                &st as *const libc::stat as *const u8,
                std::mem::size_of::<libc::stat>(),
            )
        };
        proc.write_memory(buf_addr as usize, bytes);
        Ok(0)
    }

    fn skip_syscall(&self, proc: &CapturedProcess) -> i64 {
        proc.skip_syscall().unwrap_or(0)
    }

    fn classify_opened_fd(&self, proc: &CapturedProcess, pathname: &str, fd: PassthruFd) -> DeterministicFd {
        use std::os::unix::io::AsRawFd;
        let resolved = std::fs::read_link(format!("/proc/{}/fd/{}", proc.pid.as_raw(), fd.as_raw_fd()))
            .ok()
            .and_then(|p| p.to_str().map(|s| s.to_string()));
        let check_path = resolved.as_deref().unwrap_or(pathname);
        if check_path == "/dev/urandom"
            || check_path == "/dev/random"
            || pathname.ends_with("/dev/urandom")
            || pathname.ends_with("/dev/random")
        {
            DeterministicFd::VirtualRandom(fd)
        } else if check_path == "/proc/sys/kernel/random/uuid"
            || check_path == "/proc/sys/kernel/random/boot_id"
            || check_path == "/etc/machine-id"
            || check_path == "/var/lib/dbus/machine-id"
            || pathname.ends_with("/proc/sys/kernel/random/uuid")
            || pathname.ends_with("/proc/sys/kernel/random/boot_id")
            || pathname.ends_with("/etc/machine-id")
            || pathname.ends_with("/var/lib/dbus/machine-id")
        {
            DeterministicFd::VirtualUuid(fd, 0)
        } else {
            DeterministicFd::Passthru(fd)
        }
    }

    fn fd_path_hint(&self, proc: &CapturedProcess, raw_fd: c_int) -> Option<String> {
        std::fs::read_link(format!("/proc/{}/fd/{}", proc.pid.as_raw(), raw_fd))
            .ok()
            .and_then(|p| p.to_str().map(|s| s.to_string()))
    }
}

impl Linux<DeterministicFd> for Deterministic {
    fn default_fds(&mut self) -> (DeterministicFd, DeterministicFd, DeterministicFd) {
        let (in_fd, out_fd, err_fd) = self.passthru.default_fds();
        (DeterministicFd::Passthru(in_fd), DeterministicFd::Passthru(out_fd), DeterministicFd::Passthru(err_fd))
    }

    fn dup_fd(&mut self, fd: &DeterministicFd) -> DeterministicFd {
        match fd {
            DeterministicFd::Passthru(f) => DeterministicFd::Passthru(self.passthru.dup_fd(f)),
            DeterministicFd::Virtualized(raw_fd, idx) => {
                let inner = self.network.inner.lock().unwrap();
                let mut sock = inner.sockets[*idx].lock().unwrap();
                sock.open_count += 1;
                DeterministicFd::Virtualized(*raw_fd, *idx)
            }
            DeterministicFd::VirtualRandom(f) => DeterministicFd::VirtualRandom(self.passthru.dup_fd(f)),
            DeterministicFd::VirtualUuid(f, off) => DeterministicFd::VirtualUuid(self.passthru.dup_fd(f), *off),
        }
    }

    fn dup_fd_to(&mut self, fd: &DeterministicFd, new_raw_fd: c_int) -> DeterministicFd {
        match fd {
            DeterministicFd::Passthru(_) => DeterministicFd::Passthru(PassthruFd(new_raw_fd)),
            DeterministicFd::Virtualized(_, idx) => {
                let inner = self.network.inner.lock().unwrap();
                let mut sock = inner.sockets[*idx].lock().unwrap();
                sock.open_count += 1;
                DeterministicFd::Virtualized(new_raw_fd, *idx)
            }
            DeterministicFd::VirtualRandom(_) => DeterministicFd::VirtualRandom(PassthruFd(new_raw_fd)),
            DeterministicFd::VirtualUuid(_, off) => DeterministicFd::VirtualUuid(PassthruFd(new_raw_fd), *off),
        }
    }

    fn on_fd_overwritten(&mut self, fd: DeterministicFd) {
        if let DeterministicFd::Virtualized(_, idx) = fd {
            self.release_virtual_socket(idx);
        }
    }

    fn wrap_raw_fd(&mut self, proc: &CapturedProcess, raw_fd: c_int) -> DeterministicFd {
        self.classify_opened_fd(proc, "", PassthruFd(raw_fd))
    }

    fn dup(&mut self, proc: &CapturedProcess, oldfd: &DeterministicFd) -> nix::Result<DeterministicFd> {
        use std::os::unix::io::AsRawFd;
        let res = proc.dup(oldfd.as_raw_fd())?;
        Ok(self.dup_fd_to(oldfd, res as c_int))
    }

    fn dup2(&mut self, proc: &CapturedProcess, oldfd: &DeterministicFd, newfd: c_int) -> nix::Result<DeterministicFd> {
        use std::os::unix::io::AsRawFd;
        let res = proc.dup2(oldfd.as_raw_fd(), newfd)?;
        Ok(self.dup_fd_to(oldfd, res as c_int))
    }

    fn dup3(&mut self, proc: &CapturedProcess, oldfd: &DeterministicFd, newfd: c_int, flags: c_int) -> nix::Result<DeterministicFd> {
        use std::os::unix::io::AsRawFd;
        let res = proc.dup3(oldfd.as_raw_fd(), newfd, flags)?;
        Ok(self.dup_fd_to(oldfd, res as c_int))
    }

    fn write(&mut self, proc: &CapturedProcess, fd: &mut DeterministicFd, buf: &[u8]) -> nix::Result<usize> {
        match fd {
            DeterministicFd::Passthru(f) | DeterministicFd::VirtualRandom(f) | DeterministicFd::VirtualUuid(f, _) => {
                self.passthru.write(proc, f, buf)
            }
            DeterministicFd::Virtualized(_, idx) => self.virtual_write(proc, *idx, buf),
        }
    }

    fn read(&mut self, proc: &CapturedProcess, fd: &mut DeterministicFd, count: usize) -> nix::Result<Vec<u8>> {
        match fd {
            DeterministicFd::Passthru(f) => self.passthru.read(proc, f, count),
            DeterministicFd::Virtualized(_, idx) => self.virtual_read(proc, *idx, count, 0),
            DeterministicFd::VirtualRandom(_) => {
                self.skip_syscall(proc);
                let n = std::cmp::min(count, 65536);
                if self.passthru.verbose {
                    println!("read(urandom, ..., {}) = {} (DETERMINISTIC)", count, n);
                }
                Ok(vec![0x42u8; n])
            }
            DeterministicFd::VirtualUuid(_, off) => {
                self.skip_syscall(proc);
                if *off >= DETERMINISTIC_UUID.len() {
                    return Ok(Vec::new());
                }
                let rem = &DETERMINISTIC_UUID[*off..];
                let n = std::cmp::min(count, rem.len());
                *off += n;
                Ok(rem[..n].to_vec())
            }
        }
    }

    fn open(&mut self, proc: &CapturedProcess, pathname: &str, flags: c_int, mode: mode_t) -> nix::Result<DeterministicFd> {
        let fd = self.passthru.open(proc, pathname, flags, mode)?;
        Ok(self.classify_opened_fd(proc, pathname, fd))
    }

    fn openat(&mut self, proc: &CapturedProcess, dirfd: Option<&mut DeterministicFd>, pathname: &str, flags: c_int, mode: mode_t) -> nix::Result<DeterministicFd> {
        let p_dirfd = dirfd.and_then(|d| d.as_passthru_mut());
        let fd = self.passthru.openat(proc, p_dirfd, pathname, flags, mode)?;
        Ok(self.classify_opened_fd(proc, pathname, fd))
    }

    fn close(&mut self, proc: &CapturedProcess, fd: DeterministicFd) -> nix::Result<c_int> {
        match fd {
            DeterministicFd::Passthru(f) | DeterministicFd::VirtualRandom(f) | DeterministicFd::VirtualUuid(f, _) => {
                self.passthru.close(proc, f)
            }
            DeterministicFd::Virtualized(raw_fd, idx) => self.virtual_close(proc, raw_fd, idx),
        }
    }

    fn stat(&mut self, proc: &CapturedProcess, pathname: &str) -> nix::Result<c_int> {
        let regs = proc.get_regs()?;
        let res = self.passthru.stat(proc, pathname)?;
        if res == 0 {
            self.patch_stat(proc, regs.rsi as usize, Some(pathname));
        }
        Ok(res)
    }

    fn lstat(&mut self, proc: &CapturedProcess, pathname: &str) -> nix::Result<c_int> {
        let regs = proc.get_regs()?;
        let res = self.passthru.lstat(proc, pathname)?;
        if res == 0 {
            self.patch_stat(proc, regs.rsi as usize, Some(pathname));
        }
        Ok(res)
    }

    fn fstat(&mut self, proc: &CapturedProcess, fd: &mut DeterministicFd) -> nix::Result<c_int> {
        use std::os::unix::io::AsRawFd;
        match fd {
            DeterministicFd::Passthru(f) | DeterministicFd::VirtualRandom(f) | DeterministicFd::VirtualUuid(f, _) => {
                let regs = proc.get_regs()?;
                let raw = f.as_raw_fd();
                let res = self.passthru.fstat(proc, f)?;
                if res == 0 {
                    let hint = self.fd_path_hint(proc, raw);
                    self.patch_stat(proc, regs.rsi as usize, hint.as_deref());
                }
                Ok(res)
            }
            DeterministicFd::Virtualized(_, _) => {
                let regs = proc.get_regs()?;
                self.write_virtual_socket_stat(proc, regs.rsi)
            }
        }
    }

    fn newfstatat(&mut self, proc: &CapturedProcess, dirfd: Option<&mut DeterministicFd>, pathname: &str, flags: c_int) -> nix::Result<c_int> {
        use std::os::unix::io::AsRawFd;
        if let Some(DeterministicFd::Virtualized(_, _)) = dirfd {
            if (flags & libc::AT_EMPTY_PATH) != 0 && pathname.is_empty() {
                let regs = proc.get_regs()?;
                return self.write_virtual_socket_stat(proc, regs.rdx);
            }
        }
        let p_dirfd = dirfd.and_then(|d| d.as_passthru_mut());
        let raw_dirfd = p_dirfd.as_ref().map(|f| f.as_raw_fd());
        let regs = proc.get_regs()?;
        let res = self.passthru.newfstatat(proc, p_dirfd, pathname, flags)?;
        if res == 0 {
            let hint = if !pathname.is_empty() {
                Some(pathname.to_string())
            } else {
                raw_dirfd.and_then(|r| self.fd_path_hint(proc, r))
            };
            self.patch_stat(proc, regs.rdx as usize, hint.as_deref());
        }
        Ok(res)
    }

    fn statx(&mut self, proc: &CapturedProcess, dirfd: Option<&mut DeterministicFd>, pathname: &str, flags: c_int, mask: libc::c_uint) -> nix::Result<c_int> {
        use std::os::unix::io::AsRawFd;
        if let Some(DeterministicFd::Virtualized(_, _)) = dirfd {
            if (flags & libc::AT_EMPTY_PATH) != 0 && pathname.is_empty() {
                let regs = proc.get_regs()?;
                self.skip_syscall(proc);
                if regs.r8 == 0 {
                    return Err(nix::Error::EFAULT);
                }
                let mut stx: libc::statx = unsafe { std::mem::zeroed() };
                stx.stx_mask = mask;
                stx.stx_blksize = 4096;
                stx.stx_nlink = 1;
                stx.stx_uid = 1000;
                stx.stx_gid = 1000;
                stx.stx_mode = (libc::S_IFSOCK | 0o666) as u16;
                stx.stx_ino = 1;
                stx.stx_dev_major = 0;
                stx.stx_dev_minor = 1;
                let bytes = unsafe {
                    std::slice::from_raw_parts(
                        &stx as *const libc::statx as *const u8,
                        std::mem::size_of::<libc::statx>(),
                    )
                };
                proc.write_memory(regs.r8 as usize, bytes);
                return Ok(0);
            }
        }
        let p_dirfd = dirfd.and_then(|d| d.as_passthru_mut());
        let raw_dirfd = p_dirfd.as_ref().map(|f| f.as_raw_fd());
        let regs = proc.get_regs()?;
        let res = self.passthru.statx(proc, p_dirfd, pathname, flags, mask)?;
        if res == 0 {
            let hint = if !pathname.is_empty() {
                Some(pathname.to_string())
            } else {
                raw_dirfd.and_then(|r| self.fd_path_hint(proc, r))
            };
            self.patch_statx(proc, regs.r8 as usize, hint.as_deref());
        }
        Ok(res)
    }

    fn mmap(&mut self, proc: &CapturedProcess, addr: *mut c_void, length: usize, prot: c_int, flags: c_int, fd: Option<&mut DeterministicFd>, offset: off_t) -> nix::Result<*mut c_void> {
        let p_fd = fd.and_then(|d| d.as_passthru_mut());
        self.passthru.mmap(proc, addr, length, prot, flags, p_fd, offset)
    }

    fn munmap(&mut self, proc: &CapturedProcess, addr: *mut c_void, length: usize) -> nix::Result<c_int> {
        self.passthru.munmap(proc, addr, length)
    }

    fn exit(&mut self, proc: &CapturedProcess, status: c_int) -> nix::Result<()> {
        self.passthru.exit(proc, status)
    }

    fn exit_group(&mut self, proc: &CapturedProcess, status: c_int) -> nix::Result<()> {
        self.passthru.exit_group(proc, status)
    }

    fn brk(&mut self, proc: &CapturedProcess, addr: *mut c_void) -> nix::Result<*mut c_void> {
        self.passthru.brk(proc, addr)
    }

    fn clock_gettime(&mut self, proc: &CapturedProcess, clk_id: libc::clockid_t) -> nix::Result<c_int> {
        let regs = proc.get_regs()?;
        let tp_addr = regs.rsi as usize;
        self.skip_syscall(proc);
        if tp_addr == 0 {
            return Err(nix::Error::EFAULT);
        }
        
        let current_time = self.time_manager.get_time();
        let tv_sec: i64 = current_time.as_secs() as i64;
        let tv_nsec: i64 = current_time.subsec_nanos() as i64;
        
        let mut bytes = Vec::with_capacity(16);
        bytes.extend_from_slice(&tv_sec.to_ne_bytes());
        bytes.extend_from_slice(&tv_nsec.to_ne_bytes());
        
        proc.write_memory(tp_addr, &bytes);
        
        if self.passthru.verbose {
            println!("clock_gettime({}, ...) = 0 (DETERMINISTIC)", clk_id);
        }
        Ok(0)
    }

    fn fork(&mut self, proc: &CapturedProcess) -> nix::Result<(nix::unistd::Pid, Box<dyn Linux<DeterministicFd> + Send>)> {
        let (pid, _) = self.passthru.fork(proc)?;
        let new_aspace = self.time_manager.allocate_aspace_id();
        Ok((pid, Box::new(Deterministic::with_tid(self.passthru.verbose, self.network.clone(), self.time_manager.clone(), None, new_aspace))))
    }

    fn vfork(&mut self, proc: &CapturedProcess) -> nix::Result<(nix::unistd::Pid, Box<dyn Linux<DeterministicFd> + Send>)> {
        let (pid, _) = self.passthru.vfork(proc)?;
        let new_aspace = self.time_manager.allocate_aspace_id();
        Ok((pid, Box::new(Deterministic::with_tid(self.passthru.verbose, self.network.clone(), self.time_manager.clone(), None, new_aspace))))
    }

    fn clone(&mut self, proc: &CapturedProcess, flags: c_int, tid_address: Option<*mut c_int>) -> nix::Result<(nix::unistd::Pid, Box<dyn Linux<DeterministicFd> + Send>)> {
        let (pid, _) = self.passthru.clone(proc, flags, tid_address)?;
        let child_aspace = if (flags & libc::CLONE_VM) != 0 {
            self.aspace_id
        } else {
            self.time_manager.allocate_aspace_id()
        };
        Ok((pid, Box::new(Deterministic::with_tid(self.passthru.verbose, self.network.clone(), self.time_manager.clone(), tid_address.map(|a| a as u64), child_aspace))))
    }

    fn socket(&mut self, proc: &CapturedProcess, domain: c_int, ty: c_int, protocol: c_int) -> nix::Result<DeterministicFd> {
        if self.passthru.verbose {
            println!("socket({}, {}, {}) (VIRTUAL)", domain, ty, protocol);
        }
        let mut efd_flags = 0;
        if (ty & libc::SOCK_CLOEXEC) != 0 {
            efd_flags |= libc::EFD_CLOEXEC;
        }
        let nonblocking = (ty & libc::SOCK_NONBLOCK) != 0;
        if nonblocking {
            efd_flags |= libc::EFD_NONBLOCK;
        }
        let raw_fd = proc.eventfd2(0, efd_flags)? as c_int;
        let sock = VirtualSocket {
            addr: None,
            is_listener: false,
            backlog: Vec::new(),
            peer: None,
            read_buf: Vec::new(),
            closed: false,
            open_count: 1,
            nonblocking,
        };
        let mut inner = self.network.inner.lock().unwrap();
        let idx = inner.sockets.len();
        inner.sockets.push(Arc::new(Mutex::new(sock)));
        Ok(DeterministicFd::Virtualized(raw_fd, idx))
    }

    fn bind(&mut self, proc: &CapturedProcess, fd: &mut DeterministicFd, addr: *const libc::sockaddr, len: libc::socklen_t) -> nix::Result<c_int> {
        match fd {
            DeterministicFd::Passthru(f) | DeterministicFd::VirtualRandom(f) | DeterministicFd::VirtualUuid(f, _) => {
                self.passthru.bind(proc, f, addr, len)
            }
            DeterministicFd::Virtualized(_, idx) => {
                self.skip_syscall(proc);
                let mut sock_addr = unsafe { self.read_sockaddr(proc, addr, len)? };
                if self.passthru.verbose {
                    println!("bind({}, {:?}) (VIRTUAL)", idx, sock_addr);
                }
                let mut inner = self.network.inner.lock().unwrap();
                
                if sock_addr.port() == 0 {
                    let port = inner.next_port;
                    inner.next_port += 1;
                    match sock_addr {
                        SocketAddr::V4(mut addr4) => {
                            addr4.set_port(port);
                            sock_addr = SocketAddr::V4(addr4);
                        }
                        SocketAddr::V6(mut addr6) => {
                            addr6.set_port(port);
                            sock_addr = SocketAddr::V6(addr6);
                        }
                    }
                }

                {
                    let mut sock = inner.sockets[*idx].lock().unwrap();
                    sock.addr = Some(sock_addr);
                }
                inner.listeners.insert(sock_addr, *idx);
                Ok(0)
            }
        }
    }

    fn listen(&mut self, proc: &CapturedProcess, fd: &mut DeterministicFd, backlog: c_int) -> nix::Result<c_int> {
        match fd {
            DeterministicFd::Passthru(f) | DeterministicFd::VirtualRandom(f) | DeterministicFd::VirtualUuid(f, _) => {
                self.passthru.listen(proc, f, backlog)
            }
            DeterministicFd::Virtualized(_, idx) => {
                if self.passthru.verbose {
                    println!("listen({}, {}) (VIRTUAL)", idx, backlog);
                }
                self.skip_syscall(proc);
                let inner = self.network.inner.lock().unwrap();
                let mut sock = inner.sockets[*idx].lock().unwrap();
                sock.is_listener = true;
                Ok(0)
            }
        }
    }

    fn accept(&mut self, proc: &CapturedProcess, fd: &mut DeterministicFd, addr: *mut libc::sockaddr, len: *mut libc::socklen_t) -> nix::Result<DeterministicFd> {
        self.accept4(proc, fd, addr, len, 0)
    }

    fn accept4(&mut self, proc: &CapturedProcess, fd: &mut DeterministicFd, addr: *mut libc::sockaddr, len: *mut libc::socklen_t, flags: c_int) -> nix::Result<DeterministicFd> {
        match fd {
            DeterministicFd::Passthru(f) | DeterministicFd::VirtualRandom(f) | DeterministicFd::VirtualUuid(f, _) => {
                self.passthru.accept4(proc, f, addr, len, flags).map(DeterministicFd::Passthru)
            }
            DeterministicFd::Virtualized(_, idx) => {
                loop {
                    let mut inner = self.network.inner.lock().unwrap();
                    let (res, is_nonblocking) = {
                        let mut sock = inner.sockets[*idx].lock().unwrap();
                        if !sock.backlog.is_empty() {
                            let c_idx = sock.backlog.remove(0);
                            let mut c_sock = inner.sockets[c_idx].lock().unwrap();
                            if (flags & libc::SOCK_NONBLOCK) != 0 {
                                c_sock.nonblocking = true;
                            }
                            let peer_idx = c_sock.peer;
                            drop(c_sock);
                            let client_addr = peer_idx.and_then(|p| inner.sockets[p].lock().unwrap().addr);
                            (Some((c_idx, client_addr)), sock.nonblocking)
                        } else {
                            (None, sock.nonblocking)
                        }
                    };

                    if let Some((client_idx, client_addr)) = res {
                        drop(inner);
                        let mut efd_flags = 0;
                        if (flags & libc::SOCK_CLOEXEC) != 0 {
                            efd_flags |= libc::EFD_CLOEXEC;
                        }
                        if (flags & libc::SOCK_NONBLOCK) != 0 {
                            efd_flags |= libc::EFD_NONBLOCK;
                        }
                        let raw_fd = proc.eventfd2(0, efd_flags)? as c_int;
                        if !addr.is_null() {
                            if let Some(c_addr) = client_addr {
                                unsafe { self.write_sockaddr(proc, addr, len, c_addr)?; }
                            }
                        }

                        if self.passthru.verbose {
                            println!("accept({}, ...) = {} (VIRTUAL)", idx, client_idx);
                        }
                        return Ok(DeterministicFd::Virtualized(raw_fd, client_idx));
                    }

                    if is_nonblocking {
                        drop(inner);
                        self.skip_syscall(proc);
                        return Err(nix::Error::EAGAIN);
                    }

                    if !proc.is_alive() {
                        return Err(nix::Error::ESRCH);
                    }

                    // Wait for data with timeout
                    self.time_manager.enter_blocking();
                    let (new_inner, timeout_res) = self.network.condvar.wait_timeout(inner, std::time::Duration::from_millis(100)).unwrap();
                    self.time_manager.exit_blocking();
                    inner = new_inner;
                    if timeout_res.timed_out() && !proc.is_alive() {
                        return Err(nix::Error::ESRCH);
                    }
                }
            }
        }
    }

    fn connect(&mut self, proc: &CapturedProcess, fd: &mut DeterministicFd, addr: *const libc::sockaddr, len: libc::socklen_t) -> nix::Result<c_int> {
        match fd {
            DeterministicFd::Passthru(f) | DeterministicFd::VirtualRandom(f) | DeterministicFd::VirtualUuid(f, _) => {
                self.passthru.connect(proc, f, addr, len)
            }
            DeterministicFd::Virtualized(_, idx) => {
                self.skip_syscall(proc);
                let dest_addr = unsafe { self.read_sockaddr(proc, addr, len)? };
                if self.passthru.verbose {
                    println!("connect({}, {:?}) (VIRTUAL)", idx, dest_addr);
                }
                
                let mut inner = self.network.inner.lock().unwrap();
                let server_idx = inner
                    .listeners
                    .get(&dest_addr)
                    .copied()
                    .or_else(|| {
                        if dest_addr.ip().is_loopback() {
                            let any_addr = SocketAddr::from(([0, 0, 0, 0], dest_addr.port()));
                            inner.listeners.get(&any_addr).copied()
                        } else {
                            None
                        }
                    })
                    .ok_or(nix::Error::ECONNREFUSED)?;
                
                // Assign an ephemeral client address if not already bound
                let client_addr = {
                    let sock = inner.sockets[*idx].lock().unwrap();
                    sock.addr
                }.unwrap_or_else(|| {
                    let port = inner.next_port;
                    inner.next_port += 1;
                    SocketAddr::from(([127, 0, 0, 1], port))
                });

                // Create the server-side accepted socket (local addr = dest_addr, peer = client *idx)
                let peer_sock = VirtualSocket {
                    addr: Some(dest_addr),
                    is_listener: false,
                    backlog: Vec::new(),
                    peer: Some(*idx),
                    read_buf: Vec::new(),
                    closed: false,
                    open_count: 1,
                    nonblocking: false,
                };
                let peer_idx = inner.sockets.len();
                inner.sockets.push(Arc::new(Mutex::new(peer_sock)));

                {
                    let mut client_sock = inner.sockets[*idx].lock().unwrap();
                    client_sock.addr = Some(client_addr);
                    client_sock.peer = Some(peer_idx);
                }

                {
                    let mut server_sock = inner.sockets[server_idx].lock().unwrap();
                    server_sock.backlog.push(peer_idx);
                }

                self.network.condvar.notify_all();
                Ok(0)
            }
        }
    }

    fn setsockopt(&mut self, proc: &CapturedProcess, fd: &mut DeterministicFd, level: c_int, optname: c_int, optval: *const c_void, optlen: libc::socklen_t) -> nix::Result<c_int> {
        match fd {
            DeterministicFd::Passthru(f) | DeterministicFd::VirtualRandom(f) | DeterministicFd::VirtualUuid(f, _) => {
                self.passthru.setsockopt(proc, f, level, optname, optval, optlen)
            }
            DeterministicFd::Virtualized(_, _) => {
                self.skip_syscall(proc);
                Ok(0)
            }
        }
    }

    fn getsockname(&mut self, proc: &CapturedProcess, fd: &mut DeterministicFd, addr: *mut libc::sockaddr, len: *mut libc::socklen_t) -> nix::Result<c_int> {
        match fd {
            DeterministicFd::Passthru(f) | DeterministicFd::VirtualRandom(f) | DeterministicFd::VirtualUuid(f, _) => {
                self.passthru.getsockname(proc, f, addr, len)
            }
            DeterministicFd::Virtualized(_, idx) => {
                self.skip_syscall(proc);
                let inner = self.network.inner.lock().unwrap();
                let sock = inner.sockets[*idx].lock().unwrap();
                let sock_addr = sock.addr.unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));
                unsafe { self.write_sockaddr(proc, addr, len, sock_addr)?; }
                Ok(0)
            }
        }
    }

    fn pread(&mut self, proc: &CapturedProcess, fd: &mut DeterministicFd, count: usize, offset: off_t) -> nix::Result<Vec<u8>> {
        match fd {
            DeterministicFd::Passthru(f) => self.passthru.pread(proc, f, count, offset),
            DeterministicFd::Virtualized(_, _) => {
                self.skip_syscall(proc);
                Err(nix::Error::ESPIPE)
            }
            DeterministicFd::VirtualRandom(_) => {
                self.skip_syscall(proc);
                let n = std::cmp::min(count, 65536);
                Ok(vec![0x42u8; n])
            }
            DeterministicFd::VirtualUuid(_, _) => {
                self.skip_syscall(proc);
                if offset < 0 || (offset as usize) >= DETERMINISTIC_UUID.len() {
                    return Ok(Vec::new());
                }
                let rem = &DETERMINISTIC_UUID[offset as usize..];
                let n = std::cmp::min(count, rem.len());
                Ok(rem[..n].to_vec())
            }
        }
    }

    fn poll(&mut self, proc: &CapturedProcess, fds: &mut [PollFd<DeterministicFd>], timeout: c_int) -> nix::Result<c_int> {
        let mut any_virtual = false;
        for f in fds.iter() {
            match f.fd {
                Some(DeterministicFd::Virtualized(_, _))
                | Some(DeterministicFd::VirtualRandom(_))
                | Some(DeterministicFd::VirtualUuid(_, _)) => {
                    any_virtual = true;
                    break;
                }
                None if f.raw_fd >= 0 => {
                    any_virtual = true;
                    break;
                }
                _ => {}
            }
        }

        if !any_virtual {
            let mut p_fds: Vec<PollFd<PassthruFd>> = fds.iter().map(|f| {
                let pf = match f.fd {
                    Some(DeterministicFd::Passthru(pf))
                    | Some(DeterministicFd::VirtualRandom(pf))
                    | Some(DeterministicFd::VirtualUuid(pf, _)) => Some(pf),
                    _ => None,
                };
                PollFd { fd: pf, raw_fd: f.raw_fd, events: f.events, revents: f.revents }
            }).collect();
            let res = self.passthru.poll(proc, &mut p_fds, timeout)?;
            for (i, p_f) in p_fds.iter().enumerate() {
                fds[i].revents = p_f.revents;
            }
            return Ok(res);
        }

        self.skip_syscall(proc);
        let mut waited_ms: i64 = 0;
        loop {
            let mut ready_count = 0;
            let inner = self.network.inner.lock().unwrap();
            for f in fds.iter_mut() {
                f.revents = 0;
                match f.fd {
                    None => {
                        if f.raw_fd >= 0 {
                            f.revents = libc::POLLNVAL;
                            ready_count += 1;
                        }
                    }
                    Some(DeterministicFd::Virtualized(_, idx)) => {
                        let sock = inner.sockets[idx].lock().unwrap();
                        if !sock.read_buf.is_empty() || (sock.is_listener && !sock.backlog.is_empty()) {
                            f.revents |= f.events & (libc::POLLIN | libc::POLLRDNORM);
                        }
                        if !sock.closed && !sock.is_listener {
                            f.revents |= f.events & (libc::POLLOUT | libc::POLLWRNORM);
                        }
                        if sock.closed {
                            f.revents |= libc::POLLHUP;
                            if (f.events & libc::POLLIN) != 0 {
                                f.revents |= libc::POLLIN;
                            }
                        }
                        if f.revents != 0 {
                            ready_count += 1;
                        }
                    }
                    Some(DeterministicFd::VirtualRandom(_))
                    | Some(DeterministicFd::VirtualUuid(_, _))
                    | Some(DeterministicFd::Passthru(_)) => {
                        f.revents = f.events & (libc::POLLIN | libc::POLLOUT | libc::POLLRDNORM | libc::POLLWRNORM);
                        if f.revents != 0 {
                            ready_count += 1;
                        }
                    }
                }
            }

            if ready_count > 0 || timeout == 0 {
                return Ok(ready_count);
            }

            if timeout > 0 && waited_ms >= timeout as i64 {
                let _ = self.time_manager.sleep(proc, Duration::from_millis(timeout as u64));
                return Ok(0);
            }

            if !proc.is_alive() {
                return Err(nix::Error::ESRCH);
            }

            let wait_slice = if timeout > 0 {
                std::cmp::min(20, (timeout as i64 - waited_ms) as u64)
            } else {
                100
            };
            self.time_manager.enter_blocking();
            let (_new_inner, timeout_res) = self.network.condvar.wait_timeout(inner, std::time::Duration::from_millis(wait_slice)).unwrap();
            self.time_manager.exit_blocking();
            if timeout_res.timed_out() {
                waited_ms += wait_slice as i64;
                if !proc.is_alive() {
                    return Err(nix::Error::ESRCH);
                }
            }
        }
    }

    fn sendto(&mut self, proc: &CapturedProcess, fd: &mut DeterministicFd, buf: &[u8], flags: c_int, addr: *const libc::sockaddr, len: libc::socklen_t) -> nix::Result<usize> {
        match fd {
            DeterministicFd::Passthru(f) | DeterministicFd::VirtualRandom(f) | DeterministicFd::VirtualUuid(f, _) => {
                self.passthru.sendto(proc, f, buf, flags, addr, len)
            }
            DeterministicFd::Virtualized(_, idx) => self.virtual_write(proc, *idx, buf),
        }
    }

    fn recvfrom(&mut self, proc: &CapturedProcess, fd: &mut DeterministicFd, count: usize, flags: c_int, addr: *mut libc::sockaddr, len: *mut libc::socklen_t) -> nix::Result<Vec<u8>> {
        match fd {
            DeterministicFd::Passthru(f) | DeterministicFd::VirtualRandom(f) | DeterministicFd::VirtualUuid(f, _) => {
                self.passthru.recvfrom(proc, f, count, flags, addr, len)
            }
            DeterministicFd::Virtualized(_, idx) => {
                let res = self.virtual_read(proc, *idx, count, flags)?;
                if !addr.is_null() {
                    let peer_addr = {
                        let inner = self.network.inner.lock().unwrap();
                        let sock = inner.sockets[*idx].lock().unwrap();
                        sock.peer.and_then(|p_idx| inner.sockets[p_idx].lock().unwrap().addr)
                    };
                    if let Some(p_addr) = peer_addr {
                        unsafe {
                            let _ = self.write_sockaddr(proc, addr, len, p_addr);
                        }
                    }
                }
                Ok(res)
            }
        }
    }

    fn fcntl(&mut self, proc: &CapturedProcess, fd: &mut DeterministicFd, cmd: c_int, arg: libc::c_ulong) -> nix::Result<c_int> {
        match fd {
            DeterministicFd::Passthru(f) | DeterministicFd::VirtualRandom(f) | DeterministicFd::VirtualUuid(f, _) => {
                self.passthru.fcntl(proc, f, cmd, arg)
            }
            DeterministicFd::Virtualized(raw_fd, idx) => {
                if cmd == libc::F_SETFL {
                    let inner = self.network.inner.lock().unwrap();
                    let mut sock = inner.sockets[*idx].lock().unwrap();
                    sock.nonblocking = (arg as c_int & libc::O_NONBLOCK) != 0;
                }
                let mut pf = PassthruFd(*raw_fd);
                self.passthru.fcntl(proc, &mut pf, cmd, arg)
            }
        }
    }

    fn lseek(&mut self, proc: &CapturedProcess, fd: &mut DeterministicFd, offset: off_t, whence: c_int) -> nix::Result<off_t> {
        match fd {
            DeterministicFd::Passthru(f) | DeterministicFd::VirtualRandom(f) => self.passthru.lseek(proc, f, offset, whence),
            DeterministicFd::VirtualUuid(_, off) => {
                self.skip_syscall(proc);
                let new_off = match whence {
                    libc::SEEK_SET => offset,
                    libc::SEEK_CUR => (*off as off_t) + offset,
                    libc::SEEK_END => (DETERMINISTIC_UUID.len() as off_t) + offset,
                    _ => return Err(nix::Error::EINVAL),
                };
                if new_off < 0 {
                    return Err(nix::Error::EINVAL);
                }
                *off = new_off as usize;
                Ok(new_off)
            }
            DeterministicFd::Virtualized(_, _) => {
                self.skip_syscall(proc);
                Err(nix::Error::ESPIPE)
            }
        }
    }

    fn unlink(&mut self, proc: &CapturedProcess, pathname: &str) -> nix::Result<c_int> {
        self.passthru.unlink(proc, pathname)
    }

    fn pwrite(&mut self, proc: &CapturedProcess, fd: &mut DeterministicFd, buf: &[u8], offset: off_t) -> nix::Result<usize> {
        match fd {
            DeterministicFd::Passthru(f) | DeterministicFd::VirtualRandom(f) | DeterministicFd::VirtualUuid(f, _) => {
                self.passthru.pwrite(proc, f, buf, offset)
            }
            DeterministicFd::Virtualized(_, _) => {
                self.skip_syscall(proc);
                Err(nix::Error::ESPIPE)
            }
        }
    }

    fn fsync(&mut self, proc: &CapturedProcess, fd: &mut DeterministicFd) -> nix::Result<c_int> {
        match fd {
            DeterministicFd::Passthru(f) | DeterministicFd::VirtualRandom(f) | DeterministicFd::VirtualUuid(f, _) => {
                self.passthru.fsync(proc, f)
            }
            DeterministicFd::Virtualized(_, _) => {
                self.skip_syscall(proc);
                Err(nix::Error::EINVAL)
            }
        }
    }

    fn fdatasync(&mut self, proc: &CapturedProcess, fd: &mut DeterministicFd) -> nix::Result<c_int> {
        match fd {
            DeterministicFd::Passthru(f) | DeterministicFd::VirtualRandom(f) | DeterministicFd::VirtualUuid(f, _) => {
                self.passthru.fdatasync(proc, f)
            }
            DeterministicFd::Virtualized(_, _) => {
                self.skip_syscall(proc);
                Err(nix::Error::EINVAL)
            }
        }
    }

    fn getcwd(&mut self, proc: &CapturedProcess, size: usize) -> nix::Result<Vec<u8>> {
        self.passthru.getcwd(proc, size)
    }

    fn getpid(&mut self, proc: &CapturedProcess) -> nix::Result<c_int> {
        if self.passthru.verbose {
            println!("getpid() = 1234 (DETERMINISTIC)");
        }
        self.skip_syscall(proc);
        Ok(1234)
    }

    fn gettid(&mut self, proc: &CapturedProcess) -> nix::Result<c_int> {
        let tid = self.time_manager.get_deterministic_tid(proc.pid.as_raw());
        if self.passthru.verbose {
            println!("gettid() = {} (DETERMINISTIC)", tid);
        }
        self.skip_syscall(proc);
        Ok(tid)
    }

    fn getuid(&mut self, proc: &CapturedProcess) -> nix::Result<c_int> {
        if self.passthru.verbose {
            println!("getuid() = 1000 (DETERMINISTIC)");
        }
        self.skip_syscall(proc);
        Ok(1000)
    }

    fn geteuid(&mut self, proc: &CapturedProcess) -> nix::Result<c_int> {
        if self.passthru.verbose {
            println!("geteuid() = 1000 (DETERMINISTIC)");
        }
        self.skip_syscall(proc);
        Ok(1000)
    }

    fn getrandom(&mut self, proc: &CapturedProcess, buf: &mut [u8], _flags: c_int) -> nix::Result<usize> {
        for i in 0..buf.len() {
            buf[i] = 0x42;
        }
        if self.passthru.verbose {
            println!("getrandom(..., {}, ...) = {} (DETERMINISTIC)", buf.len(), buf.len());
        }
        self.skip_syscall(proc);
        Ok(buf.len())
    }

    fn gettimeofday(&mut self, proc: &CapturedProcess) -> nix::Result<c_int> {
        let regs = proc.get_regs()?;
        let tv_addr = regs.rdi as usize;
        let tz_addr = regs.rsi as usize;
        self.skip_syscall(proc);
        
        if tv_addr != 0 {
            let current_time = self.time_manager.get_time();
            let tv_sec: i64 = current_time.as_secs() as i64;
            let tv_usec: i64 = current_time.subsec_micros() as i64;
            
            let mut bytes = Vec::with_capacity(16);
            bytes.extend_from_slice(&tv_sec.to_ne_bytes());
            bytes.extend_from_slice(&tv_usec.to_ne_bytes());
            
            proc.write_memory(tv_addr, &bytes);
        }
        if tz_addr != 0 {
            proc.write_memory(tz_addr, &[0u8; 8]);
        }
        
        if self.passthru.verbose {
            println!("gettimeofday(..., ...) = 0 (DETERMINISTIC)");
        }
        Ok(0)
    }

    fn time(&mut self, proc: &CapturedProcess, tloc: *mut libc::time_t) -> nix::Result<libc::time_t> {
        self.skip_syscall(proc);
        let secs = self.time_manager.get_time().as_secs() as libc::time_t;
        if !tloc.is_null() {
            proc.write_memory(tloc as usize, &secs.to_ne_bytes());
        }
        if self.passthru.verbose {
            println!("time({:?}) = {} (DETERMINISTIC)", tloc, secs);
        }
        Ok(secs)
    }

    fn getppid(&mut self, proc: &CapturedProcess) -> nix::Result<c_int> {
        if self.passthru.verbose {
            println!("getppid() = 1 (DETERMINISTIC)");
        }
        self.skip_syscall(proc);
        Ok(1)
    }

    fn getpgrp(&mut self, proc: &CapturedProcess) -> nix::Result<c_int> {
        if self.passthru.verbose {
            println!("getpgrp() = 1 (DETERMINISTIC)");
        }
        self.skip_syscall(proc);
        Ok(1)
    }

    fn uname(&mut self, proc: &CapturedProcess) -> nix::Result<c_int> {
        let regs = proc.get_regs()?;
        let addr = regs.rdi as usize;
        self.skip_syscall(proc);
        if addr == 0 {
            return Err(nix::Error::EFAULT);
        }
        let mut uts: libc::utsname = unsafe { std::mem::zeroed() };
        fn copy_cstr(dst: &mut [libc::c_char], src: &[u8]) {
            for (i, &b) in src.iter().enumerate() {
                if i + 1 < dst.len() {
                    dst[i] = b as libc::c_char;
                }
            }
        }
        copy_cstr(&mut uts.sysname, b"Linux");
        copy_cstr(&mut uts.nodename, b"sandbox");
        copy_cstr(&mut uts.release, b"6.0.0-deterministic");
        copy_cstr(&mut uts.version, b"#1 SMP DETERMINISTIC");
        copy_cstr(&mut uts.machine, b"x86_64");

        let bytes = unsafe {
            std::slice::from_raw_parts(
                &uts as *const libc::utsname as *const u8,
                std::mem::size_of::<libc::utsname>(),
            )
        };
        proc.write_memory(addr, bytes);
        if self.passthru.verbose {
            println!("uname(...) = 0 (DETERMINISTIC)");
        }
        Ok(0)
    }

    fn sysinfo(&mut self, proc: &CapturedProcess) -> nix::Result<c_int> {
        let regs = proc.get_regs()?;
        let addr = regs.rdi as usize;
        self.skip_syscall(proc);
        if addr == 0 {
            return Err(nix::Error::EFAULT);
        }
        let mut info: libc::sysinfo = unsafe { std::mem::zeroed() };
        let current_time = self.time_manager.get_time();
        info.uptime = current_time.as_secs().saturating_sub(946684800) as i64;
        info.totalram = 1024 * 1024 * 1024;
        info.freeram = 512 * 1024 * 1024;
        info.procs = 1;
        info.mem_unit = 1;

        let bytes = unsafe {
            std::slice::from_raw_parts(
                &info as *const libc::sysinfo as *const u8,
                std::mem::size_of::<libc::sysinfo>(),
            )
        };
        proc.write_memory(addr, bytes);
        if self.passthru.verbose {
            println!("sysinfo(...) = 0 (DETERMINISTIC)");
        }
        Ok(0)
    }

    fn getgid(&mut self, proc: &CapturedProcess) -> nix::Result<c_int> {
        if self.passthru.verbose {
            println!("getgid() = 1000 (DETERMINISTIC)");
        }
        self.skip_syscall(proc);
        Ok(1000)
    }

    fn getegid(&mut self, proc: &CapturedProcess) -> nix::Result<c_int> {
        if self.passthru.verbose {
            println!("getegid() = 1000 (DETERMINISTIC)");
        }
        self.skip_syscall(proc);
        Ok(1000)
    }

    fn times(&mut self, proc: &CapturedProcess) -> nix::Result<c_int> {
        let regs = proc.get_regs()?;
        let addr = regs.rdi as usize;
        if addr != 0 {
            // Zero out the tms struct (4 fields of 8 bytes)
            let buf = vec![0u8; 32];
            proc.write_memory(addr, &buf);
        }
        if self.passthru.verbose {
            println!("times(...) = 0 (DETERMINISTIC)");
        }
        self.skip_syscall(proc);
        Ok(0) // Return 0 ticks
    }

    fn writev(&mut self, proc: &CapturedProcess, fd: &mut DeterministicFd, iov: u64, iovcnt: i32) -> nix::Result<usize> {
        match fd {
            DeterministicFd::Passthru(f) | DeterministicFd::VirtualRandom(f) | DeterministicFd::VirtualUuid(f, _) => {
                self.passthru.writev(proc, f, iov, iovcnt)
            }
            DeterministicFd::Virtualized(_, idx) => {
                if iovcnt < 0 || iovcnt > 1024 {
                    self.skip_syscall(proc);
                    return Err(nix::Error::EINVAL);
                }
                let mut combined = Vec::new();
                for i in 0..iovcnt as usize {
                    let entry_addr = (iov as usize).saturating_add(i * 16);
                    let entry_bytes = proc.read_memory(entry_addr, 16);
                    if entry_bytes.len() < 16 {
                        self.skip_syscall(proc);
                        return Err(nix::Error::EFAULT);
                    }
                    let base = u64::from_ne_bytes(entry_bytes[0..8].try_into().unwrap()) as usize;
                    let len = u64::from_ne_bytes(entry_bytes[8..16].try_into().unwrap()) as usize;
                    if len > 0 {
                        let chunk = proc.read_memory(base, len);
                        if chunk.len() < len {
                            self.skip_syscall(proc);
                            return Err(nix::Error::EFAULT);
                        }
                        combined.extend_from_slice(&chunk);
                    }
                }
                self.virtual_write(proc, *idx, &combined)
            }
        }
    }

    fn readv(&mut self, proc: &CapturedProcess, fd: &mut DeterministicFd, iov: u64, iovcnt: i32) -> nix::Result<usize> {
        if let DeterministicFd::Passthru(f) = fd {
            return self.passthru.readv(proc, f, iov, iovcnt);
        }
        let (iovecs, total_len) = self.read_iovecs(proc, iov, iovcnt)?;
        let data = self.read(proc, fd, total_len)?;
        Ok(Self::scatter_iovecs(proc, &iovecs, &data))
    }

    fn preadv(&mut self, proc: &CapturedProcess, fd: &mut DeterministicFd, iov: u64, iovcnt: i32, file_offset: off_t) -> nix::Result<usize> {
        if let DeterministicFd::Passthru(f) = fd {
            return self.passthru.preadv(proc, f, iov, iovcnt, file_offset);
        }
        let (iovecs, total_len) = self.read_iovecs(proc, iov, iovcnt)?;
        let data = self.pread(proc, fd, total_len, file_offset)?;
        Ok(Self::scatter_iovecs(proc, &iovecs, &data))
    }

    fn futex(&mut self, proc: &CapturedProcess, uaddr: *mut u32, op: c_int, val: u32, timeout: *const libc::timespec, uaddr2: *mut u32, val3: u32) -> nix::Result<c_int> {
        let futex_op = op & !(libc::FUTEX_PRIVATE_FLAG | libc::FUTEX_CLOCK_REALTIME);
        let key_aspace = self.aspace_id;
        let key = (key_aspace, uaddr as u64);

        if futex_op == libc::FUTEX_WAIT || futex_op == libc::FUTEX_WAIT_BITSET {
            if self.passthru.verbose {
                println!("futex({:?}, {}, {}, ...) (VIRTUAL)", uaddr, if futex_op == libc::FUTEX_WAIT { "FUTEX_WAIT" } else { "FUTEX_WAIT_BITSET" }, val);
            }
            self.skip_syscall(proc);

            let bitset = if futex_op == libc::FUTEX_WAIT_BITSET {
                if val3 == 0 {
                    return Err(nix::Error::EINVAL);
                }
                val3
            } else {
                u32::MAX
            };

            let timeout_dur = if !timeout.is_null() {
                Some(Self::read_timespec(proc, timeout as usize)?)
            } else {
                None
            };

            let is_abstime = futex_op == libc::FUTEX_WAIT_BITSET;
            self.time_manager.futex_wait(proc, key, uaddr as u64, val, bitset, timeout_dur, is_abstime)
        } else if futex_op == libc::FUTEX_WAKE || futex_op == libc::FUTEX_WAKE_BITSET {
            if self.passthru.verbose {
                println!("futex({:?}, {}, {}, ...) (VIRTUAL)", uaddr, if futex_op == libc::FUTEX_WAKE { "FUTEX_WAKE" } else { "FUTEX_WAKE_BITSET" }, val);
            }
            self.skip_syscall(proc);
            let bitset = if futex_op == libc::FUTEX_WAKE_BITSET {
                if val3 == 0 {
                    return Err(nix::Error::EINVAL);
                }
                val3
            } else {
                u32::MAX
            };
            self.time_manager.futex_wake(key, val, bitset)
        } else if futex_op == libc::FUTEX_REQUEUE || futex_op == libc::FUTEX_CMP_REQUEUE {
            self.skip_syscall(proc);
            let max_requeue = (timeout as usize) as u32;
            let expected = if futex_op == libc::FUTEX_CMP_REQUEUE {
                Some(val3)
            } else {
                None
            };
            let key2 = (key_aspace, uaddr2 as u64);
            self.time_manager.futex_requeue(proc, key, key2, uaddr as u64, val, max_requeue, expected)
        } else if futex_op == libc::FUTEX_WAKE_OP {
            self.skip_syscall(proc);
            let key2 = (key_aspace, uaddr2 as u64);
            let val2 = (timeout as usize) as u32;
            // Decode FUTEX_WAKE_OP encoded in val3
            let op_type = (val3 >> 28) & 0xf;
            let cmp_type = (val3 >> 24) & 0xf;
            let oparg = ((val3 >> 12) & 0xfff) as i32;
            let cmparg = (val3 & 0xfff) as i32;
            let oparg = if (op_type & 8) != 0 {
                1i32.wrapping_shl((oparg & 31) as u32)
            } else {
                oparg
            };
            let raw_op = op_type & 7;
            let bytes = proc.read_memory(uaddr2 as usize, 4);
            if bytes.len() < 4 {
                return Err(nix::Error::EFAULT);
            }
            let oldval = i32::from_ne_bytes(bytes[0..4].try_into().unwrap());
            let newval = match raw_op {
                0 => oparg,                  // FUTEX_OP_SET
                1 => oldval.wrapping_add(oparg), // FUTEX_OP_ADD
                2 => oldval | oparg,         // FUTEX_OP_OR
                3 => oldval & !oparg,        // FUTEX_OP_ANDN
                4 => oldval ^ oparg,         // FUTEX_OP_XOR
                _ => return Err(nix::Error::ENOSYS),
            };
            proc.write_memory(uaddr2 as usize, &newval.to_ne_bytes());
            let mut woken = self.time_manager.futex_wake(key, val, u32::MAX)?;
            let cond = match cmp_type {
                0 => oldval == cmparg,
                1 => oldval != cmparg,
                2 => oldval < cmparg,
                3 => oldval <= cmparg,
                4 => oldval > cmparg,
                5 => oldval >= cmparg,
                _ => return Err(nix::Error::EINVAL),
            };
            if cond {
                woken += self.time_manager.futex_wake(key2, val2, u32::MAX)?;
            }
            Ok(woken)
        } else {
            self.passthru.futex(proc, uaddr, op, val, timeout, uaddr2, val3)
        }
    }

    fn set_tid_address(&mut self, proc: &CapturedProcess, tidptr: *mut c_int) -> nix::Result<c_int> {
        self.tid_address = Some(tidptr as u64);
        let _ = self.passthru.set_tid_address(proc, tidptr)?;
        let tid = self.time_manager.get_deterministic_tid(proc.pid.as_raw());
        Ok(tid)
    }

    fn on_start(&mut self, pid: nix::unistd::Pid) {
        self.time_manager.register_thread(pid.as_raw());
    }

    fn on_child_created(
        &mut self,
        parent_proc: &CapturedProcess,
        child_pid: nix::unistd::Pid,
        parent_tidptr: Option<u64>,
        child_tidptr: Option<u64>,
    ) -> Option<i64> {
        let det_tid = self.time_manager.get_deterministic_tid(child_pid.as_raw());
        if let Some(p_ptr) = parent_tidptr {
            if p_ptr != 0 {
                parent_proc.write_memory(p_ptr as usize, &det_tid.to_ne_bytes());
            }
        }
        if let Some(c_ptr) = child_tidptr {
            if c_ptr != 0 {
                let child_proc = CapturedProcess { pid: child_pid };
                child_proc.write_memory(c_ptr as usize, &det_tid.to_ne_bytes());
            }
        }
        Some(det_tid as i64)
    }

    fn on_exec(&mut self, proc: &CapturedProcess, sp: u64) {
        self.time_manager.register_exec_tid(proc.pid.as_raw());
        crate::vdso::scrub_auxv_random(proc, sp);
    }

    fn on_exit(&mut self, proc: &CapturedProcess) {
        if self.passthru.verbose {
            println!("on_exit: waking tid_address {:?} (VIRTUAL)", self.tid_address);
        }
        self.time_manager.on_exit(proc.pid.as_raw(), self.aspace_id, self.tid_address);
    }

    fn nanosleep(&mut self, proc: &CapturedProcess, req: *const libc::timespec, _rem: *mut libc::timespec) -> nix::Result<c_int> {
        if self.passthru.verbose {
            println!("nanosleep({:?}, ...) (DETERMINISTIC)", req);
        }
        self.skip_syscall(proc);
        let dur = Self::read_timespec(proc, req as usize)?;
        self.time_manager.sleep(proc, dur)?;
        Ok(0)
    }

    fn clock_nanosleep(&mut self, proc: &CapturedProcess, clk_id: libc::clockid_t, flags: c_int, req: *const libc::timespec, _rem: *mut libc::timespec) -> nix::Result<c_int> {
        if self.passthru.verbose {
            println!("clock_nanosleep({}, {}, {:?}, ...) (DETERMINISTIC)", clk_id, flags, req);
        }
        self.skip_syscall(proc);
        let dur = Self::read_timespec(proc, req as usize)?;
        if (flags & libc::TIMER_ABSTIME) != 0 {
            self.time_manager.sleep_until(proc, dur)?;
        } else {
            self.time_manager.sleep(proc, dur)?;
        }
        Ok(0)
    }

    fn wait4(&mut self, proc: &CapturedProcess, wpid: c_int, status_addr: u64, options: c_int, rusage_addr: u64) -> nix::Result<c_int> {
        let real_wpid = if wpid > 0 {
            self.time_manager.get_real_tid(wpid).unwrap_or(wpid)
        } else {
            wpid
        };
        let res = proc.syscall(libc::SYS_wait4 as u64, real_wpid as i64 as u64, status_addr, options as u64, rusage_addr, 0, 0)? as c_int;
        if res > 0 {
            if rusage_addr != 0 {
                let zero = vec![0u8; std::mem::size_of::<libc::rusage>()];
                proc.write_memory(rusage_addr as usize, &zero);
            }
            Ok(self.time_manager.get_deterministic_tid(res))
        } else {
            Ok(res)
        }
    }

    fn kill(&mut self, proc: &CapturedProcess, pid: c_int, sig: c_int) -> nix::Result<c_int> {
        let real_pid = self.resolve_signal_target(proc, pid);
        let res = proc.syscall(libc::SYS_kill as u64, real_pid as i64 as u64, sig as u64, 0, 0, 0, 0)?;
        Ok(res as c_int)
    }

    fn tkill(&mut self, proc: &CapturedProcess, tid: c_int, sig: c_int) -> nix::Result<c_int> {
        let real_tid = self.resolve_signal_target(proc, tid);
        let res = proc.syscall(libc::SYS_tkill as u64, real_tid as i64 as u64, sig as u64, 0, 0, 0, 0)?;
        Ok(res as c_int)
    }

    fn tgkill(&mut self, proc: &CapturedProcess, tgid: c_int, tid: c_int, sig: c_int) -> nix::Result<c_int> {
        let real_tid = self.resolve_signal_target(proc, tid);
        if tgid == 1234 {
            // In Linux, a forked process calling tgkill(getpid(), gettid(), sig) passes virtual getpid()=1234.
            // Use tkill semantics when tgid is virtualized to 1234 so forked children can signal themselves.
            let res = proc.syscall(libc::SYS_tkill as u64, real_tid as i64 as u64, sig as u64, 0, 0, 0, 0)?;
            return Ok(res as c_int);
        }
        let real_tgid = self.resolve_signal_target(proc, tgid);
        let res = proc.syscall(libc::SYS_tgkill as u64, real_tgid as i64 as u64, real_tid as i64 as u64, sig as u64, 0, 0, 0)?;
        Ok(res as c_int)
    }

    fn getpgid(&mut self, proc: &CapturedProcess, _pid: c_int) -> nix::Result<c_int> {
        self.skip_syscall(proc);
        Ok(1)
    }

    fn getsid(&mut self, proc: &CapturedProcess, _pid: c_int) -> nix::Result<c_int> {
        self.skip_syscall(proc);
        Ok(1)
    }

    fn adjtimex(&mut self, proc: &CapturedProcess, buf_addr: u64) -> nix::Result<c_int> {
        self.clock_adjtime(proc, libc::CLOCK_REALTIME, buf_addr)
    }

    fn clock_adjtime(&mut self, proc: &CapturedProcess, _clk_id: libc::clockid_t, buf_addr: u64) -> nix::Result<c_int> {
        self.skip_syscall(proc);
        if buf_addr == 0 {
            return Err(nix::Error::EFAULT);
        }
        let mut tx: libc::timex = unsafe { std::mem::zeroed() };
        let current_time = self.time_manager.get_time();
        tx.time.tv_sec = current_time.as_secs() as i64;
        tx.time.tv_usec = current_time.subsec_micros() as i64;
        let bytes = unsafe {
            std::slice::from_raw_parts(
                &tx as *const libc::timex as *const u8,
                std::mem::size_of::<libc::timex>(),
            )
        };
        proc.write_memory(buf_addr as usize, bytes);
        Ok(0)
    }

    fn getrusage(&mut self, proc: &CapturedProcess, _who: c_int, usage_addr: u64) -> nix::Result<c_int> {
        self.skip_syscall(proc);
        if usage_addr == 0 {
            return Err(nix::Error::EFAULT);
        }
        let zero = vec![0u8; std::mem::size_of::<libc::rusage>()];
        proc.write_memory(usage_addr as usize, &zero);
        Ok(0)
    }

    fn getcpu(&mut self, proc: &CapturedProcess, cpu_addr: u64, node_addr: u64, _tcache_addr: u64) -> nix::Result<c_int> {
        self.skip_syscall(proc);
        if cpu_addr != 0 {
            proc.write_memory(cpu_addr as usize, &0u32.to_ne_bytes());
        }
        if node_addr != 0 {
            proc.write_memory(node_addr as usize, &0u32.to_ne_bytes());
        }
        Ok(0)
    }

    fn clock_getres(&mut self, proc: &CapturedProcess, _clk_id: libc::clockid_t, res_addr: u64) -> nix::Result<c_int> {
        self.skip_syscall(proc);
        if res_addr != 0 {
            let mut bytes = [0u8; 16];
            bytes[8..16].copy_from_slice(&1i64.to_ne_bytes());
            proc.write_memory(res_addr as usize, &bytes);
        }
        Ok(0)
    }

    fn getresuid(&mut self, proc: &CapturedProcess, ruid_addr: u64, euid_addr: u64, suid_addr: u64) -> nix::Result<c_int> {
        self.skip_syscall(proc);
        let uid = 1000u32.to_ne_bytes();
        if ruid_addr != 0 {
            proc.write_memory(ruid_addr as usize, &uid);
        }
        if euid_addr != 0 {
            proc.write_memory(euid_addr as usize, &uid);
        }
        if suid_addr != 0 {
            proc.write_memory(suid_addr as usize, &uid);
        }
        Ok(0)
    }

    fn getresgid(&mut self, proc: &CapturedProcess, rgid_addr: u64, egid_addr: u64, sgid_addr: u64) -> nix::Result<c_int> {
        self.skip_syscall(proc);
        let gid = 1000u32.to_ne_bytes();
        if rgid_addr != 0 {
            proc.write_memory(rgid_addr as usize, &gid);
        }
        if egid_addr != 0 {
            proc.write_memory(egid_addr as usize, &gid);
        }
        if sgid_addr != 0 {
            proc.write_memory(sgid_addr as usize, &gid);
        }
        Ok(0)
    }

    fn getpeername(&mut self, proc: &CapturedProcess, fd: &mut DeterministicFd, addr: *mut libc::sockaddr, len: *mut libc::socklen_t) -> nix::Result<c_int> {
        use std::os::unix::io::AsRawFd;
        match fd {
            DeterministicFd::Passthru(_) | DeterministicFd::VirtualRandom(_) | DeterministicFd::VirtualUuid(_, _) => {
                let res = proc.syscall(libc::SYS_getpeername as u64, fd.as_raw_fd() as u64, addr as u64, len as u64, 0, 0, 0)?;
                Ok(res as c_int)
            }
            DeterministicFd::Virtualized(_, idx) => {
                self.skip_syscall(proc);
                let peer_addr = {
                    let inner = self.network.inner.lock().unwrap();
                    let sock = inner.sockets[*idx].lock().unwrap();
                    let peer_idx = sock.peer.ok_or(nix::Error::ENOTCONN)?;
                    drop(sock);
                    let peer_sock = inner.sockets[peer_idx].lock().unwrap();
                    peer_sock.addr.unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], 0)))
                };
                unsafe {
                    self.write_sockaddr(proc, addr, len, peer_addr)?;
                }
                Ok(0)
            }
        }
    }

    fn getsockopt(&mut self, proc: &CapturedProcess, fd: &mut DeterministicFd, level: c_int, optname: c_int, optval: u64, optlen: u64) -> nix::Result<c_int> {
        use std::os::unix::io::AsRawFd;
        match fd {
            DeterministicFd::Passthru(_) | DeterministicFd::VirtualRandom(_) | DeterministicFd::VirtualUuid(_, _) => {
                let res = proc.syscall(libc::SYS_getsockopt as u64, fd.as_raw_fd() as u64, level as u64, optname as u64, optval, optlen, 0)?;
                Ok(res as c_int)
            }
            DeterministicFd::Virtualized(_, _) => {
                self.skip_syscall(proc);
                if optval != 0 && optlen != 0 {
                    let len_bytes = proc.read_memory(optlen as usize, 4);
                    if len_bytes.len() < 4 {
                        return Err(nix::Error::EFAULT);
                    }
                    let max_len = u32::from_ne_bytes(len_bytes[0..4].try_into().unwrap()) as usize;
                    let write_len = std::cmp::min(max_len, 4);
                    if write_len > 0 {
                        proc.write_memory(optval as usize, &[0u8; 4][..write_len]);
                    }
                    proc.write_memory(optlen as usize, &(write_len as u32).to_ne_bytes());
                }
                Ok(0)
            }
        }
    }

    fn shutdown(&mut self, proc: &CapturedProcess, fd: &mut DeterministicFd, how: c_int) -> nix::Result<c_int> {
        use std::os::unix::io::AsRawFd;
        match fd {
            DeterministicFd::Passthru(_) | DeterministicFd::VirtualRandom(_) | DeterministicFd::VirtualUuid(_, _) => {
                let res = proc.syscall(libc::SYS_shutdown as u64, fd.as_raw_fd() as u64, how as u64, 0, 0, 0, 0)?;
                Ok(res as c_int)
            }
            DeterministicFd::Virtualized(_, idx) => {
                self.skip_syscall(proc);
                let inner = self.network.inner.lock().unwrap();
                let mut sock = inner.sockets[*idx].lock().unwrap();
                if how == libc::SHUT_RD || how == libc::SHUT_RDWR {
                    sock.closed = true;
                }
                if (how == libc::SHUT_WR || how == libc::SHUT_RDWR) && sock.peer.is_some() {
                    let peer_idx = sock.peer.unwrap();
                    drop(sock);
                    let mut peer = inner.sockets[peer_idx].lock().unwrap();
                    peer.closed = true;
                }
                self.network.condvar.notify_all();
                Ok(0)
            }
        }
    }

    fn sendmsg(&mut self, proc: &CapturedProcess, fd: &mut DeterministicFd, msg_addr: u64, flags: c_int) -> nix::Result<usize> {
        use std::os::unix::io::AsRawFd;
        match fd {
            DeterministicFd::Passthru(_) | DeterministicFd::VirtualRandom(_) | DeterministicFd::VirtualUuid(_, _) => {
                let res = proc.syscall(libc::SYS_sendmsg as u64, fd.as_raw_fd() as u64, msg_addr, flags as u64, 0, 0, 0)?;
                Ok(res as usize)
            }
            DeterministicFd::Virtualized(_, _) => {
                let hdr = proc.read_memory(msg_addr as usize, 32);
                if hdr.len() < 32 {
                    self.skip_syscall(proc);
                    return Err(nix::Error::EFAULT);
                }
                let iov = u64::from_ne_bytes(hdr[16..24].try_into().unwrap());
                let iovcnt = u64::from_ne_bytes(hdr[24..32].try_into().unwrap()) as i32;
                self.writev(proc, fd, iov, iovcnt)
            }
        }
    }

    fn recvmsg(&mut self, proc: &CapturedProcess, fd: &mut DeterministicFd, msg_addr: u64, flags: c_int) -> nix::Result<usize> {
        use std::os::unix::io::AsRawFd;
        match fd {
            DeterministicFd::Passthru(_) | DeterministicFd::VirtualRandom(_) | DeterministicFd::VirtualUuid(_, _) => {
                let res = proc.syscall(libc::SYS_recvmsg as u64, fd.as_raw_fd() as u64, msg_addr, flags as u64, 0, 0, 0)?;
                Ok(res as usize)
            }
            DeterministicFd::Virtualized(_, idx) => {
                let hdr = proc.read_memory(msg_addr as usize, 56);
                if hdr.len() < 32 {
                    self.skip_syscall(proc);
                    return Err(nix::Error::EFAULT);
                }
                let iov = u64::from_ne_bytes(hdr[16..24].try_into().unwrap());
                let iovcnt = u64::from_ne_bytes(hdr[24..32].try_into().unwrap()) as i32;
                let (iovecs, total_len) = self.read_iovecs(proc, iov, iovcnt)?;
                let data = self.virtual_read(proc, *idx, total_len, flags)?;
                if hdr.len() >= 52 {
                    proc.write_memory((msg_addr + 48) as usize, &0i32.to_ne_bytes());
                }
                Ok(Self::scatter_iovecs(proc, &iovecs, &data))
            }
        }
    }

    fn is_verbose(&self) -> bool {
        self.passthru.verbose
    }

    fn is_deterministic(&self) -> bool {
        true
    }

    fn emulate_rdtsc(&mut self, proc: &CapturedProcess) -> bool {
        let mut regs = match proc.get_regs() {
            Ok(r) => r,
            Err(_) => return false,
        };
        let bytes = proc.read_memory(regs.rip as usize, 15);
        if bytes.len() < 2 {
            return false;
        }
        let mut idx = 0;
        while idx < bytes.len() {
            let b = bytes[idx];
            if matches!(b, 0x26 | 0x2e | 0x36 | 0x3e | 0x64 | 0x65 | 0x66 | 0x67 | 0xf0 | 0xf2 | 0xf3)
                || (0x40..=0x4f).contains(&b)
            {
                idx += 1;
            } else {
                break;
            }
        }
        let rem = &bytes[idx..];
        let is_rdtsc = rem.len() >= 2 && rem[0] == 0x0f && rem[1] == 0x31;
        let is_rdtscp = rem.len() >= 3 && rem[0] == 0x0f && rem[1] == 0x01 && rem[2] == 0xf9;
        if is_rdtsc || is_rdtscp {
            let tsc = self.time_manager.next_tsc();
            regs.rax = tsc & 0xffff_ffff;
            regs.rdx = tsc >> 32;
            if is_rdtscp {
                regs.rcx = 0; // IA32_TSC_AUX
            }
            regs.rip += (idx + if is_rdtscp { 3 } else { 2 }) as u64;
            if proc.set_regs(regs).is_err() {
                return false;
            }
            if self.passthru.verbose {
                println!("{}() = {} (DETERMINISTIC)", if is_rdtscp { "rdtscp" } else { "rdtsc" }, tsc);
            }
            true
        } else if rem.len() >= 2 && rem[0] == 0x0f && rem[1] == 0xa2 {
            // cpuid
            let leaf = regs.rax as u32;
            let subleaf = regs.rcx as u32;
            let res = core::arch::x86_64::__cpuid_count(leaf, subleaf);
            let eax = res.eax;
            let mut ebx = res.ebx;
            let mut ecx = res.ecx;
            let mut edx = res.edx;
            if leaf == 1 {
                // Force initial APIC ID (bits 31..24 of EBX) to 0 and clear RDRAND (bit 30 of ECX)
                ebx &= 0x00ff_ffff;
                ecx &= !(1 << 30);
            } else if leaf == 7 && subleaf == 0 {
                // Clear RDSEED (bit 18 of EBX)
                ebx &= !(1 << 18);
            } else if leaf == 0x0b || leaf == 0x1f {
                // Extended Topology Enumeration: force x2APIC ID in EDX to 0
                edx = 0;
            }
            regs.rax = eax as u64;
            regs.rbx = ebx as u64;
            regs.rcx = ecx as u64;
            regs.rdx = edx as u64;
            regs.rip += (idx + 2) as u64;
            if proc.set_regs(regs).is_err() {
                return false;
            }
            if self.passthru.verbose {
                println!("cpuid(leaf={:#x}, subleaf={:#x}) (DETERMINISTIC)", leaf, subleaf);
            }
            true
        } else {
            false
        }
    }
}

impl Deterministic {
    fn read_timespec(proc: &CapturedProcess, addr: usize) -> nix::Result<Duration> {
        let bytes = proc.read_memory(addr, 16);
        if bytes.len() < 16 {
            return Err(nix::Error::EFAULT);
        }
        let tv_sec = i64::from_ne_bytes(bytes[0..8].try_into().unwrap());
        let tv_nsec = i64::from_ne_bytes(bytes[8..16].try_into().unwrap());
        if tv_sec < 0 || tv_nsec < 0 || tv_nsec >= 1_000_000_000 {
            return Err(nix::Error::EINVAL);
        }
        Ok(Duration::new(tv_sec as u64, tv_nsec as u32))
    }

    fn read_iovecs(&self, proc: &CapturedProcess, iov: u64, iovcnt: i32) -> nix::Result<(Vec<(usize, usize)>, usize)> {
        if iovcnt < 0 || iovcnt > 1024 {
            self.skip_syscall(proc);
            return Err(nix::Error::EINVAL);
        }
        let mut iovecs = Vec::with_capacity(iovcnt as usize);
        let mut total_len: usize = 0;
        for i in 0..iovcnt as usize {
            let entry_addr = (iov as usize).saturating_add(i * 16);
            let entry_bytes = proc.read_memory(entry_addr, 16);
            if entry_bytes.len() < 16 {
                self.skip_syscall(proc);
                return Err(nix::Error::EFAULT);
            }
            let base = u64::from_ne_bytes(entry_bytes[0..8].try_into().unwrap()) as usize;
            let len = u64::from_ne_bytes(entry_bytes[8..16].try_into().unwrap()) as usize;
            total_len = total_len.saturating_add(len);
            iovecs.push((base, len));
        }
        Ok((iovecs, total_len))
    }

    fn scatter_iovecs(proc: &CapturedProcess, iovecs: &[(usize, usize)], data: &[u8]) -> usize {
        let mut offset = 0;
        for &(base, len) in iovecs {
            if offset >= data.len() {
                break;
            }
            let take = std::cmp::min(len, data.len() - offset);
            if take > 0 {
                proc.write_memory(base, &data[offset..offset + take]);
                offset += take;
            }
        }
        data.len()
    }

    fn resolve_signal_target(&self, proc: &CapturedProcess, id: c_int) -> c_int {
        if id > 0 {
            self.time_manager.get_real_tid(id).unwrap_or_else(|| {
                if id == 1234 { proc.pid.as_raw() } else { id }
            })
        } else {
            id
        }
    }

    fn release_virtual_socket(&self, idx: usize) {
        let inner = self.network.inner.lock().unwrap();
        let mut sock = inner.sockets[idx].lock().unwrap();
        if sock.open_count > 0 {
            sock.open_count -= 1;
        }
        if sock.open_count == 0 {
            sock.closed = true;
            if let Some(peer_idx) = sock.peer {
                drop(sock);
                let mut peer_sock = inner.sockets[peer_idx].lock().unwrap();
                peer_sock.closed = true;
            }
            self.network.condvar.notify_all();
        }
    }

    fn virtual_write(&mut self, proc: &CapturedProcess, idx: usize, buf: &[u8]) -> nix::Result<usize> {
        self.skip_syscall(proc);
        let inner = self.network.inner.lock().unwrap();
        let sock = inner.sockets[idx].lock().unwrap();
        let peer_idx = sock.peer.ok_or(nix::Error::ENOTCONN)?;
        drop(sock);
        let mut peer_sock = inner.sockets[peer_idx].lock().unwrap();
        if peer_sock.closed {
            return Err(nix::Error::EPIPE);
        }
        peer_sock.read_buf.extend_from_slice(buf);
        self.network.condvar.notify_all();
        Ok(buf.len())
    }

    fn virtual_read(&mut self, proc: &CapturedProcess, idx: usize, count: usize, flags: c_int) -> nix::Result<Vec<u8>> {
        if count == 0 {
            self.skip_syscall(proc);
            return Ok(Vec::new());
        }
        let peek = (flags & libc::MSG_PEEK) != 0;
        let dontwait = (flags & libc::MSG_DONTWAIT) != 0;
        loop {
            let mut inner = self.network.inner.lock().unwrap();
            let (res, is_nonblocking) = {
                let mut sock = inner.sockets[idx].lock().unwrap();
                if !sock.read_buf.is_empty() {
                    let n = std::cmp::min(count, sock.read_buf.len());
                    let buf = if peek {
                        sock.read_buf[0..n].to_vec()
                    } else {
                        sock.read_buf.drain(0..n).collect()
                    };
                    (Some(Ok(buf)), sock.nonblocking)
                } else if sock.closed {
                    (Some(Ok(Vec::new())), sock.nonblocking)
                } else {
                    (None, sock.nonblocking)
                }
            };
            
            if let Some(r) = res {
                self.skip_syscall(proc);
                return r;
            }

            if is_nonblocking || dontwait {
                drop(inner);
                self.skip_syscall(proc);
                return Err(nix::Error::EAGAIN);
            }

            if !proc.is_alive() {
                return Err(nix::Error::ESRCH);
            }

            // Wait for data with timeout
            self.time_manager.enter_blocking();
            let (new_inner, timeout_res) = self.network.condvar.wait_timeout(inner, std::time::Duration::from_millis(100)).unwrap();
            self.time_manager.exit_blocking();
            inner = new_inner;
            if timeout_res.timed_out() && !proc.is_alive() {
                return Err(nix::Error::ESRCH);
            }
        }
    }

    fn virtual_close(&mut self, proc: &CapturedProcess, raw_fd: c_int, idx: usize) -> nix::Result<c_int> {
        self.release_virtual_socket(idx);
        let res = proc.close(raw_fd)?;
        Ok(res as c_int)
    }

    unsafe fn read_sockaddr(&self, proc: &CapturedProcess, addr: *const libc::sockaddr, len: libc::socklen_t) -> nix::Result<SocketAddr> {
        if addr.is_null() {
            return Err(nix::Error::EFAULT);
        }
        let bytes = proc.read_memory(addr as usize, len as usize);
        if bytes.len() < 2 { return Err(nix::Error::EINVAL); }
        let family = u16::from_ne_bytes([bytes[0], bytes[1]]);
        if family == libc::AF_INET as u16 {
            if bytes.len() < 16 { return Err(nix::Error::EINVAL); }
            let port = u16::from_be_bytes([bytes[2], bytes[3]]);
            let ip = [bytes[4], bytes[5], bytes[6], bytes[7]];
            Ok(SocketAddr::from((ip, port)))
        } else {
            // For now only AF_INET
            Err(nix::Error::EAFNOSUPPORT)
        }
    }

    unsafe fn write_sockaddr(&self, proc: &CapturedProcess, addr: *mut libc::sockaddr, len_ptr: *mut libc::socklen_t, sa: SocketAddr) -> nix::Result<()> {
        if addr.is_null() || len_ptr.is_null() {
            return Ok(());
        }
        let len_bytes = proc.read_memory(len_ptr as usize, 4);
        if len_bytes.len() < 4 {
            return Err(nix::Error::EFAULT);
        }
        let max_len = u32::from_ne_bytes(len_bytes[0..4].try_into().unwrap()) as usize;

        let mut bytes = [0u8; 16];
        let family = libc::AF_INET as u16;
        bytes[0..2].copy_from_slice(&family.to_ne_bytes());
        match sa {
            SocketAddr::V4(addr4) => {
                bytes[2..4].copy_from_slice(&addr4.port().to_be_bytes());
                bytes[4..8].copy_from_slice(&addr4.ip().octets());
            }
            _ => return Err(nix::Error::EAFNOSUPPORT),
        }
        
        let copy_len = std::cmp::min(bytes.len(), max_len);
        if copy_len > 0 {
            proc.write_memory(addr as usize, &bytes[..copy_len]);
        }
        let actual_len = bytes.len() as u32;
        proc.write_memory(len_ptr as usize, &actual_len.to_ne_bytes());
        Ok(())
    }
}
