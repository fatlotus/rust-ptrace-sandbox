use crate::linux::{Linux, PollFd};
use crate::captured::CapturedProcess;
use crate::passthru::{Passthru, PassthruFd};
use libc::{c_int, c_void, mode_t, off_t};
use std::sync::{Arc, Mutex, Condvar};
use std::collections::{BinaryHeap, HashMap};
use std::net::SocketAddr;
use std::time::Duration;
use std::cmp::Ordering;

pub enum DeterministicFd {
    Passthru(PassthruFd),
    Virtualized(usize),
}

impl std::os::unix::io::AsRawFd for DeterministicFd {
    fn as_raw_fd(&self) -> c_int {
        match self {
            DeterministicFd::Passthru(f) => f.0,
            DeterministicFd::Virtualized(_) => -1,
        }
    }
}

struct VirtualSocket {
    addr: Option<SocketAddr>,
    is_listener: bool,
    backlog: Vec<usize>, // Indicies of pending client sockets
    peer: Option<usize>, // Index of peer socket if connected
    read_buf: Vec<u8>,
    closed: bool,
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

struct TimeInner {
    current_time: Duration,
    active_threads: usize,
    blocked_threads: usize,
    next_waiter_id: usize,
    timers: BinaryHeap<TimerEvent>,
    waiters: HashMap<usize, WaiterStatus>,
    futex_waiters: HashMap<u64, Vec<usize>>,
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
                active_threads: 1,
                blocked_threads: 0,
                next_waiter_id: 0,
                timers: BinaryHeap::new(),
                waiters: HashMap::new(),
                futex_waiters: HashMap::new(),
            }),
            condvar: Condvar::new(),
        }
    }

    fn maybe_advance_clock_locked(inner: &mut TimeInner, condvar: &Condvar) {
        if inner.blocked_threads >= inner.active_threads && !inner.timers.is_empty() {
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

    pub fn register_thread(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.active_threads += 1;
    }

    pub fn sleep(&self, proc: &CapturedProcess, dur: Duration) -> nix::Result<()> {
        let mut inner = self.inner.lock().unwrap();
        let waiter_id = inner.next_waiter_id;
        inner.next_waiter_id += 1;

        let target_time = inner.current_time + dur;
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

            let (new_inner, timeout_res) = self.condvar.wait_timeout(inner, Duration::from_millis(50)).unwrap();
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

    pub fn sleep_until(&self, proc: &CapturedProcess, target_time: Duration) -> nix::Result<()> {
        let mut inner = self.inner.lock().unwrap();
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

            let (new_inner, timeout_res) = self.condvar.wait_timeout(inner, Duration::from_millis(50)).unwrap();
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

    fn cleanup_waiter(&self, inner: &mut TimeInner, uaddr: u64, waiter_id: usize) {
        if let Some(list) = inner.futex_waiters.get_mut(&uaddr) {
            list.retain(|&id| id != waiter_id);
            if list.is_empty() {
                inner.futex_waiters.remove(&uaddr);
            }
        }
        if let Some(status) = inner.waiters.remove(&waiter_id) {
            if status == WaiterStatus::Waiting && inner.blocked_threads > 0 {
                inner.blocked_threads -= 1;
            }
        }
    }

    pub fn futex_wait(
        &self,
        proc: &CapturedProcess,
        uaddr: u64,
        val: u32,
        timeout: Option<Duration>,
    ) -> nix::Result<c_int> {
        let waiter_id;
        {
            let mut inner = self.inner.lock().unwrap();
            waiter_id = inner.next_waiter_id;
            inner.next_waiter_id += 1;
            inner.futex_waiters.entry(uaddr).or_default().push(waiter_id);
            inner.waiters.insert(waiter_id, WaiterStatus::Waiting);
            inner.blocked_threads += 1;

            if let Some(dur) = timeout {
                let target_time = inner.current_time + dur;
                inner.timers.push(TimerEvent {
                    target_time,
                    waiter_id,
                });
            }

            Self::maybe_advance_clock_locked(&mut inner, &self.condvar);
        }

        // Read current value from guest memory to check if value matches
        let bytes = proc.read_memory(uaddr as usize, 4);
        if bytes.len() < 4 {
            let mut inner = self.inner.lock().unwrap();
            self.cleanup_waiter(&mut inner, uaddr, waiter_id);
            return Err(nix::Error::EFAULT);
        }
        let current_val = u32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if current_val != val {
            let mut inner = self.inner.lock().unwrap();
            self.cleanup_waiter(&mut inner, uaddr, waiter_id);
            return Err(nix::Error::EAGAIN);
        }

        let mut inner = self.inner.lock().unwrap();
        while inner.waiters.get(&waiter_id) == Some(&WaiterStatus::Waiting) {
            if !proc.is_alive() {
                self.cleanup_waiter(&mut inner, uaddr, waiter_id);
                return Err(nix::Error::ESRCH);
            }

            let (new_inner, timeout_res) = self.condvar.wait_timeout(inner, Duration::from_millis(50)).unwrap();
            inner = new_inner;

            if timeout_res.timed_out() {
                if !proc.is_alive() {
                    self.cleanup_waiter(&mut inner, uaddr, waiter_id);
                    return Err(nix::Error::ESRCH);
                }
                Self::maybe_advance_clock_locked(&mut inner, &self.condvar);
            }
        }

        let final_status = inner.waiters.remove(&waiter_id);
        if let Some(list) = inner.futex_waiters.get_mut(&uaddr) {
            list.retain(|&id| id != waiter_id);
            if list.is_empty() {
                inner.futex_waiters.remove(&uaddr);
            }
        }

        match final_status {
            Some(WaiterStatus::Woken) => Ok(0),
            Some(WaiterStatus::TimerExpired) => Err(nix::Error::ETIMEDOUT),
            _ => Ok(0),
        }
    }

    pub fn futex_wake(&self, uaddr: u64, val: u32) -> nix::Result<c_int> {
        let mut inner = self.inner.lock().unwrap();
        if let Some(list) = inner.futex_waiters.get_mut(&uaddr) {
            let to_wake = std::cmp::min(val as usize, list.len());
            let woken_ids: Vec<usize> = list.drain(0..to_wake).collect();
            if list.is_empty() {
                inner.futex_waiters.remove(&uaddr);
            }
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
            self.condvar.notify_all();
            Ok(to_wake as i32)
        } else {
            Ok(0)
        }
    }

    pub fn on_exit(&self, tid_address: Option<u64>) {
        let mut inner = self.inner.lock().unwrap();
        if let Some(addr) = tid_address {
            if let Some(list) = inner.futex_waiters.remove(&addr) {
                for id in list {
                    if let Some(status) = inner.waiters.get_mut(&id) {
                        if *status == WaiterStatus::Waiting {
                            *status = WaiterStatus::Woken;
                            if inner.blocked_threads > 0 {
                                inner.blocked_threads -= 1;
                            }
                        }
                    }
                }
            }
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
}

impl Deterministic {
    pub fn new(verbose: bool) -> Self {
        Self {
            passthru: Passthru::new(verbose),
            network: Arc::new(Network::new()),
            time_manager: Arc::new(TimeManager::new()),
            tid_address: None,
        }
    }

    pub fn with_tid(verbose: bool, network: Arc<Network>, time_manager: Arc<TimeManager>, tid_address: Option<u64>) -> Self {
        Self {
            passthru: Passthru::new(verbose),
            network,
            time_manager,
            tid_address,
        }
    }

    fn patch_stat(&self, proc: &CapturedProcess, addr: usize) {
        // struct stat on x86_64:
        // atime (72..88), mtime (88..104), ctime (104..120)
        
        let mut bytes = proc.read_memory(addr, 120); // Only need up to ctime
        if bytes.len() < 120 { return; }
        
        // Zero out timestamps (atim 72..88, mtim 88..104, ctim 104..120)
        for i in 72..120 { bytes[i] = 0; }
        
        proc.write_memory(addr, &bytes);
        if self.passthru.verbose {
            println!("path_stat({:#x}) (DETERMINISTIC)", addr);
        }
    }

    fn skip_syscall(&self, proc: &CapturedProcess) -> i64 {
        proc.skip_syscall().unwrap_or(0)
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
            DeterministicFd::Virtualized(idx) => DeterministicFd::Virtualized(*idx),
        }
    }

    fn write(&mut self, proc: &CapturedProcess, fd: &mut DeterministicFd, buf: &[u8]) -> nix::Result<usize> {
        match fd {
            DeterministicFd::Passthru(f) => self.passthru.write(proc, f, buf),
            DeterministicFd::Virtualized(idx) => self.virtual_write(proc, *idx, buf),
        }
    }

    fn read(&mut self, proc: &CapturedProcess, fd: &mut DeterministicFd, count: usize) -> nix::Result<Vec<u8>> {
        match fd {
            DeterministicFd::Passthru(f) => self.passthru.read(proc, f, count),
            DeterministicFd::Virtualized(idx) => self.virtual_read(proc, *idx, count),
        }
    }

    fn open(&mut self, proc: &CapturedProcess, pathname: &str, flags: c_int, mode: mode_t) -> nix::Result<DeterministicFd> {
        self.passthru.open(proc, pathname, flags, mode).map(DeterministicFd::Passthru)
    }

    fn openat(&mut self, proc: &CapturedProcess, dirfd: Option<&mut DeterministicFd>, pathname: &str, flags: c_int, mode: mode_t) -> nix::Result<DeterministicFd> {
        let p_dirfd = match dirfd {
            Some(DeterministicFd::Passthru(f)) => Some(f),
            _ => None, // Virtualized FDs shouldn't be dirfds for now
        };
        self.passthru.openat(proc, p_dirfd, pathname, flags, mode).map(DeterministicFd::Passthru)
    }

    fn close(&mut self, proc: &CapturedProcess, fd: DeterministicFd) -> nix::Result<c_int> {
        match fd {
            DeterministicFd::Passthru(f) => self.passthru.close(proc, f),
            DeterministicFd::Virtualized(idx) => self.virtual_close(proc, idx),
        }
    }

    fn fstat(&mut self, proc: &CapturedProcess, fd: &mut DeterministicFd) -> nix::Result<c_int> {
        match fd {
            DeterministicFd::Passthru(f) => {
                let regs = proc.get_regs()?;
                let res = self.passthru.fstat(proc, f)?;
                if res == 0 {
                    self.patch_stat(proc, regs.rsi as usize);
                }
                Ok(res)
            }
            DeterministicFd::Virtualized(_) => {
                // TODO: Implement fstat for virtualized sockets
                Ok(0)
            }
        }
    }

    fn newfstatat(&mut self, proc: &CapturedProcess, dirfd: Option<&mut DeterministicFd>, pathname: &str, flags: c_int) -> nix::Result<c_int> {
        let p_dirfd = match dirfd {
            Some(DeterministicFd::Passthru(f)) => Some(f),
            _ => None,
        };
        let regs = proc.get_regs()?;
        let res = self.passthru.newfstatat(proc, p_dirfd, pathname, flags)?;
        if res == 0 {
            self.patch_stat(proc, regs.rdx as usize);
        }
        Ok(res)
    }

    fn mmap(&mut self, proc: &CapturedProcess, addr: *mut c_void, length: usize, prot: c_int, flags: c_int, fd: Option<&mut DeterministicFd>, offset: off_t) -> nix::Result<*mut c_void> {
        let p_fd = match fd {
            Some(DeterministicFd::Passthru(f)) => Some(f),
            _ => None,
        };
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
        self.time_manager.register_thread();
        Ok((pid, Box::new(Deterministic::with_tid(self.passthru.verbose, self.network.clone(), self.time_manager.clone(), None))))
    }

    fn vfork(&mut self, proc: &CapturedProcess) -> nix::Result<(nix::unistd::Pid, Box<dyn Linux<DeterministicFd> + Send>)> {
        let (pid, _) = self.passthru.vfork(proc)?;
        self.time_manager.register_thread();
        Ok((pid, Box::new(Deterministic::with_tid(self.passthru.verbose, self.network.clone(), self.time_manager.clone(), None))))
    }

    fn clone(&mut self, proc: &CapturedProcess, flags: c_int, tid_address: Option<*mut c_int>) -> nix::Result<(nix::unistd::Pid, Box<dyn Linux<DeterministicFd> + Send>)> {
        let (pid, _) = self.passthru.clone(proc, flags, tid_address)?;
        self.time_manager.register_thread();
        Ok((pid, Box::new(Deterministic::with_tid(self.passthru.verbose, self.network.clone(), self.time_manager.clone(), tid_address.map(|a| a as u64)))))
    }

    fn socket(&mut self, _proc: &CapturedProcess, domain: c_int, ty: c_int, protocol: c_int) -> nix::Result<DeterministicFd> {
        if self.passthru.verbose {
            println!("socket({}, {}, {}) (VIRTUAL)", domain, ty, protocol);
        }
        self.skip_syscall(_proc);
        let sock = VirtualSocket {
            addr: None,
            is_listener: false,
            backlog: Vec::new(),
            peer: None,
            read_buf: Vec::new(),
            closed: false,
        };
        let mut inner = self.network.inner.lock().unwrap();
        let idx = inner.sockets.len();
        inner.sockets.push(Arc::new(Mutex::new(sock)));
        Ok(DeterministicFd::Virtualized(idx))
    }

    fn bind(&mut self, proc: &CapturedProcess, fd: &mut DeterministicFd, addr: *const libc::sockaddr, len: libc::socklen_t) -> nix::Result<c_int> {
        match fd {
            DeterministicFd::Passthru(f) => self.passthru.bind(proc, f, addr, len),
            DeterministicFd::Virtualized(idx) => {
                let mut sock_addr = unsafe { self.read_sockaddr(proc, addr, len)? };
                if self.passthru.verbose {
                    println!("bind({}, {:?}) (VIRTUAL)", idx, sock_addr);
                }
                self.skip_syscall(proc);
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
            DeterministicFd::Passthru(f) => self.passthru.listen(proc, f, backlog),
            DeterministicFd::Virtualized(idx) => {
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

    fn accept4(&mut self, proc: &CapturedProcess, fd: &mut DeterministicFd, addr: *mut libc::sockaddr, len: *mut libc::socklen_t, _flags: c_int) -> nix::Result<DeterministicFd> {
        match fd {
            DeterministicFd::Passthru(f) => self.passthru.accept4(proc, f, addr, len, _flags).map(DeterministicFd::Passthru),
            DeterministicFd::Virtualized(idx) => {
                loop {
                    let mut inner = self.network.inner.lock().unwrap();
                    let res = {
                        let mut sock = inner.sockets[*idx].lock().unwrap();
                        if !sock.backlog.is_empty() {
                            let c_idx = sock.backlog.remove(0);
                            let c_sock = inner.sockets[c_idx].lock().unwrap();
                            Some((c_idx, c_sock.addr))
                        } else {
                            None
                        }
                    };

                    if let Some((client_idx, client_addr)) = res {
                        self.skip_syscall(proc);
                        if !addr.is_null() {
                            if let Some(c_addr) = client_addr {
                                unsafe { self.write_sockaddr(proc, addr, len, c_addr)?; }
                            }
                        }

                        if self.passthru.verbose {
                            println!("accept({}, ...) = {} (VIRTUAL)", idx, client_idx);
                        }
                        return Ok(DeterministicFd::Virtualized(client_idx));
                    }

                    if !proc.is_alive() {
                        return Err(nix::Error::ESRCH);
                    }

                    // Wait for data with timeout
                    let (new_inner, timeout_res) = self.network.condvar.wait_timeout(inner, std::time::Duration::from_millis(100)).unwrap();
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
            DeterministicFd::Passthru(f) => self.passthru.connect(proc, f, addr, len),
            DeterministicFd::Virtualized(idx) => {
                let dest_addr = unsafe { self.read_sockaddr(proc, addr, len)? };
                if self.passthru.verbose {
                    println!("connect({}, {:?}) (VIRTUAL)", idx, dest_addr);
                }
                self.skip_syscall(proc);
                
                let mut inner = self.network.inner.lock().unwrap();
                let server_idx = *inner.listeners.get(&dest_addr).ok_or(nix::Error::ECONNREFUSED)?;
                
                {
                    let mut server_sock = inner.sockets[server_idx].lock().unwrap();
                    server_sock.backlog.push(*idx);
                }

                // Create a peer socket for the server to use
                let peer_sock = VirtualSocket {
                    addr: Some(dest_addr), // The peer of the client is the server
                    is_listener: false,
                    backlog: Vec::new(),
                    peer: Some(*idx),
                    read_buf: Vec::new(),
                    closed: false,
                };
                let peer_idx = inner.sockets.len();
                inner.sockets.push(Arc::new(Mutex::new(peer_sock)));

                {
                    let mut client_sock = inner.sockets[*idx].lock().unwrap();
                    client_sock.peer = Some(peer_idx);
                }

                // Swap the server's backlog entry to use the peer socket instead of the client socket?
                // Actually, accept should return a *new* socket.
                // Re-doing logic: accept returns a new socket that is connected to the client.
                {
                    let mut server_sock = inner.sockets[server_idx].lock().unwrap();
                    // Replace the client idx with the peer idx in the backlog
                    let last_idx = server_sock.backlog.len() - 1;
                    server_sock.backlog[last_idx] = peer_idx;
                }

                self.network.condvar.notify_all();
                Ok(0)
            }
        }
    }

    fn setsockopt(&mut self, proc: &CapturedProcess, fd: &mut DeterministicFd, level: c_int, optname: c_int, optval: *const c_void, optlen: libc::socklen_t) -> nix::Result<c_int> {
        match fd {
            DeterministicFd::Passthru(f) => self.passthru.setsockopt(proc, f, level, optname, optval, optlen),
            DeterministicFd::Virtualized(_) => {
                // TODO: Implement setsockopt for virtualized sockets
                Ok(0)
            }
        }
    }

    fn getsockname(&mut self, proc: &CapturedProcess, fd: &mut DeterministicFd, addr: *mut libc::sockaddr, len: *mut libc::socklen_t) -> nix::Result<c_int> {
        match fd {
            DeterministicFd::Passthru(f) => self.passthru.getsockname(proc, f, addr, len),
            DeterministicFd::Virtualized(idx) => {
                self.skip_syscall(proc);
                let inner = self.network.inner.lock().unwrap();
                let sock = inner.sockets[*idx].lock().unwrap();
                if let Some(sock_addr) = sock.addr {
                    unsafe { self.write_sockaddr(proc, addr, len, sock_addr)?; }
                    Ok(0)
                } else {
                    Err(nix::Error::EBADF)
                }
            }
        }
    }

    fn pread(&mut self, proc: &CapturedProcess, fd: &mut DeterministicFd, count: usize, offset: off_t) -> nix::Result<Vec<u8>> {
        match fd {
            DeterministicFd::Passthru(f) => self.passthru.pread(proc, f, count, offset),
            DeterministicFd::Virtualized(_) => Err(nix::Error::ESPIPE),
        }
    }

    fn poll(&mut self, proc: &CapturedProcess, fds: &mut [PollFd<DeterministicFd>], _timeout: c_int) -> nix::Result<c_int> {
        // Check if any virtualized FDs are ready, or if all are passthru
        let mut any_virtual = false;
        for f in fds.iter() {
            if let DeterministicFd::Virtualized(_) = f.fd {
                any_virtual = true;
                break;
            }
        }

        if !any_virtual {
            // All passthru, we can delegate but we need to convert PollFd<DeterministicFd> to PollFd<PassthruFd>
            let mut p_fds: Vec<PollFd<PassthruFd>> = fds.iter().map(|f| {
                match f.fd {
                    DeterministicFd::Passthru(ref pf) => PollFd { fd: PassthruFd(pf.0), events: f.events, revents: f.revents },
                    _ => unreachable!(),
                }
            }).collect();
            let res = self.passthru.poll(proc, &mut p_fds, _timeout)?;
            for (i, p_f) in p_fds.iter().enumerate() {
                fds[i].revents = p_f.revents;
            }
            return Ok(res);
        }

        // Mixed or all virtualized. For now, only handle virtualized correctly.
        // TODO: Handle mixed FDs by polling passthru ones with 0 timeout.
        self.skip_syscall(proc);
        loop {
            let mut ready_count = 0;
            let mut inner = self.network.inner.lock().unwrap();
            for f in fds.iter_mut() {
                f.revents = 0;
                match f.fd {
                    DeterministicFd::Virtualized(idx) => {
                        let sock = inner.sockets[idx].lock().unwrap();
                        if !sock.read_buf.is_empty() {
                            f.revents |= libc::POLLIN;
                        }
                        if sock.is_listener && !sock.backlog.is_empty() {
                            f.revents |= libc::POLLIN;
                        }
                        if sock.closed {
                            f.revents |= libc::POLLHUP;
                        }
                        if f.revents & f.events != 0 {
                            ready_count += 1;
                        }
                    }
                    DeterministicFd::Passthru(_) => {
                        // For now, ignore passthru FDs when mixed
                    }
                }
            }

            if ready_count > 0 {
                return Ok(ready_count);
            }

            if !proc.is_alive() {
                return Err(nix::Error::ESRCH);
            }

            // Wait for events with timeout
            let (new_inner, timeout_res) = self.network.condvar.wait_timeout(inner, std::time::Duration::from_millis(100)).unwrap();
            inner = new_inner;
            if timeout_res.timed_out() && !proc.is_alive() {
                return Err(nix::Error::ESRCH);
            }
        }
    }

    fn sendto(&mut self, proc: &CapturedProcess, fd: &mut DeterministicFd, buf: &[u8], flags: c_int, addr: *const libc::sockaddr, len: libc::socklen_t) -> nix::Result<usize> {
        match fd {
            DeterministicFd::Passthru(f) => self.passthru.sendto(proc, f, buf, flags, addr, len),
            DeterministicFd::Virtualized(idx) => self.virtual_write(proc, *idx, buf),
        }
    }

    fn recvfrom(&mut self, proc: &CapturedProcess, fd: &mut DeterministicFd, count: usize, flags: c_int, addr: *mut libc::sockaddr, len: *mut libc::socklen_t) -> nix::Result<Vec<u8>> {
        match fd {
            DeterministicFd::Passthru(f) => self.passthru.recvfrom(proc, f, count, flags, addr, len),
            DeterministicFd::Virtualized(idx) => self.virtual_read(proc, *idx, count),
        }
    }

    fn fcntl(&mut self, proc: &CapturedProcess, fd: &mut DeterministicFd, cmd: c_int, arg: libc::c_ulong) -> nix::Result<c_int> {
        match fd {
            DeterministicFd::Passthru(f) => self.passthru.fcntl(proc, f, cmd, arg),
            DeterministicFd::Virtualized(_) => {
                // TODO: Implement fcntl for virtualized sockets
                Ok(0)
            }
        }
    }

    fn lseek(&mut self, proc: &CapturedProcess, fd: &mut DeterministicFd, offset: off_t, whence: c_int) -> nix::Result<off_t> {
        match fd {
            DeterministicFd::Passthru(f) => self.passthru.lseek(proc, f, offset, whence),
            DeterministicFd::Virtualized(_) => Err(nix::Error::ESPIPE),
        }
    }

    fn unlink(&mut self, proc: &CapturedProcess, pathname: &str) -> nix::Result<c_int> {
        self.passthru.unlink(proc, pathname)
    }

    fn pwrite(&mut self, proc: &CapturedProcess, fd: &mut DeterministicFd, buf: &[u8], offset: off_t) -> nix::Result<usize> {
        match fd {
            DeterministicFd::Passthru(f) => self.passthru.pwrite(proc, f, buf, offset),
            DeterministicFd::Virtualized(_) => Err(nix::Error::ESPIPE),
        }
    }

    fn fsync(&mut self, proc: &CapturedProcess, fd: &mut DeterministicFd) -> nix::Result<c_int> {
        match fd {
            DeterministicFd::Passthru(f) => self.passthru.fsync(proc, f),
            DeterministicFd::Virtualized(_) => Ok(0),
        }
    }

    fn fdatasync(&mut self, proc: &CapturedProcess, fd: &mut DeterministicFd) -> nix::Result<c_int> {
        match fd {
            DeterministicFd::Passthru(f) => self.passthru.fdatasync(proc, f),
            DeterministicFd::Virtualized(_) => Ok(0),
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
        
        let current_time = self.time_manager.get_time();
        let tv_sec: i64 = current_time.as_secs() as i64;
        let tv_usec: i64 = current_time.subsec_micros() as i64;
        
        let mut bytes = Vec::with_capacity(16);
        bytes.extend_from_slice(&tv_sec.to_ne_bytes());
        bytes.extend_from_slice(&tv_usec.to_ne_bytes());
        
        proc.write_memory(tv_addr, &bytes);
        
        if self.passthru.verbose {
            println!("gettimeofday(..., ...) = 0 (DETERMINISTIC)");
        }
        self.skip_syscall(proc);
        Ok(0)
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
        self.passthru.uname(proc)
    }

    fn sysinfo(&mut self, proc: &CapturedProcess) -> nix::Result<c_int> {
        self.passthru.sysinfo(proc)
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
        // Zero out the tms struct (4 fields of 8 bytes)
        let buf = vec![0u8; 32];
        proc.write_memory(addr, &buf);
        if self.passthru.verbose {
            println!("times(...) = 0 (DETERMINISTIC)");
        }
        self.skip_syscall(proc);
        Ok(0) // Return 0 ticks
    }

    fn writev(&mut self, proc: &CapturedProcess, fd: &mut DeterministicFd, iov: u64, iovcnt: i32) -> nix::Result<usize> {
        match fd {
            DeterministicFd::Passthru(f) => self.passthru.writev(proc, f, iov, iovcnt),
            DeterministicFd::Virtualized(_idx) => {
                // TODO: Implement writev for virtualized sockets
                Ok(0)
            }
        }
    }

    fn futex(&mut self, proc: &CapturedProcess, uaddr: *mut u32, op: c_int, val: u32, timeout: *const libc::timespec, uaddr2: *mut u32, val3: u32) -> nix::Result<c_int> {
        let futex_op = op & !(libc::FUTEX_PRIVATE_FLAG | libc::FUTEX_CLOCK_REALTIME);
        if futex_op == libc::FUTEX_WAIT || futex_op == libc::FUTEX_WAIT_BITSET {
            if self.passthru.verbose {
                println!("futex({:?}, {}, {}, ...) (VIRTUAL)", uaddr, if futex_op == libc::FUTEX_WAIT { "FUTEX_WAIT" } else { "FUTEX_WAIT_BITSET" }, val);
            }
            self.skip_syscall(proc);

            let timeout_dur = if !timeout.is_null() {
                let bytes = proc.read_memory(timeout as usize, 16);
                if bytes.len() < 16 {
                    return Err(nix::Error::EFAULT);
                }
                let tv_sec = i64::from_ne_bytes(bytes[0..8].try_into().unwrap());
                let tv_nsec = i64::from_ne_bytes(bytes[8..16].try_into().unwrap());
                if tv_sec < 0 || tv_nsec < 0 || tv_nsec >= 1_000_000_000 {
                    return Err(nix::Error::EINVAL);
                }
                Some(Duration::new(tv_sec as u64, tv_nsec as u32))
            } else {
                None
            };

            self.time_manager.futex_wait(proc, uaddr as u64, val, timeout_dur)
        } else if futex_op == libc::FUTEX_WAKE || futex_op == libc::FUTEX_WAKE_BITSET {
            if self.passthru.verbose {
                println!("futex({:?}, {}, {}, ...) (VIRTUAL)", uaddr, if futex_op == libc::FUTEX_WAKE { "FUTEX_WAKE" } else { "FUTEX_WAKE_BITSET" }, val);
            }
            self.skip_syscall(proc);
            self.time_manager.futex_wake(uaddr as u64, val)
        } else {
            self.passthru.futex(proc, uaddr, op, val, timeout, uaddr2, val3)
        }
    }

    fn set_tid_address(&mut self, proc: &CapturedProcess, tidptr: *mut c_int) -> nix::Result<c_int> {
        self.tid_address = Some(tidptr as u64);
        self.passthru.set_tid_address(proc, tidptr)
    }

    fn on_exit(&mut self, _proc: &CapturedProcess) {
        if self.passthru.verbose {
            println!("on_exit: waking tid_address {:?} (VIRTUAL)", self.tid_address);
        }
        self.time_manager.on_exit(self.tid_address);
    }

    fn nanosleep(&mut self, proc: &CapturedProcess, req: *const libc::timespec, _rem: *mut libc::timespec) -> nix::Result<c_int> {
        if self.passthru.verbose {
            println!("nanosleep({:?}, ...) (DETERMINISTIC)", req);
        }
        self.skip_syscall(proc);

        let bytes = proc.read_memory(req as usize, 16);
        if bytes.len() < 16 {
            return Err(nix::Error::EFAULT);
        }
        let tv_sec = i64::from_ne_bytes(bytes[0..8].try_into().unwrap());
        let tv_nsec = i64::from_ne_bytes(bytes[8..16].try_into().unwrap());
        if tv_sec < 0 || tv_nsec < 0 || tv_nsec >= 1_000_000_000 {
            return Err(nix::Error::EINVAL);
        }
        let dur = Duration::new(tv_sec as u64, tv_nsec as u32);
        self.time_manager.sleep(proc, dur)?;
        Ok(0)
    }

    fn clock_nanosleep(&mut self, proc: &CapturedProcess, clk_id: libc::clockid_t, flags: c_int, req: *const libc::timespec, _rem: *mut libc::timespec) -> nix::Result<c_int> {
        if self.passthru.verbose {
            println!("clock_nanosleep({}, {}, {:?}, ...) (DETERMINISTIC)", clk_id, flags, req);
        }
        self.skip_syscall(proc);

        let bytes = proc.read_memory(req as usize, 16);
        if bytes.len() < 16 {
            return Err(nix::Error::EFAULT);
        }
        let tv_sec = i64::from_ne_bytes(bytes[0..8].try_into().unwrap());
        let tv_nsec = i64::from_ne_bytes(bytes[8..16].try_into().unwrap());
        if tv_sec < 0 || tv_nsec < 0 || tv_nsec >= 1_000_000_000 {
            return Err(nix::Error::EINVAL);
        }
        let is_abstime = (flags & libc::TIMER_ABSTIME) != 0;
        if is_abstime {
            let target_time = Duration::new(tv_sec as u64, tv_nsec as u32);
            self.time_manager.sleep_until(proc, target_time)?;
        } else {
            let dur = Duration::new(tv_sec as u64, tv_nsec as u32);
            self.time_manager.sleep(proc, dur)?;
        }
        Ok(0)
    }

    fn is_verbose(&self) -> bool {
        self.passthru.verbose
    }
}

impl Deterministic {
    fn virtual_write(&mut self, proc: &CapturedProcess, idx: usize, buf: &[u8]) -> nix::Result<usize> {
        let inner = self.network.inner.lock().unwrap();
        let sock = inner.sockets[idx].lock().unwrap();
        let peer_idx = sock.peer.ok_or(nix::Error::ENOTCONN)?;
        let mut peer_sock = inner.sockets[peer_idx].lock().unwrap();
        peer_sock.read_buf.extend_from_slice(buf);
        self.network.condvar.notify_all();
        self.skip_syscall(proc);
        Ok(buf.len())
    }

    fn virtual_read(&mut self, proc: &CapturedProcess, idx: usize, count: usize) -> nix::Result<Vec<u8>> {
        loop {
            let mut inner = self.network.inner.lock().unwrap();
            let res = {
                let mut sock = inner.sockets[idx].lock().unwrap();
                if !sock.read_buf.is_empty() {
                    let n = std::cmp::min(count, sock.read_buf.len());
                    let buf = sock.read_buf.drain(0..n).collect();
                    Some(Ok(buf))
                } else if sock.closed {
                    Some(Ok(Vec::new()))
                } else {
                    None
                }
            };
            
            if let Some(r) = res {
                self.skip_syscall(proc);
                return r;
            }

            if !proc.is_alive() {
                return Err(nix::Error::ESRCH);
            }

            // Wait for data with timeout
            let (new_inner, timeout_res) = self.network.condvar.wait_timeout(inner, std::time::Duration::from_millis(100)).unwrap();
            inner = new_inner;
            if timeout_res.timed_out() && !proc.is_alive() {
                return Err(nix::Error::ESRCH);
            }
        }
    }

    fn virtual_close(&mut self, proc: &CapturedProcess, idx: usize) -> nix::Result<c_int> {
        let inner = self.network.inner.lock().unwrap();
        let mut sock = inner.sockets[idx].lock().unwrap();
        sock.closed = true;
        if let Some(peer_idx) = sock.peer {
            let mut peer_sock = inner.sockets[peer_idx].lock().unwrap();
            peer_sock.closed = true;
        }
        self.network.condvar.notify_all();
        self.skip_syscall(proc);
        Ok(0)
    }

    unsafe fn read_sockaddr(&self, proc: &CapturedProcess, addr: *const libc::sockaddr, len: libc::socklen_t) -> nix::Result<SocketAddr> {
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
        let mut bytes = vec![0u8; 16];
        let family = libc::AF_INET as u16;
        bytes[0..2].copy_from_slice(&family.to_ne_bytes());
        match sa {
            SocketAddr::V4(addr4) => {
                bytes[2..4].copy_from_slice(&addr4.port().to_be_bytes());
                bytes[4..8].copy_from_slice(&addr4.ip().octets());
            }
            _ => return Err(nix::Error::EAFNOSUPPORT),
        }
        
        proc.write_memory(addr as usize, &bytes);
        let len = bytes.len() as u32;
        proc.write_memory(len_ptr as usize, &len.to_ne_bytes());
        Ok(())
    }
}
