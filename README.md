# rust-ptrace-sandbox

A `ptrace`-based deterministic execution sandbox for Linux `x86_64` processes, written in Rust.

By default, `ptrace` runs target programs inside a **deterministic sandbox** that intercepts system calls, traps hardware non-determinism instructions (`RDTSC`, `RDTSCP`, `CPUID`, `RDRAND`, `RDSEED`), disables the vDSO and ASLR, and virtualizes pipes, loopback sockets, futexes, and clocks so consecutive executions produce identical results.

## Features

- **Deterministic Time & Instant Sleep**: Virtualizes `clock_gettime`, `gettimeofday`, `time`, `clock_getres`, `nanosleep`, `clock_nanosleep`, `alarm`, `setitimer`, `getitimer`, `timerfd_*`, and `sysinfo` starting at a fixed epoch (`2022-01-01 00:00:00 UTC`). Multi-threaded sleeps wake in deterministic deadline order without waiting on wall-clock time.
- **Deterministic Entropy & Process Identity**:
  - Scrubs `AT_RANDOM` in the initial auxiliary vector (`auxv`) and disables `AT_SYSINFO_EHDR` (vDSO) so `libc` time and randomness calls always trap into the kernel.
  - Disables ASLR (`ADDR_NO_RANDOMIZE`) across `execve`.
  - Virtualizes `getrandom`, `/dev/random`, and `/dev/urandom` using a seeded ChaCha8 PRNG.
  - Virtualizes `getpid`, `getppid`, `gettid`, UIDs/GIDs, `uname`, `/proc/self/stat`, `/proc/self/maps`, and `/proc/sys/kernel/random/uuid`.
- **Hardware Instruction Trap Emulation**:
  - Disables raw timestamp counter instructions via `prctl(PR_SET_TSC, PR_TSC_SIGSEGV)` and emulates `RDTSC` / `RDTSCP` with virtual clock ticks.
  - Emulates `CPUID` and clears `RDRAND` / `RDSEED` feature bits, trapping and deterministically emulating direct `RDRAND` / `RDSEED` instructions.
- **User-Space Virtual IPC & Loopback Networking**:
  - Emulates `pipe`/`pipe2`, `socketpair`, and loopback TCP (`socket`, `bind`, `listen`, `accept`/`accept4`, `connect`, `getsockname`, `getpeername`, `read`/`write`, `recvfrom`/`sendto`, `recvmsg`/`sendmsg`) in user space.
  - Emulates `futex` (`FUTEX_WAIT`, `FUTEX_WAIT_BITSET`, `FUTEX_WAKE`, `FUTEX_REQUEUE`, `FUTEX_CMP_REQUEUE`) and readiness polling (`poll`, `ppoll`, `select`, `pselect6`, `epoll_*`) deterministically.
- **Filesystem Metadata Normalization**:
  - Normalizes inode numbers, device IDs, ownership, block sizes, and timestamps across `stat`, `lstat`, `fstat`, `newfstatat`, and `statx`.

## Usage

Run any command inside the deterministic sandbox (default):

```bash
cargo run -- <command> [args...]
```

Options:
- `--verbose`, `-v`: Log intercepted syscalls, virtualized operations, and scheduler state transitions to `stderr`.
- `--passthru`, `--no-sandbox`: Disable deterministic virtualization and only trace/log syscalls as they pass through to the host kernel.
- `--sandbox`: Explicitly enable deterministic sandbox mode (enabled by default).

### Examples

```bash
# Run `date` inside the deterministic sandbox (always prints Sat Jan  1 00:00:00 UTC 2022)
cargo run -- date -u

# Run a command with verbose syscall tracing
cargo run -- --verbose echo "Hello, sandbox!"

# Run in passthru mode without sandboxing
cargo run -- --passthru date
```

## Running Tests

Run the test suite:

```bash
cargo test
```

Run the stress test suite:

```bash
cargo test --features stress
```