# Typed system call interception in Rust

This project implements a system call interceptor using `ptrace` in Rust, allowing system calls to be handled via a typed trait.

## Goal

Make it possible to implement all system calls of a target process using safe Rust.

## Usage

You can run commands like `echo`, `date`, and `cat` under the ptrace sandbox:

```bash
cargo run --bin=ptrace -- /bin/echo "hello world"
cargo run --bin=ptrace -- /bin/date
cargo run --bin=ptrace -- /bin/cat Cargo.toml
```

### Options

- `--sandbox`: Enable deterministic mode (fixed time and randomness).
- `--verbose`: Print all intercepted system calls and their results.

### Sandbox Mode (Deterministic)

You can enable a deterministic sandbox mode with the `--sandbox` flag. In this mode, system calls return fixed, predictable values to ensure reproducible execution. This is particularly useful for programs like `bash` that use various sources of entropy for things like `$RANDOM`.

Features made deterministic in sandbox mode:
- **Time**: `gettimeofday`, `clock_gettime`, `times`.
- **Identity**: `getpid`, `getppid`, `getpgrp`, `getuid`, `geteuid`, `getgid`, `getegid`.
- **Randomness**: `getrandom` returns a fixed byte pattern.
- **File Metadata**: `fstat` and `newfstatat` zero out timestamps to remove file modification time entropy.
- **Inter-Process Communication (IPC)**: Virtualizes networking (`socket`, `bind`, `connect`, `accept`, `listen`, `poll`) to allow simulated communication between sandboxed processes without exposing real network interfaces.
- **System Info**: `uname` and `sysinfo`.
- **ASLR**: Disables Address Space Layout Randomization (ASLR) in the child process using `personality(ADDR_NO_RANDOMIZE)`.

```bash
cargo run --bin=ptrace -- --sandbox /bin/bash -c 'echo $RANDOM'
cargo run --bin=ptrace -- --sandbox target/debug/random_gen
```

### Verbose Mode

By default, debugging output is hidden. Use the `--verbose` flag to see the intercepted system calls:

```bash
cargo run --bin=ptrace -- --verbose /bin/echo "hello world"
```

## Code Layout

- `src/linux.rs`: The `Linux` trait which defines system calls. It is now generic over a file descriptor type `Fd`, allowing implementations to define what a file descriptor represents. It returns `nix::Result` and each method receives a `&CapturedProcess` to interact with the tracee.
- `src/passthru.rs`: A "passthru" implementation of the `Linux` trait that uses a `PassthruFd` struct (wrapping a `c_int`). It logs and forwards syscalls to the native OS by executing them directly in the tracee context via `CapturedProcess`.
- `src/captured.rs`: The `CapturedProcess` struct which encapsulates `ptrace` operations, providing high-level methods for system call injection and memory access in the tracee.
- `src/vdso.rs`: Logic to disable the virtual Dynamic Shared Object (vDSO) in tracee processes.
- `src/deterministic.rs`: A deterministic implementation of the `Linux` trait that overrides time and randomness syscalls.
- `src/interceptor.rs`: The core logic that handles the ptrace loop. it maintains a mapping between guest `c_int` file descriptors and the generic `Fd` type used by the `Linux` implementation.

- `src/main.rs`: The CLI entry point.

## Testing

All tests are located in the `tests/` directory.

To run the integration tests:

```bash
cargo test
```

### Stress Testing

A `stress` feature is available to run each test multiple times (default 100 iterations) to identify non-deterministic failures or race conditions.

```bash
cargo test --features stress
```

### Test Timeouts

All tests are configured with a 1-second timeout using the `ntest` crate to ensure they complete within a reasonable timeframe and to catch potential deadlocks.

The following tests verify functionality:
- `tests/echo_test.rs`: Basic write/brk interception.
- `tests/cat_test.rs`: File IO interception (openat, read, write, close).
- `tests/date_test.rs`: Time interception (clock_gettime).
- `tests/fork_test.rs`: Process creation interception (fork, vfork, clone).
- `tests/networking.rs`: Networking interception (socket, bind, accept, connect).
- `tests/networking_sandbox.rs`: Verification of networking virtualization in sandbox mode.
- `tests/futex_test.rs`: Verification of futex system call (used by threads).
- `tests/sqlite_test.rs`: SQLite3 support (lseek, unlink, pwrite64, fsync, fdatasync, getcwd).
- `tests/deterministic_test.rs`: Verification of deterministic time and randomness in sandbox mode.

## Parallel Tracing

The interceptor now supports parallel tracing of multi-process and multi-threaded applications. 
- Each process and thread is served by its own instance of the `Linux` trait.
- Tracing loops run in separate host threads to allow concurrent tracee execution.
- Per-process/thread state (like file descriptor maps) is isolated.

This is verified by the `networking` test, which spawns a background thread to handle socket operations concurrently with the main thread.

## Limitations

- The `Passthru` implementation of `exit` and `exit_group` now correctly passes the syscall to the child process instead of killing the tracer.
- `fork`, `vfork`, and `clone` are intercepted to allow tracing of child processes.