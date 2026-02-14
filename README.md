# Typed system call interception in Rust

This project implements a system call interceptor using `ptrace` in Rust, allowing system calls to be handled via a typed trait.

## Goal

Make it possible to implement all system calls of a target process using safe Rust.

## Usage

You can run commands like `echo`, `date`, and `cat` under the ptrace sandbox:

```bash
cargo run -- /bin/echo "hello world"
cargo run -- /bin/date
cargo run -- /bin/cat Cargo.toml
```

The output will show the intercepted system calls and their results:

```
openat(AT_FDCWD, "Cargo.toml", O_RDONLY, 0) = 3
read(3, ..., 8192) = 181
write(1, "...", 181) = 181
close(3) = 0
```

## Code Layout

- `src/linux.rs`: The `Linux` trait which defines system calls. It is now generic over a file descriptor type `Fd`, allowing implementations to define what a file descriptor represents. It returns `nix::Result` and each method receives a `&CapturedProcess` to interact with the tracee.
- `src/passthru.rs`: A "passthru" implementation of the `Linux` trait that uses a `PassthruFd` struct (wrapping a `c_int`). It logs and forwards syscalls to the native OS by executing them directly in the tracee context via `CapturedProcess`.
- `src/captured.rs`: The `CapturedProcess` struct which encapsulates `ptrace` operations, providing high-level methods for system call injection and memory access in the tracee.
- `src/vdso.rs`: Logic to disable the virtual Dynamic Shared Object (vDSO) in tracee processes.
- `src/interceptor.rs`: The core logic that handles the ptrace loop. it maintains a mapping between guest `c_int` file descriptors and the generic `Fd` type used by the `Linux` implementation.

- `src/main.rs`: The CLI entry point.

## Testing

All tests are located in the `tests/` directory.

To run the integration tests:

```bash
cargo test
```

The following tests verify functionality:
- `tests/echo_test.rs`: Basic write/brk interception.
- `tests/cat_test.rs`: File IO interception (openat, read, write, close).
- `tests/date_test.rs`: Time interception (clock_gettime).
- `tests/fork_test.rs`: Process creation interception (fork, vfork, clone).
- `tests/networking.rs`: Networking interception (socket, bind, accept, connect).
- `tests/sqlite_test.rs`: SQLite3 support (lseek, unlink, pwrite64, fsync, fdatasync, getcwd).

## Parallel Tracing

The interceptor now supports parallel tracing of multi-process and multi-threaded applications. 
- Each process and thread is served by its own instance of the `Linux` trait.
- Tracing loops run in separate host threads to allow concurrent tracee execution.
- Per-process/thread state (like file descriptor maps) is isolated.

This is verified by the `networking` test, which spawns a background thread to handle socket operations concurrently with the main thread.

## Limitations

- The `Passthru` implementation of `exit` and `exit_group` now correctly passes the syscall to the child process instead of killing the tracer.
- `fork`, `vfork`, and `clone` are intercepted to allow tracing of child processes.