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

- `src/linux.rs`: The `Linux` trait which defines system calls (`read`, `write`, `open`, `close`, `brk`, `mmap`, `clock_gettime`, etc.).
- `src/passthru.rs`: A "passthru" implementation of the `Linux` trait that logs and forwards syscalls to the native OS.
- `src/vdso.rs`: Logic to disable the virtual Dynamic Shared Object (vDSO) in tracee processes. This ensures that syscalls like `clock_gettime` are forced to go through the kernel where they can be intercepted.
- `src/interceptor.rs`: The core logic that handles the ptrace loop. It includes a `waitpid` timeout (1 second) to prevent hangs and safely terminates stalling child processes.
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

## Limitations

- The `Passthru` implementation of `exit` and `exit_group` now correctly passes the syscall to the child process instead of killing the tracer.
- `fork`, `vfork`, and `clone` are intercepted to allow tracing of child processes.