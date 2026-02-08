# Typed system call interception in Rust

This project implements a system call interceptor using `ptrace` in Rust, allowing system calls to be handled via a typed trait.

## Goal

Make it possible to implement all system calls of a target process using safe Rust.

## Usage

You can run any command under the ptrace sandbox using the `Passthru` implementation:

```bash
cargo run -- /bin/echo "hello world"
```

The output will show the intercepted system calls and their results:

```
brk(0x0) = 0
write(1, "hello world\n", 12) = 12
exit_group(0)
```

## Code Layout

- `src/linux.rs`: The `Linux` trait which defines system calls using idiomatic Rust types (from `libc`).
- `src/passthru.rs`: A "passthru" implementation of the `Linux` trait that logs and forwards syscalls to the native OS.
- `src/interceptor.rs`: The core logic that spawns a child process with `PTRACE_TRACEME` and handles the syscall interception loop, including memory reading from the child process.
- `src/main.rs`: The CLI entry point.

## Testing

All tests are located in the `tests/` directory.

To run the integration tests:

```bash
cargo test
```

The `tests/echo_test.rs` verifies that `/bin/echo` runs correctly under the sandbox and that system calls are being intercepted as expected.