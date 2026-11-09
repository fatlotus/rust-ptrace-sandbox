# NoDice

Imagine you are trying to debug a flaky unit test that fails once every hundred runs. Wouldn't it be nice if you could replay the exact same run of the test to see what went wrong?

NoDice (`nodice`) is a command-line tool for Linux (`x86_64` and `aarch64`) that runs programs inside a deterministic sandbox. It searches for concurrency bugs by varying seeds and timing jitter across runs, and gives you a command to replay any failing run with the same thread and network ordering.

## Installation

Install `nodice` with Cargo:

```bash
cargo install nodice
```

Or build and install from a local checkout:

```bash
cargo install --path .
```

If you prefer not to install it globally, `cargo build --release` produces a standalone binary at `target/release/nodice`.

## Usage

Run any test or command inside the sandbox by wrapping it with `nodice`:

```bash
nodice ./my-test
```

To hunt for a flaky failure, pass `--iterations <N>`. `nodice` runs the command `N` times in parallel across all CPU cores and hides output from successful runs. If you don't specify `--jitter`, it starts with a small jitter (`1ms`) and gradually increases it on each iteration:

```bash
nodice --iterations 50 ./my-test
```

When an iteration fails, `nodice` stops, prints the output from that failing run, and prints the command to replay it:

```text
Failed on iteration 3/50 (seed 3, jitter 3ms). Reproduce with:
  nodice --seed 3 --jitter 3ms ./my-test
```

You can then run that command directly to reproduce the failure:

```bash
nodice --seed 3 --jitter 3ms ./my-test
```

See [`example/`](./example/README.md) for a walkthrough that finds and reproduces a log-truncation race in a 3-node Go Raft cluster over HTTP.

### Options

- `--iterations <N>`: Run the command `N` times in parallel across cores, hiding output from passing runs.
- `--seed <N>`: Seed the internal pseudo-random number generator.
- `--jitter <duration>`: Add deterministic timing jitter (`100us`, `5ms`, `1s`, etc.) to loopback network delivery and readiness notifications.
- `--verbose`, `-v`: Print intercepted system calls and scheduler events.
- `--passthru`, `--no-sandbox`: Trace system calls without virtualizing them.

## How It Works

`nodice` uses `ptrace` to intercept system calls and manually control the ordering of all threads, removing all sources of non-determinism. Then it introduces them back in, in a deterministic way:

1. **Removing non-determinism**: `nodice` intercepts every system call made by the target process and its child threads, pins execution to a single CPU core, disables ASLR and the kernel vDSO, and traps unprivileged instructions that expose host state (`RDTSC`, `RDTSCP`, `CPUID`, `RDRAND`, and `RDSEED` on `x86_64`; `MRS` reads of hardware random and counter registers on `aarch64`). Clocks, timers, `futex` queues, pipes, and loopback TCP sockets (`127.0.0.1` along with `epoll`, `poll`, and `select`) are handled in user space so `nodice` decides which thread wakes up next. Virtual time advances immediately when all runnable threads are blocked on timers, so sleeps do not wait on the wall clock.
2. **Reintroducing deterministic variation**: A ChaCha PRNG seeded by `--seed` supplies `/dev/urandom`, `getrandom`, and initial `AT_RANDOM` bytes (which runtimes like Go use for internal scheduler tie-breaking). When `--jitter` is enabled, `nodice` uses the same PRNG to assign transit delays to loopback packets and shuffle ready `epoll` events. Because every decision comes from the seed, running the command again with the same `--seed` and `--jitter` produces the same thread and message interleaving.

## Limitations

- **Platform**: Linux (`x86_64` and `aarch64`).
- **Overhead**: Every system call goes through a `ptrace` context switch, so syscall-heavy programs run slower than native execution.
- **Adding logs**: Execution is deterministic for a given sequence of system calls. If you add logging that performs extra `write` calls or allocates more memory, the schedule remains identical up to that point, though thread ordering after the new system calls may shift.

## Running the NoDice Test Suite

```bash
cargo test
```

To cross-compile and run the full `aarch64` test suite locally inside an ARM64 Linux kernel under QEMU (`qemu-system-aarch64`):

```bash
./scripts/setup-qemu-arm64.sh
./scripts/test-arm64-qemu.sh
```

Or run individual ARM64 test targets via Cargo's configured QEMU runner:

```bash
cargo test --target aarch64-unknown-linux-gnu --test determinism_test
```