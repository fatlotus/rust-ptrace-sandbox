#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

if [ -d "$HOME/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/bin" ]; then
    export RUSTUP_HOME="$HOME/.rustup"
    export PATH="$HOME/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/bin:$PATH"
fi

TARGET="${CARGO_BUILD_TARGET:-aarch64-unknown-linux-gnu}"
QEMU_DIR="$REPO_ROOT/target/qemu-arm64"

if [ ! -f "$QEMU_DIR/initramfs.cpio" ] || [ ! -e "$QEMU_DIR/vmlinuz" ]; then
    "$REPO_ROOT/scripts/setup-qemu-arm64.sh"
fi

# Build the nodice binary and all test binaries on the host first
cargo build --target "$TARGET" --bin nodice
cargo test --target "$TARGET" --no-run "$@"

if [ $# -gt 0 ]; then
    exec cargo test --target "$TARGET" "$@"
fi

# Run all integration test suites inside a single QEMU VM boot for fast iteration
if command -v qemu-system-aarch64 >/dev/null 2>&1; then
    QEMU_BIN="qemu-system-aarch64"
    QEMU_SHARE=()
else
    export LD_LIBRARY_PATH="$QEMU_DIR/host/usr/lib/x86_64-linux-gnu:$QEMU_DIR/host/lib/x86_64-linux-gnu${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
    QEMU_BIN="$QEMU_DIR/host/usr/bin/qemu-system-aarch64"
    QEMU_SHARE=(-L "$QEMU_DIR/host/usr/share/qemu")
fi

RUNNER_SCRIPT="$QEMU_DIR/guest_suite_$$.sh"
LOG_FILE="$QEMU_DIR/qemu_suite_$$.log"
trap 'rm -f "$RUNNER_SCRIPT" "$LOG_FILE"' EXIT

{
    echo "#!/bin/sh"
    echo "set -e"
    echo "cd \"$REPO_ROOT\""
    echo "export RUST_BACKTRACE=\"${RUST_BACKTRACE:-1}\""
    echo "cp \"$REPO_ROOT/target/$TARGET/debug/nodice\" /tmp/nodice"
    echo "chmod +x /tmp/nodice"
    echo "/bin/busybox mount --bind /tmp/nodice \"$REPO_ROOT/target/$TARGET/debug/nodice\" 2>/dev/null || true"
    echo "export CARGO_BIN_EXE_nodice=/tmp/nodice"
    for suite in cli_test concurrency_test determinism_test filesystem_test networking_test; do
        BIN="$(find "$REPO_ROOT/target/$TARGET/debug/deps" -maxdepth 1 -type f -executable -name "${suite}-*" | head -n 1)"
        if [ -n "$BIN" ]; then
            echo "echo \"=== Running $suite ($TARGET) ===\""
            echo "cp \"$BIN\" /tmp/$suite"
            echo "chmod +x /tmp/$suite"
            if [ "$suite" = "cli_test" ]; then
                echo "/tmp/$suite --test-threads=1"
            else
                echo "/tmp/$suite"
            fi
            echo "rm -f /tmp/$suite"
        fi
    done
} > "$RUNNER_SCRIPT"
chmod +x "$RUNNER_SCRIPT"

"$QEMU_BIN" \
    -M virt \
    -cpu cortex-a72 \
    -smp 4 \
    -m 1024M \
    -nographic \
    -no-reboot \
    -nic none \
    "${QEMU_SHARE[@]}" \
    -kernel "$QEMU_DIR/vmlinuz" \
    -initrd "$QEMU_DIR/initramfs.cpio" \
    -fsdev "local,id=hostws,path=$REPO_ROOT,security_model=none,readonly=on" \
    -device "virtio-9p-pci,fsdev=hostws,mount_tag=hostws,romfile=" \
    -append "console=ttyAMA0 quiet panic=-1 nodice_ws=$REPO_ROOT nodice_run=$RUNNER_SCRIPT" \
    2>&1 | tee "$LOG_FILE"

EXIT_CODE="$(sed -n 's/.*NODICE_QEMU_EXIT_CODE=\([0-9]*\).*/\1/p' "$LOG_FILE" | tail -n 1)"
exit "${EXIT_CODE:-1}"
