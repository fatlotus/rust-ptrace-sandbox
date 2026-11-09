#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
QEMU_DIR="$REPO_ROOT/target/qemu-arm64"

if [ ! -f "$QEMU_DIR/initramfs.cpio" ] || [ ! -e "$QEMU_DIR/vmlinuz" ]; then
    "$REPO_ROOT/scripts/setup-qemu-arm64.sh"
fi

if command -v qemu-system-aarch64 >/dev/null 2>&1; then
    QEMU_BIN="qemu-system-aarch64"
    QEMU_SHARE=()
else
    export LD_LIBRARY_PATH="$QEMU_DIR/host/usr/lib/x86_64-linux-gnu:$QEMU_DIR/host/lib/x86_64-linux-gnu${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
    QEMU_BIN="$QEMU_DIR/host/usr/bin/qemu-system-aarch64"
    QEMU_SHARE=(-L "$QEMU_DIR/host/usr/share/qemu")
fi

BIN_PATH="$(realpath "$1")"
shift

NODICE_BIN="${CARGO_BIN_EXE_nodice:-}"
if [ -z "$NODICE_BIN" ]; then
    CANDIDATE="$(dirname "$(dirname "$BIN_PATH")")/nodice"
    if [ -x "$CANDIDATE" ]; then
        NODICE_BIN="$CANDIDATE"
    fi
fi

RUNNER_SCRIPT="$QEMU_DIR/guest_run_$$.sh"
LOG_FILE="$QEMU_DIR/qemu_out_$$.log"
trap 'rm -f "$RUNNER_SCRIPT" "$LOG_FILE"' EXIT

{
    echo "#!/bin/sh"
    echo "set -e"
    echo "cd \"$REPO_ROOT\""
    echo "export RUST_BACKTRACE=\"${RUST_BACKTRACE:-1}\""
    echo "export RUST_TEST_THREADS=\"${RUST_TEST_THREADS:-1}\""
    if [ -n "$NODICE_BIN" ] && [ -f "$NODICE_BIN" ]; then
        echo "cp \"$NODICE_BIN\" /tmp/nodice"
        echo "chmod +x /tmp/nodice"
        echo "/bin/busybox mount --bind /tmp/nodice \"$NODICE_BIN\" 2>/dev/null || true"
        echo "export CARGO_BIN_EXE_nodice=/tmp/nodice"
    fi
    echo "cp \"$BIN_PATH\" /tmp/test_bin"
    echo "chmod +x /tmp/test_bin"
    printf 'exec /tmp/test_bin'
    for arg in "$@"; do
        printf ' %q' "$arg"
    done
    printf '\n'
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
