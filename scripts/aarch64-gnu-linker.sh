#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SYSROOT="$REPO_ROOT/target/qemu-arm64/sysroot"

if [ -d "$SYSROOT/lib/aarch64-linux-gnu" ]; then
    GCC_DIR="$(find "$SYSROOT/usr/lib/gcc/aarch64-linux-gnu" -maxdepth 1 -mindepth 1 -type d | head -n 1)"
    exec clang \
        --target=aarch64-unknown-linux-gnu \
        -fuse-ld=lld \
        --sysroot="$SYSROOT" \
        -B"$GCC_DIR" \
        -L"$GCC_DIR" \
        -L"$SYSROOT/lib/aarch64-linux-gnu" \
        -L"$SYSROOT/usr/lib/aarch64-linux-gnu" \
        "$@"
elif command -v aarch64-linux-gnu-gcc >/dev/null 2>&1; then
    exec aarch64-linux-gnu-gcc "$@"
else
    echo "error: ARM64 sysroot not found at $SYSROOT and aarch64-linux-gnu-gcc is not installed." >&2
    echo "Run ./scripts/setup-qemu-arm64.sh first." >&2
    exit 1
fi
