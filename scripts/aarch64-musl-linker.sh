#!/usr/bin/env bash
set -euo pipefail

if command -v clang >/dev/null 2>&1 && command -v ld.lld >/dev/null 2>&1; then
    exec clang --target=aarch64-unknown-linux-musl -fuse-ld=lld "$@"
elif command -v aarch64-linux-musl-gcc >/dev/null 2>&1; then
    exec aarch64-linux-musl-gcc "$@"
elif command -v aarch64-linux-gnu-gcc >/dev/null 2>&1; then
    exec aarch64-linux-gnu-gcc "$@"
else
    echo "error: clang + lld or aarch64-linux-musl-gcc is required to link aarch64-unknown-linux-musl." >&2
    exit 1
fi
