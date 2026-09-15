#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VM_DIR="$SCRIPT_DIR"
BUILD_DIR="$VM_DIR/.build"
ROOTFS_DIR="$BUILD_DIR/rootfs"

ALPINE_MIRROR="https://dl-cdn.alpinelinux.org/alpine/v3.20"
MINIROOTFS_URL="$ALPINE_MIRROR/releases/x86_64/alpine-minirootfs-3.20.3-x86_64.tar.gz"
LINUX_VIRT_URL="$ALPINE_MIRROR/main/x86_64/linux-virt-6.6.142-r0.apk"
BASH_URL="$ALPINE_MIRROR/main/x86_64/bash-5.2.26-r0.apk"
READLINE_URL="$ALPINE_MIRROR/main/x86_64/readline-8.2.10-r0.apk"
NCURSESW_URL="$ALPINE_MIRROR/main/x86_64/libncursesw-6.4_p20240420-r2.apk"
TERMINFO_URL="$ALPINE_MIRROR/main/x86_64/ncurses-terminfo-base-6.4_p20240420-r2.apk"
SQLITE_URL="$ALPINE_MIRROR/main/x86_64/sqlite-3.45.3-r3.apk"

if [[ -f "$VM_DIR/vmlinuz" && -f "$VM_DIR/initramfs.cpio.gz" && "${1:-}" != "--force" ]]; then
    echo "VM files already exist in $VM_DIR. Pass --force to re-generate."
    exit 0
fi

echo "Setting up minimal QEMU Linux VM in $VM_DIR..."

rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR" "$ROOTFS_DIR"

download() {
    local url="$1"
    local dest="$2"
    if [[ ! -f "$dest" ]]; then
        echo "Downloading $(basename "$url")..."
        curl -fsSL "$url" -o "$dest"
    fi
}

mkdir -p "$VM_DIR/.cache"

download "$MINIROOTFS_URL" "$VM_DIR/.cache/alpine-minirootfs.tar.gz"
download "$LINUX_VIRT_URL" "$VM_DIR/.cache/linux-virt.apk"
download "$BASH_URL" "$VM_DIR/.cache/bash.apk"
download "$READLINE_URL" "$VM_DIR/.cache/readline.apk"
download "$NCURSESW_URL" "$VM_DIR/.cache/libncursesw.apk"
download "$TERMINFO_URL" "$VM_DIR/.cache/ncurses-terminfo-base.apk"
download "$SQLITE_URL" "$VM_DIR/.cache/sqlite.apk"

echo "Extracting base rootfs..."
tar -xzf "$VM_DIR/.cache/alpine-minirootfs.tar.gz" -C "$ROOTFS_DIR"

echo "Extracting packages (bash, sqlite, readline, ncurses)..."
tar -xzf "$VM_DIR/.cache/bash.apk" -C "$ROOTFS_DIR"
tar -xzf "$VM_DIR/.cache/readline.apk" -C "$ROOTFS_DIR"
tar -xzf "$VM_DIR/.cache/libncursesw.apk" -C "$ROOTFS_DIR"
tar -xzf "$VM_DIR/.cache/ncurses-terminfo-base.apk" -C "$ROOTFS_DIR"
tar -xzf "$VM_DIR/.cache/sqlite.apk" -C "$ROOTFS_DIR"

echo "Extracting kernel and modules..."
tar -xzf "$VM_DIR/.cache/linux-virt.apk" -C "$BUILD_DIR"
cp "$BUILD_DIR/boot/vmlinuz-virt" "$VM_DIR/vmlinuz"
cp -r "$BUILD_DIR/lib/modules" "$ROOTFS_DIR/lib/"

echo "Creating init script..."
cat <<'EOF' > "$ROOTFS_DIR/init"
#!/bin/sh
export PATH=/bin:/sbin:/usr/bin:/usr/sbin
export TERM=xterm-256color

mount -t proc proc /proc
mount -t sysfs sys /sys
mount -t devtmpfs dev /dev
mkdir -p /dev/pts /dev/shm
mount -t devpts devpts /dev/pts
mount -t tmpfs tmpfs /dev/shm
mount -t tmpfs tmpfs /tmp

# Enable loopback interface for network tests
ifconfig lo 127.0.0.1 up 2>/dev/null || ip link set lo up 2>/dev/null

# Load 9p modules
modprobe 9pnet 2>/dev/null
modprobe 9pnet_virtio 2>/dev/null
modprobe 9p 2>/dev/null

# Mount workspace
mkdir -p /workspace
if ! mount -t 9p -o trans=virtio,version=9p2000.L,msize=1048576 workspace /workspace 2>/dev/null; then
    mount -t 9p -o trans=virtio workspace /workspace 2>/dev/null
fi

# Mirror host path so absolute paths embedded in test binaries resolve
HOST_DIR=$(sed -n 's/.*qemu_host_pwd=\([^ ]*\).*/\1/p' /proc/cmdline)
if [ -n "$HOST_DIR" ]; then
    mkdir -p "$(dirname "$HOST_DIR")"
    ln -sf /workspace "$HOST_DIR"
fi

# Ensure /bin/bash and symlinks exist
[ -f /usr/bin/bash ] && [ ! -f /bin/bash ] && ln -s /usr/bin/bash /bin/bash
[ -f /usr/bin/sqlite3 ] && [ ! -f /bin/sqlite3 ] && ln -s /usr/bin/sqlite3 /bin/sqlite3

CUSTOM_CMD=$(sed -n 's/.*qemu_cmd=\([^ ]*\).*/\1/p' /proc/cmdline)

if grep -q "qemu_test=1" /proc/cmdline; then
    echo "============================================================"
    echo "             Running Linux Tests inside QEMU                "
    echo "============================================================"
    TEST_EXIT=0
    if [ -f /workspace/vm/guest_test_runner.sh ]; then
        /bin/bash /workspace/vm/guest_test_runner.sh
        TEST_EXIT=$?
    else
        echo "Error: /workspace/vm/guest_test_runner.sh not found!"
        TEST_EXIT=1
    fi
    mkdir -p /workspace/target
    echo "$TEST_EXIT" > /workspace/target/.vm_test_status
    sync
elif [ -n "$CUSTOM_CMD" ]; then
    DECODED_CMD=$(echo "$CUSTOM_CMD" | base64 -d 2>/dev/null || echo "$CUSTOM_CMD")
    cd /workspace
    eval "$DECODED_CMD"
    CMD_EXIT=$?
    mkdir -p /workspace/target
    echo "$CMD_EXIT" > /workspace/target/.vm_cmd_status
    sync
else
    echo "============================================================"
    echo "       Welcome to Minimal Linux x86_64 VM (QEMU)            "
    echo "       Workspace mounted at: /workspace                     "
    echo "============================================================"
    cd /workspace
    /bin/bash --login
fi

echo "Powering off VM..."
sync
poweroff -f
reboot -f
EOF

chmod +x "$ROOTFS_DIR/init"

# Clean up any apk metadata left in rootfs
rm -f "$ROOTFS_DIR"/.PKGINFO "$ROOTFS_DIR"/.SIGN.* "$ROOTFS_DIR"/.pre-install "$ROOTFS_DIR"/.post-install

echo "Building initramfs.cpio.gz..."
(cd "$ROOTFS_DIR" && find . | cpio -o -H newc | gzip -9) > "$VM_DIR/initramfs.cpio.gz"

echo "Cleaning up temporary build directory..."
rm -rf "$BUILD_DIR"

echo "VM setup complete! Kernel: $VM_DIR/vmlinuz, Initramfs: $VM_DIR/initramfs.cpio.gz"
