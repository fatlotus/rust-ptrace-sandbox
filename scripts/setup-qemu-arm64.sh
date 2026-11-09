#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
QEMU_DIR="$REPO_ROOT/target/qemu-arm64"
mkdir -p "$QEMU_DIR"

python3 - "$QEMU_DIR" <<'PYEOF'
import gzip
import os
import re
import shutil
import stat
import subprocess
import sys
import urllib.request

qemu_dir = os.path.abspath(sys.argv[1])
debs_dir = os.path.join(qemu_dir, "debs")
host_dir = os.path.join(qemu_dir, "host")
sysroot_dir = os.path.join(qemu_dir, "sysroot")
rootfs_dir = os.path.join(qemu_dir, "rootfs")
stage_dir = os.path.join(qemu_dir, "initramfs_stage")

for d in [debs_dir, host_dir, sysroot_dir, rootfs_dir]:
    os.makedirs(d, exist_ok=True)

def get_packages(arch):
    cache = os.path.join(debs_dir, f"Packages-{arch}.txt")
    if not os.path.exists(cache):
        url = f"https://deb.debian.org/debian/dists/bookworm/main/binary-{arch}/Packages.gz"
        print(f"Fetching Debian Bookworm package index for {arch}...")
        with urllib.request.urlopen(url) as resp:
            data = gzip.decompress(resp.read()).decode("utf-8", errors="replace")
        with open(cache, "w") as f:
            f.write(data)
    else:
        with open(cache) as f:
            data = f.read()
    pkgs = {}
    for block in data.split("\n\n"):
        m_pkg = re.search(r"^Package: (\S+)", block, re.M)
        m_file = re.search(r"^Filename: (\S+)", block, re.M)
        if m_pkg and m_file:
            pkgs[m_pkg.group(1)] = m_file.group(1)
    return pkgs

def download_and_extract(pkgs, arch, pkg_name, dest):
    rel_url = pkgs[pkg_name]
    deb_path = os.path.join(debs_dir, f"{pkg_name}_{arch}.deb")
    marker = os.path.join(dest, f".extracted_{pkg_name}_{arch}")
    if not os.path.exists(deb_path):
        print(f"Downloading {pkg_name} ({arch})...")
        urllib.request.urlretrieve(f"https://deb.debian.org/debian/{rel_url}", deb_path)
    if not os.path.exists(marker):
        subprocess.run(["dpkg-deb", "-x", deb_path, dest], check=True)
        with open(marker, "w") as f:
            f.write("ok\n")

if shutil.which("qemu-system-aarch64") is None:
    amd64 = get_packages("amd64")
    host_pkgs = [
        "qemu-system-arm",
        "qemu-system-common",
        "qemu-system-data",
        "libcapstone4",
        "libfdt1",
        "libpixman-1-0",
        "libslirp0",
        "liburing2",
        "libaio1",
        "libbpf1",
        "libfuse3-3",
        "libibverbs1",
        "libnuma1",
        "libpmem1",
        "librdmacm1",
        "libvdeplug2",
        "libnl-3-200",
        "libnl-route-3-200",
        "libdaxctl1",
        "libndctl6",
        "libkmod2",
    ]
    for pkg in host_pkgs:
        if pkg in amd64:
            download_and_extract(amd64, "amd64", pkg, host_dir)

arm64 = get_packages("arm64")

# Find latest Debian Bookworm standard arm64 kernel image
kernel_pkgs = sorted(
    k for k in arm64.keys()
    if re.match(r"^linux-image-6\.1\.0-\d+-arm64$", k)
)
if not kernel_pkgs:
    raise RuntimeError("Could not find linux-image-6.1.0-*-arm64 in Debian Bookworm")
kernel_pkg = kernel_pkgs[-1]
kernel_ver = kernel_pkg.replace("linux-image-", "")

sysroot_pkgs = [
    "libc6",
    "libc6-dev",
    "libgcc-s1",
    "gcc-12-base",
    "libgcc-12-dev",
    "linux-libc-dev",
]
for pkg in sysroot_pkgs:
    download_and_extract(arm64, "arm64", pkg, sysroot_dir)

# Fix absolute symlinks in sysroot so clang --sysroot resolves them cleanly
for root, dirs, files in os.walk(sysroot_dir):
    for name in files + dirs:
        p = os.path.join(root, name)
        if os.path.islink(p):
            target = os.readlink(p)
            if target.startswith("/"):
                rel = os.path.relpath(os.path.join(sysroot_dir, target.lstrip("/")), root)
                os.unlink(p)
                os.symlink(rel, p)

rootfs_pkgs = [
    kernel_pkg,
    "busybox-static",
    "coreutils",
    "dash",
    "libc6",
    "libgcc-s1",
    "libacl1",
    "libattr1",
    "libselinux1",
    "libgmp10",
    "libpcre2-8-0",
    "sqlite3",
    "libsqlite3-0",
    "libreadline8",
    "libtinfo6",
    "zlib1g",
]
for pkg in rootfs_pkgs:
    download_and_extract(arm64, "arm64", pkg, rootfs_dir)

vmlinuz_src = os.path.join(rootfs_dir, "boot", f"vmlinuz-{kernel_ver}")
vmlinuz_dst = os.path.join(qemu_dir, "vmlinuz")
if os.path.lexists(vmlinuz_dst):
    os.unlink(vmlinuz_dst)
os.symlink(vmlinuz_src, vmlinuz_dst)

# Stage initramfs
if os.path.exists(stage_dir):
    shutil.rmtree(stage_dir)

for d in [
    "bin",
    "sbin",
    "usr/bin",
    "lib/aarch64-linux-gnu",
    "usr/lib/aarch64-linux-gnu",
    "lib/modules",
    "proc",
    "sys",
    "dev",
    "tmp",
    "etc",
    "run",
]:
    os.makedirs(os.path.join(stage_dir, d), exist_ok=True)

shutil.copy2(os.path.join(rootfs_dir, "bin/busybox"), os.path.join(stage_dir, "bin/busybox"))
os.chmod(os.path.join(stage_dir, "bin/busybox"), 0o755)
for applet in [
    "sh", "mount", "umount", "mkdir", "mknod", "chmod", "chown", "ln",
    "rm", "cp", "mv", "ls", "grep", "sed", "awk", "cut", "head", "tail",
    "tr", "wc", "sort", "uniq", "find", "xargs",
]:
    os.symlink("busybox", os.path.join(stage_dir, "bin", applet))
for sapplet in ["insmod", "ifconfig", "route", "poweroff", "halt", "reboot", "sysctl"]:
    os.symlink("../bin/busybox", os.path.join(stage_dir, "sbin", sapplet))

for b in ["echo", "cat", "date", "sleep", "dash"]:
    src = os.path.join(rootfs_dir, "bin", b)
    if os.path.exists(src):
        shutil.copy2(src, os.path.join(stage_dir, "bin", b))
os.unlink(os.path.join(stage_dir, "bin/sh"))
os.symlink("dash", os.path.join(stage_dir, "bin/sh"))

for ub in ["od", "sqlite3", "env", "id", "expr", "seq", "test", "true", "false"]:
    src = os.path.join(rootfs_dir, "usr/bin", ub)
    if os.path.exists(src):
        shutil.copy2(src, os.path.join(stage_dir, "usr/bin", ub))

for libdir in ["lib/aarch64-linux-gnu", "usr/lib/aarch64-linux-gnu"]:
    src_dir = os.path.join(rootfs_dir, libdir)
    dst_dir = os.path.join(stage_dir, libdir)
    for name in os.listdir(src_dir):
        if ".so" in name:
            s = os.path.join(src_dir, name)
            d = os.path.join(dst_dir, name)
            if os.path.islink(s):
                os.symlink(os.readlink(s), d)
            elif os.path.isfile(s):
                shutil.copy2(s, d)

if not os.path.exists(os.path.join(stage_dir, "lib/ld-linux-aarch64.so.1")):
    os.symlink(
        "aarch64-linux-gnu/ld-linux-aarch64.so.1",
        os.path.join(stage_dir, "lib/ld-linux-aarch64.so.1"),
    )

mod_base = os.path.join(rootfs_dir, "lib/modules", kernel_ver, "kernel")
mods = [
    "drivers/virtio/virtio_pci_legacy_dev.ko",
    "drivers/virtio/virtio_pci_modern_dev.ko",
    "drivers/virtio/virtio_pci.ko",
    "drivers/virtio/virtio_mmio.ko",
    "fs/netfs/netfs.ko",
    "fs/fscache/fscache.ko",
    "net/9p/9pnet.ko",
    "net/9p/9pnet_virtio.ko",
    "fs/9p/9p.ko",
]
for m in mods:
    shutil.copy2(
        os.path.join(mod_base, m),
        os.path.join(stage_dir, "lib/modules", os.path.basename(m)),
    )

with open(os.path.join(stage_dir, "etc/passwd"), "w") as f:
    f.write("root:x:0:0:root:/root:/bin/sh\nantigravity:x:1000:1000:antigravity:/tmp:/bin/sh\n")
with open(os.path.join(stage_dir, "etc/group"), "w") as f:
    f.write("root:x:0:\nantigravity:x:1000:\n")
with open(os.path.join(stage_dir, "etc/machine-id"), "w") as f:
    f.write("0123456789abcdef0123456789abcdef\n")

init_script = """#!/bin/busybox sh
export PATH=/usr/bin:/bin:/sbin
/bin/busybox mount -t proc proc /proc
/bin/busybox mount -t sysfs sysfs /sys
/bin/busybox mount -t devtmpfs devtmpfs /dev 2>/dev/null || /bin/busybox mount -t tmpfs dev /dev
/bin/busybox mkdir -p /dev/pts /dev/shm
/bin/busybox mount -t tmpfs tmpfs /tmp
/bin/busybox mount -t tmpfs tmpfs /run

/sbin/ifconfig lo 127.0.0.1 up

for m in virtio_pci_legacy_dev.ko virtio_pci_modern_dev.ko virtio_pci.ko virtio_mmio.ko netfs.ko fscache.ko 9pnet.ko 9pnet_virtio.ko 9p.ko; do
    /sbin/insmod /lib/modules/$m 2>/dev/null
done

WS=$(/bin/busybox sed -n 's/.*nodice_ws=\\([^ ]*\\).*/\\1/p' /proc/cmdline)
RUNNER=$(/bin/busybox sed -n 's/.*nodice_run=\\([^ ]*\\).*/\\1/p' /proc/cmdline)

if [ -n "$WS" ]; then
    /bin/busybox mkdir -p "$WS"
    /bin/busybox mount -t 9p -o trans=virtio,version=9p2000.L,msize=524288,ro hostws "$WS"
fi

if [ -n "$RUNNER" ] && [ -f "$RUNNER" ]; then
    /bin/sh "$RUNNER"
    RC=$?
else
    echo "error: guest runner script not found: $RUNNER"
    RC=1
fi

echo "NODICE_QEMU_EXIT_CODE=$RC"
/sbin/poweroff -f
"""
init_path = os.path.join(stage_dir, "init")
with open(init_path, "w") as f:
    f.write(init_script)
os.chmod(init_path, 0o755)

def write_cpio_newc(root_dir, out_path):
    ino = 1
    with open(out_path, "wb") as out:
        def add_entry(rel_path, full_path):
            nonlocal ino
            st = os.lstat(full_path)
            mode = st.st_mode
            if stat.S_ISLNK(mode):
                body = os.readlink(full_path).encode("utf-8")
            elif stat.S_ISREG(mode):
                with open(full_path, "rb") as f:
                    body = f.read()
            else:
                body = b""
            name_bytes = rel_path.encode("utf-8") + b"\x00"
            hdr = (
                f"070701"
                f"{ino:08x}"
                f"{mode:08x}"
                f"{0:08x}"
                f"{0:08x}"
                f"{1:08x}"
                f"{0:08x}"
                f"{len(body):08x}"
                f"{0:08x}{0:08x}{0:08x}{0:08x}"
                f"{len(name_bytes):08x}"
                f"{0:08x}"
            ).encode("ascii")
            ino += 1
            out.write(hdr + name_bytes)
            pad_hdr = (4 - ((len(hdr) + len(name_bytes)) % 4)) % 4
            out.write(b"\x00" * pad_hdr)
            if body:
                out.write(body)
                pad_body = (4 - (len(body) % 4)) % 4
                out.write(b"\x00" * pad_body)

        for dirpath, dirnames, filenames in os.walk(root_dir):
            dirnames.sort()
            filenames.sort()
            rel_dir = os.path.relpath(dirpath, root_dir)
            if rel_dir != ".":
                add_entry(rel_dir, dirpath)
            for fn in dirnames:
                p = os.path.join(dirpath, fn)
                if os.path.islink(p):
                    add_entry(os.path.relpath(p, root_dir), p)
            for fn in filenames:
                p = os.path.join(dirpath, fn)
                add_entry(os.path.relpath(p, root_dir), p)

        trailer = b"TRAILER!!!\x00"
        hdr = (
            f"070701{0:08x}{0:08x}{0:08x}{0:08x}{1:08x}{0:08x}{0:08x}"
            f"{0:08x}{0:08x}{0:08x}{0:08x}{len(trailer):08x}{0:08x}"
        ).encode("ascii")
        out.write(hdr + trailer)
        pad = (4 - ((len(hdr) + len(trailer)) % 4)) % 4
        out.write(b"\x00" * pad)

cpio_path = os.path.join(qemu_dir, "initramfs.cpio")
write_cpio_newc(stage_dir, cpio_path)
print(f"ARM64 QEMU environment ready at {qemu_dir}")
PYEOF
