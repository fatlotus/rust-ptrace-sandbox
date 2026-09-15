#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VM_DIR="$SCRIPT_DIR"
PROJECT_DIR="$(cd "$VM_DIR/.." && pwd)"

# Ensure VM files exist
if [[ ! -f "$VM_DIR/vmlinuz" || ! -f "$VM_DIR/initramfs.cpio.gz" ]]; then
    echo "VM files not found. Running setup..."
    "$VM_DIR/setup.sh"
fi

APPEND="console=ttyS0 quiet panic=-1 qemu_host_pwd=$PROJECT_DIR"
TEST_MODE=0
CMD_MODE=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --test)
            TEST_MODE=1
            APPEND="$APPEND qemu_test=1"
            shift
            ;;
        --cmd)
            shift
            CMD_MODE="$1"
            ENCODED_CMD=$(echo -n "$CMD_MODE" | base64 | tr -d '\n')
            APPEND="$APPEND qemu_cmd=$ENCODED_CMD"
            shift
            ;;
        *)
            echo "Unknown argument: $1"
            echo "Usage: $0 [--test] [--cmd <command>]"
            exit 1
            ;;
    esac
done

rm -f "$PROJECT_DIR/target/.vm_test_status" "$PROJECT_DIR/target/.vm_cmd_status"

# Run QEMU
qemu-system-x86_64 \
    -m 1024M \
    -smp 4 \
    -cpu max \
    -kernel "$VM_DIR/vmlinuz" \
    -initrd "$VM_DIR/initramfs.cpio.gz" \
    -append "$APPEND" \
    -nographic \
    -nodefaults \
    -serial stdio \
    -no-reboot \
    -fsdev "local,id=fsdev0,path=$PROJECT_DIR,security_model=none" \
    -device "virtio-9p-pci,fsdev=fsdev0,mount_tag=workspace" \
    -netdev "user,id=net0" \
    -device "virtio-net-pci,netdev=net0"

if [[ $TEST_MODE -eq 1 ]]; then
    if [[ -f "$PROJECT_DIR/target/.vm_test_status" ]]; then
        STATUS=$(cat "$PROJECT_DIR/target/.vm_test_status" | tr -d '[:space:]')
        exit "${STATUS:-1}"
    else
        echo "Error: VM exited without writing test status."
        exit 1
    fi
elif [[ -n "$CMD_MODE" ]]; then
    if [[ -f "$PROJECT_DIR/target/.vm_cmd_status" ]]; then
        STATUS=$(cat "$PROJECT_DIR/target/.vm_cmd_status" | tr -d '[:space:]')
        exit "${STATUS:-1}"
    fi
fi
