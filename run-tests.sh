#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== Building Linux test binaries on host ==="
mkdir -p "$SCRIPT_DIR/target"

TEST_BINS=()
while IFS= read -r line; do
    if [[ "$line" =~ \"executable\":\"([^\"]+)\" ]]; then
        exe="${BASH_REMATCH[1]}"
        if [[ "$exe" =~ /deps/ ]]; then
            TEST_BINS+=("$exe")
        fi
    fi
done < <(cargo test --no-run --message-format=json)

printf "%s\n" "${TEST_BINS[@]}" > "$SCRIPT_DIR/target/.test_executables"

echo "Built ${#TEST_BINS[@]} test executable(s)."
echo "=== Booting QEMU VM to run test suite ==="

exec "$SCRIPT_DIR/vm/run.sh" --test
