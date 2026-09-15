#!/usr/bin/env bash
set -uo pipefail

cd /workspace

TEST_LIST_FILE="/workspace/target/.test_executables"
TESTS=()

if [[ -f "$TEST_LIST_FILE" ]]; then
    while IFS= read -r line; do
        [[ -n "$line" && -x "$line" ]] && TESTS+=("$line")
    done < "$TEST_LIST_FILE"
fi

if [[ ${#TESTS[@]} -eq 0 ]]; then
    # Fallback auto-discovery
    DEPS_DIR="/workspace/target/x86_64-unknown-linux-musl/debug/deps"
    for name in echo_test cat_test date_test fork_test futex_test networking networking_sandbox sqlite_test deterministic_test ptrace; do
        bin=$(find "$DEPS_DIR" -maxdepth 1 -type f -name "${name}-*" ! -name "*.*" -perm -111 2>/dev/null | head -n 1)
        if [[ -n "$bin" && -x "$bin" ]]; then
            TESTS+=("$bin")
        fi
    done
fi

if [[ ${#TESTS[@]} -eq 0 ]]; then
    echo "No test executables found to run!"
    exit 1
fi

TOTAL=${#TESTS[@]}
PASSED=0
FAILED=0
FAILED_NAMES=()

echo "Discovered $TOTAL test executable(s) to run."
echo "------------------------------------------------------------"

for test_bin in "${TESTS[@]}"; do
    test_name=$(basename "$test_bin")
    # Clean test name for display (strip hash)
    display_name=$(echo "$test_name" | sed 's/-[0-9a-f]\{16\}$//')
    
    echo -n "Running $display_name ... "
    
    # Run test and capture output
    set +e
    output=$("$test_bin" 2>&1)
    status=$?
    set -e
    
    if [[ $status -eq 0 ]]; then
        echo "PASS"
        PASSED=$((PASSED + 1))
    else
        echo "FAIL (exit $status)"
        echo "----------------- Output for $display_name -----------------"
        echo "$output"
        echo "------------------------------------------------------------"
        FAILED=$((FAILED + 1))
        FAILED_NAMES+=("$display_name")
    fi
done

echo "------------------------------------------------------------"
echo "Test Results: $PASSED passed, $FAILED failed out of $TOTAL total."

if [[ $FAILED -gt 0 ]]; then
    echo "Failed tests: ${FAILED_NAMES[*]}"
    exit 1
else
    echo "All tests passed successfully!"
    exit 0
fi
