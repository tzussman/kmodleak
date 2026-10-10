#!/bin/bash

# Test script that runs kmodleak, loads module, unloads module, and checks output

# Seconds to wait for kmodleak to exit on its own after the module is unloaded
KMODLEAK_TIMEOUT=30

# Print why a test failed along with kmodleak's output, and stop kmodleak if it
# is still running
fail() {
    echo "$1"
    echo "--- kmodleak output:"
    cat "$output"
    echo "---"
    sudo kill "$kmodleak_pid" 2> /dev/null
    wait "$kmodleak_pid" 2> /dev/null
    rm -f "$output"
    return 1
}

run_test() {
    module=$1
    expected_output=$2
    output="out_$module"

    echo "Running kmodleak on module '$module'..."
    sudo timeout $KMODLEAK_TIMEOUT ../src/kmodleak "$module" > "$output" 2>&1 &
    kmodleak_pid=$!

    echo "kmodleak running on PID $kmodleak_pid"

    # Wait for kmodleak to attach its BPF programs before loading the module.
    for _ in $(seq 1 100); do
        if grep -q "Tracing module memory allocs" "$output"; then
            break
        fi
        sleep 0.1
    done

    if ! grep -q "Tracing module memory allocs" "$output"; then
        fail "kmodleak did not start tracing"
        return 1
    fi

    echo "Loading module..."
    if ! sudo insmod "$module.ko"; then
        fail "Failed to load module $module"
        return 1
    fi

    echo "Unloading module..."
    if ! sudo rmmod "$module"; then
        fail "Failed to unload module $module"
        return 1
    fi

    # kmodleak exits on its own once the module is unloaded; timeout kills it
    # with SIGTERM otherwise, which makes it print what it has.
    wait "$kmodleak_pid"
    status=$?
    if [ $status -eq 124 ]; then
        fail "kmodleak did not exit within $KMODLEAK_TIMEOUT seconds of module unload"
        return 1
    elif [ $status -ne 0 ]; then
        fail "kmodleak exited with status $status"
        return 1
    fi

    echo "Checking output..."
    if ! grep -q "$expected_output" "$output"; then
        fail "Output does not contain '$expected_output'"
        return 1
    fi

    echo "Test '$module' passed."
    echo
    rm "$output"
}

# Run tests

test_failed=0

if ! run_test "leak" "1 stacks with outstanding allocations"; then
    test_failed=1
fi

if ! run_test "noleak" "0 stacks with outstanding allocations"; then
    test_failed=1
fi

exit $test_failed
