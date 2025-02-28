#!/bin/bash

# Test script that runs kmodleak, loads module, unloads module, and checks output

run_test() {
    module=$1
    expected_output=$2
    echo "Running kmodleak on module '$module'..."
    sudo ../src/kmodleak "$module" > "out_$module" &
    kmodleak_pid=$!

    echo "kmodleak running on PID $kmodleak_pid"

    # Sleep so that kmodleak has time to register the BPF programs before the
    # module is loaded.
    sleep 1

    echo "Loading module..."
    if ! sudo insmod "$module.ko"; then
        echo "Failed to load module $module"
        kill $kmodleak_pid
        return 1
    fi

    echo "Unloading module..."
    if ! sudo rmmod "$module"; then
        echo "Failed to unload module $module"
        kill $kmodleak_pid
        return 1
    fi

    sleep 1

    echo "Checking output..."
    if ! grep -q "$expected_output" "out_$module"; then
        echo "Output does not contain expected output"
        return 1
    fi

    echo "Test '$module' passed."
    echo
    rm "out_$module"
    wait $kmodleak_pid
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
