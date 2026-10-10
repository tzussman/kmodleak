#!/bin/bash

# Test script that runs kmodleak, loads module, unloads module, and checks output

# Wait up to 10 seconds for the given process to exit
wait_for_exit() {
    for _ in $(seq 1 100); do
        if ! kill -0 "$1" 2> /dev/null; then
            return 0
        fi
        sleep 0.1
    done
    return 1
}

stop_kmodleak() {
    if kill -0 "$1" 2> /dev/null; then
        sudo kill "$1"
    fi
    wait "$1" 2> /dev/null
}

run_test() {
    module=$1
    expected_output=$2
    output="out_$module"

    echo "Running kmodleak on module '$module'..."
    sudo ../src/kmodleak "$module" > "$output" &
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
        echo "kmodleak did not start tracing:"
        cat "$output"
        stop_kmodleak $kmodleak_pid
        rm "$output"
        return 1
    fi

    echo "Loading module..."
    if ! sudo insmod "$module.ko"; then
        echo "Failed to load module $module"
        stop_kmodleak $kmodleak_pid
        rm "$output"
        return 1
    fi

    echo "Unloading module..."
    if ! sudo rmmod "$module"; then
        echo "Failed to unload module $module"
        stop_kmodleak $kmodleak_pid
        rm "$output"
        return 1
    fi

    # kmodleak exits on its own once the module is unloaded.
    if ! wait_for_exit $kmodleak_pid; then
        echo "kmodleak did not exit after module unload"
        stop_kmodleak $kmodleak_pid
        rm "$output"
        return 1
    fi
    wait $kmodleak_pid

    echo "Checking output..."
    if ! grep -q "$expected_output" "$output"; then
        echo "Output does not contain expected output:"
        cat "$output"
        rm "$output"
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
