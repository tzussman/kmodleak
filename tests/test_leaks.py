# SPDX-License-Identifier: BSD-3-Clause
"""Leak detection on the sample modules."""


def test_leak(kmodleak, modules):
    k = kmodleak("leak")
    k.insmod(modules.ko("leak"))
    k.rmmod()
    r = k.wait_exit()

    assert r.returncode == 0 and r.done
    assert r.loaded and r.unloaded
    assert len(r.stacks) == 1
    stack = r.stacks[0]
    assert stack.count == 1
    assert len(stack.allocations) == 1
    assert stack.allocations[0][1] >= 100
    # leak_init is __init, so this checks in-kernel init symbol resolution
    assert "leak_init" in stack.symbols()
    assert r.no_stack_count == 0


def test_noleak(kmodleak, modules):
    k = kmodleak("noleak")
    k.insmod(modules.ko("noleak"))
    k.rmmod()
    r = k.wait_exit()

    assert r.returncode == 0 and r.done
    assert r.loaded and r.unloaded
    assert r.outstanding == 0
