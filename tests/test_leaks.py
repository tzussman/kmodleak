# SPDX-License-Identifier: BSD-3-Clause
"""Leak detection on the sample modules."""

import os
import signal
import subprocess
import time
from pathlib import Path

import pytest

PAGE_SIZE = os.sysconf("SC_PAGE_SIZE")


def trace(kmodleak, modules, name, *flags, between=None, params=()):
    """Load and unload a module under kmodleak, running between() while it
    is loaded, and return the report."""
    k = kmodleak(name, *flags)
    k.insmod(modules.ko(name), *params)
    if between:
        between()
    k.rmmod()
    r = k.wait_exit()
    assert r.returncode == 0 and r.done
    assert r.loaded and r.unloaded
    return r


def test_leak(kmodleak, modules):
    r = trace(kmodleak, modules, "leak")

    # leak_init is __init, so this checks in-kernel init symbol resolution
    stacks = r.direct_stacks("leak_init")
    assert len(stacks) == 1
    stack = stacks[0]
    assert stack.count == 1
    assert len(stack.allocations) == 1
    assert stack.allocations[0][1] >= 100
    assert r.no_stack_count == 0


def test_noleak(kmodleak, modules):
    r = trace(kmodleak, modules, "noleak")
    assert r.outstanding == 0


def test_multiple_allocations_aggregate(kmodleak, modules):
    """Allocations from one call site are reported as one stack."""
    r = trace(kmodleak, modules, "leak_multi", params=("nr_allocs=10",))

    stacks = r.direct_stacks("leak_multi_init")
    assert len(stacks) == 1
    stack = stacks[0]
    assert stack.count == 10
    assert len(stack.allocations) == 10
    assert stack.size == sum(size for _, size in stack.allocations)
    assert stack.size >= 10 * 64


def test_page_allocation_leak(kmodleak, modules):
    """Page allocations are tracked by pfn and sized by order."""
    r = trace(kmodleak, modules, "leak_pages")

    stacks = r.direct_stacks("leak_pages_init")
    assert len(stacks) == 1
    stack = stacks[0]
    assert stack.count == 1
    assert stack.size == 2 * PAGE_SIZE


def test_page_allocation_freed(kmodleak, modules):
    r = trace(kmodleak, modules, "noleak_pages")
    assert r.outstanding == 0


def test_percpu_leak_with_flag(kmodleak, modules):
    r = trace(kmodleak, modules, "leak_percpu", "-P")

    stacks = r.direct_stacks("leak_percpu_init")
    assert len(stacks) == 1
    stack = stacks[0]
    assert stack.count == 1
    assert stack.size >= 4


def test_percpu_ignored_without_flag(kmodleak, modules):
    r = trace(kmodleak, modules, "leak_percpu")
    assert r.direct_stacks("leak_percpu_init") == []


def write_trigger():
    Path("/sys/module/leak_core/parameters/trigger").write_text("1")


def check_core_text_leak(r):
    stacks = r.direct_stacks("trigger_set")
    assert len(stacks) == 1
    stack = stacks[0]
    assert stack.count == 1
    assert "leak_core_init" not in stack.symbols()


def test_leak_from_core_text(kmodleak, modules):
    """An allocation after init, from a parameter callback in core text,
    is attributed to the module and resolved from kallsyms."""
    def between():
        # Give kmodleak time to snapshot kallsyms before the module is gone
        time.sleep(0.5)
        write_trigger()

    r = trace(kmodleak, modules, "leak_core", between=between)
    check_core_text_leak(r)


@pytest.mark.xfail(reason="core text symbols come from a kallsyms snapshot that races a fast unload")
def test_leak_from_core_text_fast_unload(kmodleak, modules):
    r = trace(kmodleak, modules, "leak_core", between=write_trigger)
    check_core_text_leak(r)


def test_leak_from_work_item(kmodleak, modules):
    """An allocation from a kworker is attributed via the module's frame."""
    r = trace(kmodleak, modules, "leak_work", between=lambda: time.sleep(0.5))

    stacks = r.direct_stacks("leak_work_fn")
    assert len(stacks) == 1
    assert stacks[0].count == 1


def test_free_from_other_context(kmodleak, modules):
    """A free from a different context than the allocation still matches."""
    r = trace(kmodleak, modules, "noleak_xctx", between=lambda: time.sleep(0.5))
    assert r.outstanding == 0
