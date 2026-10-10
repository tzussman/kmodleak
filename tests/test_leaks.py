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
