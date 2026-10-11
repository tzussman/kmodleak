# SPDX-License-Identifier: BSD-3-Clause
"""Leak detection on the sample modules."""

import errno
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


def test_slab_pages_are_not_attributed(kmodleak, modules):
    """Pages the slab allocator takes to serve the module's kmallocs are the
    slab's, not the module's: enough objects to need new slabs must still
    report only the object stack."""
    r = trace(kmodleak, modules, "leak_multi", params=("nr_allocs=20000",))

    stacks = [s for s in r.stacks if "leak_multi_init" in s.symbols()]
    assert len(stacks) == 1
    assert stacks[0].count == 20000


def test_large_kmalloc_counted_once(kmodleak, modules):
    """A kmalloc too large for a slab cache is served by the page allocator
    and traced as an object; its pages must not be reported as well."""
    r = trace(kmodleak, modules, "leak_large")

    stacks = [s for s in r.stacks if "leak_large_init" in s.symbols()]
    assert len(stacks) == 1
    assert stacks[0].count == 1
    assert stacks[0].size >= 256 * 1024


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


def test_failed_page_allocation_is_ignored(kmodleak, modules):
    """The mm_page_alloc tracepoint fires with a pfn of -1 when the allocation
    fails; that must not be recorded as an allocation that is never freed."""
    r = trace(kmodleak, modules, "noleak_pages_fail")
    assert r.outstanding == 0


VMALLOC_TRACEPOINT = Path("/sys/kernel/tracing/events/vmalloc/alloc_vmap_area")

needs_vmalloc_tracepoints = pytest.mark.skipif(
    not VMALLOC_TRACEPOINT.exists(), reason="vmalloc tracepoints need Linux 6.2")


@needs_vmalloc_tracepoints
def test_vmalloc_leak(kmodleak, modules):
    """A vmalloc() area is tracked by its address and counted once, without
    the pages behind it. Its bookkeeping (vm_struct, vmap_area and the pages
    array) leaks with it and is reported as well."""
    r = trace(kmodleak, modules, "leak_vmalloc")

    areas = [s for s in r.stacks if s.size >= 1 << 20]
    assert len(areas) == 1
    assert areas[0].count == 1
    assert areas[0].is_direct_from("leak_vmalloc_init")
    # no stack of per-page allocations behind the area
    assert all(s.count == 1 for s in r.stacks if "leak_vmalloc_init" in s.symbols())


@needs_vmalloc_tracepoints
def test_vmalloc_freed(kmodleak, modules):
    r = trace(kmodleak, modules, "noleak_vmalloc")
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
    """An allocation after init, from a parameter callback in core text, is
    attributed to the module and its symbol resolved even though the module
    is unloaded again immediately."""
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


def test_kmem_cache_alloc_outstanding(kmodleak, modules):
    """An object from a private slab cache shows as outstanding while the
    module is loaded, reported on SIGINT."""
    k = kmodleak("cache_alloc")
    k.insmod(modules.ko("cache_alloc"))
    k.signal(signal.SIGINT)
    r = k.wait_exit()
    k.rmmod()

    assert r.returncode == 0 and r.done
    assert r.loaded and not r.unloaded
    # kmem_cache_create() allocates sysfs nodes from the module's init too;
    # only the object allocated directly by the module is of interest
    stacks = r.direct_stacks("cache_alloc_init")
    assert len(stacks) == 1
    stack = stacks[0]
    assert stack.count == 1
    assert stack.size >= 64
    assert any("kmem_cache_alloc" in s for s in stack.symbols())


def test_other_modules_are_ignored(kmodleak, modules):
    """Allocations by a module other than the traced one are not reported,
    even while the traced module is loaded."""
    k = kmodleak("noleak")
    k.insmod(modules.ko("noleak"))
    k.insmod(modules.ko("leak"))
    k.rmmod("noleak")
    r = k.wait_exit()
    k.rmmod("leak")

    assert r.returncode == 0 and r.done
    assert r.loaded and r.unloaded
    assert r.outstanding == 0


PERF_EVENT_MAX_STACK = Path("/proc/sys/kernel/perf_event_max_stack")


def write_perf_event_max_stack(value, retries=40):
    """The kernel refuses the change while anything holds a callchain buffer,
    which includes a stack map that is still being freed after kmodleak
    exited, so retry for a few seconds."""
    for attempt in range(retries):
        try:
            PERF_EVENT_MAX_STACK.write_text(str(value))
            return
        except OSError as e:
            if e.errno != errno.EBUSY or attempt == retries - 1:
                raise
            time.sleep(0.1)


@pytest.fixture
def perf_event_max_stack():
    """Set kernel.perf_event_max_stack for a test and restore it afterwards."""
    saved = PERF_EVENT_MAX_STACK.read_text()

    def set_depth(depth):
        try:
            write_perf_event_max_stack(depth)
        except OSError as e:
            pytest.skip(f"cannot set kernel.perf_event_max_stack: {e}")

    yield set_depth
    write_perf_event_max_stack(saved)


@pytest.mark.parametrize("depth", [16, 4095])
def test_stack_depth_follows_sysctl(kmodleak, modules, perf_event_max_stack, depth):
    """The stack depth is sized from kernel.perf_event_max_stack, up to the
    most the per-CPU stack buffer can hold."""
    perf_event_max_stack(depth)
    r = trace(kmodleak, modules, "leak")

    stacks = r.direct_stacks("leak_init")
    assert len(stacks) == 1
    assert max(f.index for f in stacks[0].frames) < depth


def test_truncated_stacks_are_reported(kmodleak, modules, perf_event_max_stack):
    """With too few frames to reach the module, the leak goes unattributed
    and the report says that stack traces were truncated."""
    # Frame 0 is always inside the allocator or tracepoint code, never the module
    perf_event_max_stack(1)
    r = trace(kmodleak, modules, "leak")

    assert r.direct_stacks("leak_init") == []
    assert r.truncated_stacks > 0


@pytest.mark.parametrize("sig", [signal.SIGINT, signal.SIGTERM])
def test_signal_before_unload_reports(kmodleak, modules, sig):
    k = kmodleak("leak")
    k.insmod(modules.ko("leak"))
    k.signal(sig)
    r = k.wait_exit()
    k.rmmod()

    assert r.returncode == 0 and r.done
    assert r.loaded and not r.unloaded
    stacks = r.direct_stacks("leak_init")
    assert len(stacks) == 1
    assert stacks[0].count == 1


def test_leak_from_failing_init(kmodleak, modules):
    """A module whose init fails is freed from do_init_module() without an
    exit function; the leak is still reported and its init symbol resolved."""
    k = kmodleak("leak_initfail")
    with pytest.raises(subprocess.CalledProcessError):
        k.insmod(modules.ko("leak_initfail"))
    r = k.wait_exit()

    assert r.returncode == 0 and r.done
    assert r.loaded and r.unloaded
    stacks = r.direct_stacks("leak_initfail_init")
    assert len(stacks) == 1
    assert stacks[0].count == 1


LONG_NAME = "leak_with_the_longest_module_name_the_kernel_permits_xx"


def test_longest_module_name(kmodleak, modules):
    """A MODULE_NAME_LEN - 1 character name is matched in full."""
    assert len(LONG_NAME) == 55
    r = trace(kmodleak, modules, LONG_NAME)

    assert len(r.direct_stacks("longname_init")) == 1


def test_dash_in_module_name(kmodleak, modules):
    """insmod leak-dash.ko loads a module named leak_dash, and the name may
    be given either way."""
    k = kmodleak("leak-dash")
    k.insmod(modules.ko("leak-dash"))
    k.rmmod("leak_dash")
    r = k.wait_exit()

    assert r.loaded and r.unloaded
    assert "module 'leak_dash' loaded" in r.output
    assert len(r.direct_stacks("leak_dash_init")) == 1


@pytest.mark.xfail(reason="kfree_rcu() frees land after module_free and bypass the kfree tracepoint")
def test_kfree_rcu_in_exit(kmodleak, modules):
    r = trace(kmodleak, modules, "noleak_rcu")
    assert r.outstanding == 0
