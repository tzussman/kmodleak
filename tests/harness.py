# SPDX-License-Identifier: BSD-3-Clause
"""Drive kmodleak against a kernel module and parse its report."""

import os
import re
import shutil
import signal
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path


def _sbin(name):
    return shutil.which(name) or f"/sbin/{name}"


INSMOD = _sbin("insmod")
RMMOD = _sbin("rmmod")


def module_name(ko):
    """Kernel module name for a .ko path: basename, dashes become underscores."""
    return Path(ko).stem.replace("-", "_")


def module_loaded(name):
    return Path("/sys/module", name, "initstate").exists()


@dataclass
class Frame:
    index: int
    addr: int
    symbol: str  # symbol name, or "<null sym>" when unresolved
    offset: int  # offset from symbol, 0 when unresolved


# Frames that belong to the allocator or tracepoint machinery rather than to
# a caller: anything between an allocation and the function that made it.
_ALLOCATOR = re.compile(r"alloc|free_pages|vm_area|vmap|^(__traceiter_|trace_|perf_trace_)")


@dataclass
class Stack:
    size: int  # total bytes outstanding from this stack
    count: int  # number of outstanding allocations
    allocations: list = field(default_factory=list)  # (addr, size)
    frames: list = field(default_factory=list)

    def symbols(self):
        return [f.symbol for f in self.frames]

    def is_direct_from(self, symbol):
        """Whether the allocation was made directly by the named function:
        it is on the stack and every frame above it is allocator internal.
        Allocations the kernel makes on a module's behalf, such as sysfs
        nodes created by kmem_cache_create(), have other frames in between.
        """
        syms = self.symbols()
        if symbol not in syms:
            return False
        return all(_ALLOCATOR.search(s) for s in syms[:syms.index(symbol)])


@dataclass
class Report:
    output: str
    returncode: int
    loaded: bool = False
    unloaded: bool = False
    stacks: list = field(default_factory=list)
    no_stack_bytes: int = 0
    no_stack_count: int = 0
    truncated_stacks: int = 0  # captures that hit the stack depth limit
    done: bool = False

    @property
    def outstanding(self):
        return sum(s.count for s in self.stacks) + self.no_stack_count

    def direct_stacks(self, symbol):
        """Stacks of allocations made directly by the named function."""
        return [s for s in self.stacks if s.is_direct_from(symbol)]


_RE = {
    "module": re.compile(r"^module '(.+)' (loaded|unloaded)$"),
    "stack": re.compile(r"^(\d+) bytes in (\d+) allocations from stack$"),
    "alloc": re.compile(r"^\s+addr = (0x[0-9a-f]+) size = (\d+)$"),
    "frame": re.compile(r"^\s+(\d+) \[<([0-9a-f]+)>\] (.+)$"),
    "nostack": re.compile(r"^(\d+) bytes in (\d+) allocations with no stack trace available$"),
    "truncated": re.compile(r"^warning: (\d+) stack traces hit the limit of (\d+) frames"),
    "symbol": re.compile(r"^(.+)\+0x([0-9a-f]+)$"),
}


def parse_report(output, returncode=0):
    report = Report(output=output, returncode=returncode)
    stack = None

    for line in output.splitlines():
        m = _RE["module"].match(line)
        if m:
            if m.group(2) == "loaded":
                report.loaded = True
            else:
                report.unloaded = True
            continue

        m = _RE["stack"].match(line)
        if m:
            stack = Stack(size=int(m.group(1)), count=int(m.group(2)))
            report.stacks.append(stack)
            continue

        m = _RE["alloc"].match(line)
        if m and stack is not None:
            stack.allocations.append((int(m.group(1), 16), int(m.group(2))))
            continue

        m = _RE["frame"].match(line)
        if m and stack is not None:
            sym = _RE["symbol"].match(m.group(3))
            if sym:
                frame = Frame(int(m.group(1)), int(m.group(2), 16), sym.group(1), int(sym.group(2), 16))
            else:
                frame = Frame(int(m.group(1)), int(m.group(2), 16), m.group(3), 0)
            stack.frames.append(frame)
            continue

        m = _RE["nostack"].match(line)
        if m:
            report.no_stack_bytes = int(m.group(1))
            report.no_stack_count = int(m.group(2))
            continue

        m = _RE["truncated"].match(line)
        if m:
            report.truncated_stacks = int(m.group(1))
            continue

        if line == "done":
            report.done = True

    return report


class KmodleakError(Exception):
    def __init__(self, message, output):
        super().__init__(f"{message}\n--- kmodleak output:\n{output}\n---")
        self.output = output


class Kmodleak:
    """A running kmodleak process tracing one module.

    Output is collected on a background thread so that it can be waited on
    with a timeout. Modules loaded through insmod() are remembered so that
    cleanup() can unload whatever a failing test left behind.
    """

    def __init__(self, binary, module, flags=(), timeout=30):
        self.module = module
        self.timeout = timeout
        self.lines = []
        self.loaded = []
        self.proc = subprocess.Popen(
            [binary, *flags, module],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        self._reader = threading.Thread(target=self._read, daemon=True)
        self._reader.start()

    def _read(self):
        for line in self.proc.stdout:
            self.lines.append(line.rstrip("\n"))

    @property
    def output(self):
        return "\n".join(self.lines)

    def wait_for(self, pattern, timeout=10):
        """Wait until a line matching the regex has been printed."""
        regex = re.compile(pattern)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if any(regex.search(line) for line in self.lines):
                return
            if self.proc.poll() is not None:
                break
            time.sleep(0.05)
        raise KmodleakError(f"kmodleak did not print a line matching {pattern!r}", self.output)

    def wait_tracing(self, timeout=10):
        self.wait_for(r"^Tracing module memory allocs", timeout)

    def insmod(self, ko, *params):
        subprocess.run([INSMOD, str(ko), *params], check=True)
        self.loaded.append(module_name(ko))

    def rmmod(self, name=None):
        name = name or self.module
        subprocess.run([RMMOD, name], check=True)
        if name in self.loaded:
            self.loaded.remove(name)

    def signal(self, sig=signal.SIGINT):
        self.proc.send_signal(sig)

    def wait_exit(self, timeout=None):
        """Wait for kmodleak to exit and return the parsed report.

        Raises KmodleakError if it has not exited within the timeout; it is
        terminated in that case so that its output is still available.
        """
        try:
            self.proc.wait(timeout or self.timeout)
        except subprocess.TimeoutExpired:
            self.terminate()
            raise KmodleakError(f"kmodleak did not exit within {timeout or self.timeout} seconds", self.output)
        self._reader.join(5)
        return parse_report(self.output, self.proc.returncode)

    def terminate(self):
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
        self._reader.join(5)

    def cleanup(self):
        self.terminate()
        for name in list(self.loaded):
            if module_loaded(name):
                subprocess.run([RMMOD, name], check=False)
        self.loaded.clear()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.cleanup()
