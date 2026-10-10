# SPDX-License-Identifier: BSD-3-Clause
import os
import subprocess
from pathlib import Path

import pytest

from harness import Kmodleak

TESTS_DIR = Path(__file__).resolve().parent
MODULES_DIR = TESTS_DIR / "modules"
DEFAULT_BINARY = TESTS_DIR.parent / "src" / "kmodleak"


def pytest_addoption(parser):
    parser.addoption("--kmodleak", default=os.environ.get("KMODLEAK", str(DEFAULT_BINARY)),
                     help="path to the kmodleak binary to test")


def pytest_sessionstart(session):
    if os.geteuid() != 0:
        pytest.exit("the tests load modules and BPF programs and must run as root, "
                    "e.g. sudo python3 -m pytest tests", returncode=2)


def run_as_invoker(args, **kwargs):
    """Run a command as the user who invoked sudo, so that build products in
    the source tree are not owned by root."""
    if "SUDO_UID" in os.environ:
        kwargs.setdefault("user", int(os.environ["SUDO_UID"]))
        kwargs.setdefault("group", int(os.environ["SUDO_GID"]))
    proc = subprocess.run(args, capture_output=True, text=True, **kwargs)
    if proc.returncode != 0:
        pytest.exit(f"{' '.join(args)} failed:\n{proc.stdout}{proc.stderr}", returncode=2)
    return proc


@pytest.fixture(scope="session")
def kmodleak_bin(request):
    binary = Path(request.config.getoption("--kmodleak"))
    if not binary.exists():
        pytest.exit(f"{binary} does not exist; build it with make -C src first", returncode=2)
    return str(binary)


class Modules:
    def __init__(self, directory):
        self.dir = directory

    def ko(self, name):
        path = self.dir / f"{name}.ko"
        assert path.exists(), f"{path} was not built"
        return path


@pytest.fixture(scope="session")
def modules():
    """The sample modules, built against the running kernel."""
    run_as_invoker(["make", "-C", str(MODULES_DIR)])
    return Modules(MODULES_DIR)


@pytest.fixture
def kmodleak(kmodleak_bin, request):
    """Factory for a traced kmodleak run: kmodleak("module", "-P") starts
    kmodleak and returns once it is tracing, or immediately with wait=False.
    Everything started is stopped, and any module it loaded unloaded, when
    the test ends."""
    started = []
    request.node.kmodleak_runs = started

    def start(module, *flags, timeout=30, wait=True):
        k = Kmodleak(kmodleak_bin, module, flags, timeout=timeout)
        started.append(k)
        if wait:
            k.wait_tracing()
        return k

    yield start

    for k in started:
        k.cleanup()


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    report = outcome.get_result()
    if report.when == "call" and report.failed:
        for i, k in enumerate(getattr(item, "kmodleak_runs", [])):
            report.sections.append((f"kmodleak output (run {i + 1})", k.output))
        dmesg = subprocess.run(["dmesg", "-T"], capture_output=True, text=True, check=False).stdout
        report.sections.append(("dmesg (tail)", "\n".join(dmesg.splitlines()[-30:])))
