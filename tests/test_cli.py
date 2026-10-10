# SPDX-License-Identifier: BSD-3-Clause
"""Command line handling and refusals."""

import subprocess


def run(kmodleak_bin, *args):
    return subprocess.run([kmodleak_bin, *args], capture_output=True, text=True)


def test_missing_module_name(kmodleak_bin):
    p = run(kmodleak_bin)
    assert p.returncode == 1
    assert "missing module name" in p.stderr


def test_module_name_too_long(kmodleak_bin):
    p = run(kmodleak_bin, "a" * 56)
    assert p.returncode != 0
    assert "too long" in p.stderr


def test_extra_positional_argument(kmodleak_bin):
    p = run(kmodleak_bin, "leak", "extra")
    assert p.returncode != 0
    assert "Unrecognized positional argument" in p.stderr
