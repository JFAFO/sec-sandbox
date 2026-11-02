"""T5-07 内核黑盒：no_new_privs（仅 VM/Linux 原生）。"""

from __future__ import annotations

import subprocess

import pytest

pytestmark = pytest.mark.kernel


def test_no_new_privs_set_inside_bwrap():
    proc = subprocess.run(
        [
            "bwrap",
            "--ro-bind", "/", "/",
            "--dev", "/dev",
            "--proc", "/proc",
            "/bin/sh", "-c", "grep '^NoNewPrivs' /proc/self/status",
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert proc.returncode == 0
    assert "NoNewPrivs:\t1" in proc.stdout or "NoNewPrivs: 1" in proc.stdout
