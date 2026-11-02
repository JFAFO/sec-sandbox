"""T5-07 内核黑盒：嵌套 bwrap 与非特权 user namespace（仅 VM/Linux 原生）。"""

from __future__ import annotations

import subprocess

import pytest

pytestmark = pytest.mark.kernel


def test_nested_bwrap_runs():
    proc = subprocess.run(
        [
            "bwrap",
            "--ro-bind", "/", "/",
            "--dev", "/dev",
            "--proc", "/proc",
            "--unshare-user",
            "--unshare-pid",
            "bwrap", "--version",
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert proc.returncode == 0
    assert "bubblewrap" in proc.stdout.lower() or "bwrap" in proc.stdout.lower()


def test_unprivileged_userns_allowed():
    proc = subprocess.run(
        ["bwrap", "--unshare-user", "--ro-bind", "/", "/", "true"],
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert proc.returncode == 0
