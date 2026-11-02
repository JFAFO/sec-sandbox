"""T5-07 内核黑盒：cgroup v2 配额（仅 VM/Linux 原生）。"""

from __future__ import annotations

import shutil
import subprocess

import pytest

pytestmark = pytest.mark.kernel


_CGROUP_PATH = (
    "p=$(sed -n 's/^0:://p' /proc/self/cgroup); "
    "test -n \"$p\" || p=$(cat /proc/self/cgroup | cut -d: -f3); "
    "echo \"/sys/fs/cgroup${p}\""
)


@pytest.mark.skipif(shutil.which("systemd-run") is None, reason="systemd-run 不可用")
def test_memory_max_applied():
    proc = subprocess.run(
        [
            "systemd-run",
            "--user",
            "--scope",
            "--collect",
            "-p", "MemoryMax=64M",
            "--",
            "sh", "-c", f"cat $({_CGROUP_PATH})/memory.max",
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert proc.returncode == 0
    assert "67108864" in proc.stdout


@pytest.mark.skipif(shutil.which("systemd-run") is None, reason="systemd-run 不可用")
def test_pids_max_applied():
    proc = subprocess.run(
        [
            "systemd-run",
            "--user",
            "--scope",
            "--collect",
            "-p", "TasksMax=32",
            "--",
            "sh", "-c", f"cat $({_CGROUP_PATH})/pids.max",
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert proc.returncode == 0
    assert "32" in proc.stdout
