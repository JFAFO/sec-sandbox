"""T5-07 内核黑盒：文件视图、写白名单与 pid namespace（仅 VM/Linux 原生）。"""

from __future__ import annotations

import subprocess

import pytest

pytestmark = pytest.mark.kernel


def bwrap(*args: str, **kwargs):
    return subprocess.run(
        ["bwrap", *args],
        capture_output=True,
        text=True,
        timeout=30,
        **kwargs,
    )


def test_root_is_readonly(tmp_path):
    target = "/etc/__secsand_readonly_test__"
    proc = bwrap(
        "--ro-bind", "/", "/",
        "--dev", "/dev",
        "--proc", "/proc",
        "--tmpfs", "/tmp",
        "/bin/sh", "-c", f"touch {target}",
    )

    assert proc.returncode != 0


def test_workspace_is_writable(tmp_path):
    target = tmp_path / "ok"
    proc = bwrap(
        "--ro-bind", "/", "/",
        "--dev", "/dev",
        "--proc", "/proc",
        "--tmpfs", "/tmp",
        "--bind", str(tmp_path), str(tmp_path),
        "/bin/sh", "-c", f"touch {target}",
    )

    assert proc.returncode == 0
    assert target.exists()


def test_mask_hides_contents(tmp_path):
    secret = tmp_path / "secret"
    secret.mkdir()
    (secret / "token").write_text("x", encoding="utf-8")

    proc = bwrap(
        "--ro-bind", "/", "/",
        "--tmpfs", str(secret),
        "--dev", "/dev",
        "--proc", "/proc",
        "/bin/sh", "-c", f"ls -A {secret}",
    )

    assert proc.returncode == 0
    assert proc.stdout.strip() == ""


def test_pid_namespace_isolation():
    proc = bwrap(
        "--ro-bind", "/", "/",
        "--dev", "/dev",
        "--unshare-pid",
        "--proc", "/proc",
        "/bin/sh", "-c", "cat /proc/1/comm",
    )

    assert proc.returncode == 0
    # bwrap 可能作为 pid 1 保留，重点是看不到宿主 init/systemd
    assert proc.stdout.strip() not in {"systemd", "init"}
