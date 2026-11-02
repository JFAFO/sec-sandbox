"""T5-07 内核黑盒：seccomp 过滤器装载（仅 VM/Linux 原生）。"""

from __future__ import annotations

import os
import subprocess

import pytest

from sec_sandbox.sandbox.seccomp import generate_bpf, write_memfd

pytestmark = pytest.mark.kernel


def test_seccomp_filter_is_loaded():
    bpf = generate_bpf(("ptrace", "mount"))
    fd = write_memfd(bpf)
    try:
        proc = subprocess.run(
            [
                "bwrap",
                "--ro-bind", "/", "/",
                "--dev", "/dev",
                "--proc", "/proc",
                "--seccomp", str(fd),
                "/bin/sh", "-c", "grep '^Seccomp' /proc/self/status",
            ],
            capture_output=True,
            text=True,
            timeout=30,
            pass_fds=(fd,),
        )
    finally:
        os.close(fd)

    assert proc.returncode == 0
    assert "Seccomp:" in proc.stdout
    assert "Seccomp:\t2" in proc.stdout or "Seccomp: 2" in proc.stdout
