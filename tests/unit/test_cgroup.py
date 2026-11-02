"""T5-04 cgroup 后端测试。"""

from __future__ import annotations

from pathlib import Path

import pytest

from sec_sandbox.contracts import LaunchPlan
from sec_sandbox.policy.models import ResourceLimits
from sec_sandbox.sandbox.cgroup import (
    CgroupError,
    CgroupLimits,
    ManualCgroup,
    build_cgroup,
    systemd_run_argv,
)


def limits() -> ResourceLimits:
    return ResourceLimits(memory_max="512M", pids_max=64, cpu_quota="50%")


def test_systemd_run_argv():
    argv = systemd_run_argv(
        CgroupLimits.from_resource_limits(limits()),
        ("bwrap", "--ro-bind", "/", "/"),
    )

    assert argv == (
        "systemd-run",
        "--user",
        "--scope",
        "--collect",
        "-p",
        "MemoryMax=512M",
        "-p",
        "TasksMax=64",
        "-p",
        "CPUQuota=50%",
        "--",
        "bwrap",
        "--ro-bind",
        "/",
        "/",
    )


def test_build_cgroup_wraps_plan():
    plan = LaunchPlan(argv=("bwrap",))

    wrapped = build_cgroup(plan, limits(), binary="/usr/bin/systemd-run")

    assert wrapped.argv[0] == "/usr/bin/systemd-run"
    assert wrapped.argv[-1] == "bwrap"


def test_build_cgroup_without_systemd_returns_original(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: None)
    plan = LaunchPlan(argv=("bwrap",))

    assert build_cgroup(plan, limits()) is plan


def test_manual_cgroup_files(tmp_path):
    cgroup = ManualCgroup(tmp_path, "secsand-test")
    cgroup_limits = CgroupLimits.from_resource_limits(limits())

    path = cgroup.create(cgroup_limits)
    cgroup.attach(1234)

    assert (path / "memory.max").read_text() == str(512 * 1024 * 1024)
    assert (path / "pids.max").read_text() == "64"
    assert (path / "cpu.max").read_text() == "50000 100000"
    assert (path / "cgroup.procs").read_text() == "1234"

    cgroup.cleanup()
    assert not path.exists()


def test_invalid_cpu_quota():
    with pytest.raises(CgroupError):
        systemd_run_argv(
            CgroupLimits(memory_max="512M", pids_max=64, cpu_quota="50"),
            ("bwrap",),
        )


def test_invalid_memory():
    with pytest.raises(CgroupError):
        systemd_run_argv(
            CgroupLimits(memory_max="abc", pids_max=64, cpu_quota="50%"),
            ("bwrap",),
        )


def test_zero_pids():
    with pytest.raises(CgroupError):
        systemd_run_argv(
            CgroupLimits(memory_max="512M", pids_max=0, cpu_quota="50%"),
            ("bwrap",),
        )
