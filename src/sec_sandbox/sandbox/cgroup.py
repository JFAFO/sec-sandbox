"""cgroup 资源限制：``systemd-run --user`` 后端与手工 cgroup 后端（§4.6）。

bwrap 本身没有资源参数；fork/内存/CPU 炸弹由 cgroup v2 拦截。
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass, replace
from decimal import Decimal, InvalidOperation
from pathlib import Path

from ..contracts import LaunchPlan
from ..policy.models import ResourceLimits
from ..util import logging as internal_log


class CgroupError(Exception):
    """cgroup 初始化失败或配额格式非法。"""


@dataclass(frozen=True)
class CgroupLimits:
    memory_max: str
    pids_max: int
    cpu_quota: str

    @classmethod
    def from_resource_limits(cls, limits: ResourceLimits) -> CgroupLimits:
        return cls(
            memory_max=limits.memory_max,
            pids_max=limits.pids_max,
            cpu_quota=limits.cpu_quota,
        )

    def memory_bytes(self) -> int:
        return _memory_bytes(self.memory_max)

    def cpu_max(self) -> str:
        return _cpu_max(self.cpu_quota)


def systemd_run_argv(
    limits: CgroupLimits,
    argv: tuple[str, ...],
    *,
    binary: str = "systemd-run",
) -> tuple[str, ...]:
    """把 argv 包进 ``systemd-run --user --scope``。"""
    _validate(limits)
    return (
        binary,
        "--user",
        "--scope",
        "--collect",
        "-p",
        f"MemoryMax={limits.memory_max}",
        "-p",
        f"TasksMax={limits.pids_max}",
        "-p",
        f"CPUQuota={limits.cpu_quota}",
        "--",
        *argv,
    )


def build_cgroup(
    plan: LaunchPlan,
    limits: ResourceLimits,
    *,
    binary: str | None = None,
) -> LaunchPlan:
    """优先使用 systemd-run；不可用时原样返回（由调用方记录可读提示）。"""
    systemd_run = binary if binary is not None else shutil.which("systemd-run")
    if not systemd_run:
        internal_log.warning("systemd-run 不可用：本次调用不启用 cgroup 资源限制")
        return plan

    cgroup_limits = CgroupLimits.from_resource_limits(limits)
    return replace(plan, argv=systemd_run_argv(cgroup_limits, plan.argv, binary=systemd_run))


class ManualCgroup:
    """手工 cgroup v2 后端；用于 systemd 委托不可用的环境。"""

    def __init__(self, base: Path, name: str) -> None:
        self.path = base / name

    def create(self, limits: CgroupLimits) -> Path:
        _validate(limits)
        try:
            self.path.mkdir(parents=True, exist_ok=False)
            (self.path / "memory.max").write_text(
                str(limits.memory_bytes()), encoding="utf-8"
            )
            (self.path / "pids.max").write_text(
                str(limits.pids_max), encoding="utf-8"
            )
            (self.path / "cpu.max").write_text(limits.cpu_max(), encoding="utf-8")
        except OSError as exc:
            raise CgroupError(f"无法创建 cgroup：{self.path}") from exc
        return self.path

    def attach(self, pid: int) -> None:
        try:
            (self.path / "cgroup.procs").write_text(str(pid), encoding="utf-8")
        except OSError as exc:
            raise CgroupError(f"无法把 pid {pid} 加入 cgroup") from exc

    def cleanup(self) -> None:
        try:
            self.path.rmdir()
            return
        except OSError:
            pass
        # 普通文件系统模拟目录：先清空再删（真实 cgroup 的控制文件删不掉，忽略）
        try:
            for child in self.path.iterdir():
                child.unlink(missing_ok=True)
            self.path.rmdir()
        except OSError:
            pass


def _validate(limits: CgroupLimits) -> None:
    if limits.pids_max <= 0:
        raise CgroupError("pids_max 必须为正整数")
    _memory_bytes(limits.memory_max)
    _cpu_max(limits.cpu_quota)


def _memory_bytes(text: str) -> int:
    raw = text.strip().upper()
    multiplier = 1
    if raw.endswith("K"):
        multiplier, raw = 1024, raw[:-1]
    elif raw.endswith("M"):
        multiplier, raw = 1024 * 1024, raw[:-1]
    elif raw.endswith("G"):
        multiplier, raw = 1024 * 1024 * 1024, raw[:-1]
    try:
        value = int(raw)
    except ValueError as exc:
        raise CgroupError(f"memory_max 格式非法：{text!r}") from exc
    if value <= 0:
        raise CgroupError(f"memory_max 必须为正数：{text!r}")
    return value * multiplier


def _cpu_max(text: str) -> str:
    raw = text.strip()
    if not raw.endswith("%"):
        raise CgroupError(f"cpu_quota 格式非法：{text!r}")
    try:
        percent = Decimal(raw[:-1])
    except InvalidOperation as exc:
        raise CgroupError(f"cpu_quota 格式非法：{text!r}") from exc
    if percent <= 0:
        raise CgroupError(f"cpu_quota 必须为正数：{text!r}")
    quota_us = int(percent * 1000)
    return f"{quota_us} 100000"
