"""沙箱自检：四项核心能力 + bash 路径 + libseccomp + overlayfs（§4.6、T5-06）。"""

from __future__ import annotations

import shutil
import subprocess
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .seccomp import libseccomp_available


@dataclass(frozen=True)
class CheckResult:
    """单项自检结果。"""

    name: str
    ok: bool
    detail: str
    critical: bool = True


def run_selfcheck(
    *,
    which: Callable[[str], str | None] = shutil.which,
    run: Callable[..., Any] = subprocess.run,
    filesystems: str | None = None,
    libseccomp: bool | None = None,
) -> tuple[CheckResult, ...]:
    """执行全部检查；返回可直接渲染的结果列表。"""
    bwrap = which("bwrap")
    seccomp_ok = libseccomp if libseccomp is not None else libseccomp_available()
    results = [
        CheckResult("bubblewrap", bool(bwrap), bwrap or "未找到 bwrap"),
        _check_nested(bwrap, run),
        _check_cgroup(which, run),
        _check_userns(bwrap, run),
        _check_bash(which),
        CheckResult(
            "libseccomp",
            seccomp_ok,
            "可用" if seccomp_ok else "不可用，将回退静态表",
        ),
        _check_overlayfs(filesystems),
    ]
    return tuple(results)


def format_report(results: Sequence[CheckResult]) -> str:
    """把检查结果渲染为可读文本。"""
    lines: list[str] = []
    for result in results:
        mark = "通过" if result.ok else "失败"
        lines.append(f"[{mark}] {result.name}：{result.detail}")
    critical_ok = all(result.ok for result in results if result.critical)
    lines.append("全部关键项通过" if critical_ok else "存在关键失败")
    return "\n".join(lines)


def _check_nested(bwrap: str | None, run: Callable[..., Any]) -> CheckResult:
    if not bwrap:
        return CheckResult("嵌套 bwrap", False, "bwrap 缺失")
    argv = [
        bwrap,
        "--ro-bind",
        "/",
        "/",
        "--dev",
        "/dev",
        "--proc",
        "/proc",
        "--unshare-user",
        "--unshare-pid",
        bwrap,
        "--version",
    ]
    return _run_check("嵌套 bwrap", argv, run)


def _check_cgroup(which: Callable[[str], str | None], run: Callable[..., Any]) -> CheckResult:
    systemd_run = which("systemd-run")
    if not systemd_run:
        return CheckResult("cgroup 委托", False, "未找到 systemd-run --user")
    return _run_check(
        "cgroup 委托",
        [systemd_run, "--user", "--scope", "--collect", "true"],
        run,
    )


def _check_userns(bwrap: str | None, run: Callable[..., Any]) -> CheckResult:
    if not bwrap:
        return CheckResult("非特权 user namespace", False, "bwrap 缺失")
    return _run_check(
        "非特权 user namespace",
        [bwrap, "--unshare-user", "--ro-bind", "/", "/", "true"],
        run,
    )


def _check_bash(which: Callable[[str], str | None]) -> CheckResult:
    bash = which("bash")
    if bash is None:
        for candidate in ("/bin/bash", "/usr/bin/bash"):
            if Path(candidate).exists():
                bash = candidate
                break
    return CheckResult("bash 路径", bash is not None, bash or "未找到 bash")


def _check_overlayfs(filesystems: str | None) -> CheckResult:
    text = filesystems
    if text is None:
        try:
            text = Path("/proc/filesystems").read_text(encoding="utf-8")
        except OSError:
            text = ""
    ok = "overlay" in text
    return CheckResult(
        "overlayfs",
        ok,
        "可用" if ok else "不可用（使用 --bind 回退）",
        critical=False,
    )


def _run_check(name: str, argv: list[str], run: Callable[..., Any]) -> CheckResult:
    try:
        proc = run(argv, capture_output=True, timeout=15)
    except Exception as exc:  # noqa: BLE001 - 自检不应抛异常
        return CheckResult(name, False, f"{type(exc).__name__}: {exc}")
    ok = getattr(proc, "returncode", 1) == 0
    return CheckResult(name, ok, "通过" if ok else "执行失败")
