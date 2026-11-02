"""``sandbox`` 入口：自检、TUI/预设选择、写 profile 与同进程 exec（§4.9）。"""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from ..gateway.messages import INTERNAL_ERROR
from ..policy.loader import (
    ProfileError,
    default_profile_path,
    load_profile,
    save_profile,
)
from ..policy.models import Profile
from ..policy.presets import get_preset, preset_names
from ..sandbox import SandboxBuildError
from ..sandbox.builder import SandboxBuilderImpl
from ..sandbox.selfcheck import format_report, run_selfcheck
from ..util import logging as internal_log
from .term import terminal_guard


def main(
    argv: Sequence[str] | None = None,
    *,
    execv: Callable[[str, list[str]], Any] = os.execv,
    form_factory: Callable[[Profile], Any] | None = None,
    selfcheck: Callable[[], Any] = run_selfcheck,
) -> int:
    """返回退出码；成功启动时不会返回（``execv``）。"""
    args = _parse_args(argv)
    if args is None:
        return 64

    if args.check:
        results = selfcheck()
        print(format_report(results))
        return 0 if all(result.ok for result in results if result.critical) else 1

    try:
        profile_path, profile = _resolve_profile(args, form_factory)
    except ProfileError as exc:
        internal_log.debug(f"profile 加载失败：{exc}")
        print(INTERNAL_ERROR, file=sys.stderr)
        return 127
    except SandboxBuildError as exc:
        internal_log.debug(f"沙箱构建失败：{exc}")
        print(INTERNAL_ERROR, file=sys.stderr)
        return 127

    if profile is None:
        return 0

    # 审计目录由网关创建（§8.3），这样外层 bwrap 才能把它绑定为可写
    profile.audit.log_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

    try:
        plan = _build_launch_plan(profile, profile_path)
    except SandboxBuildError as exc:
        internal_log.debug(f"外层 bwrap 构建失败：{exc}")
        print(INTERNAL_ERROR, file=sys.stderr)
        return 127

    execv(plan.argv[0], list(plan.argv))
    return 127


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace | None:
    parser = argparse.ArgumentParser(prog="sandbox", add_help=True)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--profile", help="跳过 TUI，直接加载 profile 路径")
    group.add_argument(
        "--preset",
        choices=preset_names(),
        help="加载预设并跳过 TUI",
    )
    parser.add_argument("--check", action="store_true", help="只运行自检")
    parser.add_argument("--no-tui", action="store_true", help="使用 standard 预设（仅开发）")

    try:
        return parser.parse_args(list(argv) if argv is not None else None)
    except SystemExit as exc:
        if exc.code == 0:
            raise
        return None


def _resolve_profile(
    args: argparse.Namespace,
    form_factory: Callable[[Profile], Any] | None,
) -> tuple[Path, Profile | None]:
    if args.profile:
        path = Path(args.profile).expanduser()
        return path, load_profile(path)

    workspace = Path.cwd()
    if args.preset:
        profile = get_preset(args.preset, workspace=workspace)
    elif args.no_tui:
        internal_log.warning("--no-tui 仅开发使用，采用 standard 预设")
        profile = get_preset("standard", workspace=workspace)
    else:
        from .screens import ProfileForm

        factory = form_factory or ProfileForm
        form = factory(get_preset("standard", workspace=workspace))
        with terminal_guard():
            profile = form.run_form()
        if profile is None:
            return default_profile_path(), None

    path = default_profile_path()
    save_profile(profile, path)
    return path, profile


def _build_launch_plan(profile: Profile, profile_path: Path):
    safe_exec = Path(__file__).resolve().parents[3] / "bin" / "safe-exec"
    builder = SandboxBuilderImpl(safe_exec=safe_exec, profile_path=profile_path)
    plan = builder.build_outer(profile, profile_path)
    return builder.build_cgroup(plan, profile.resources)
