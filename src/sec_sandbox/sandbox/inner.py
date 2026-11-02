"""内层 bwrap：类 3 的硬隔离视图（§4.6）。

内层不替换 ``/bin/bash``，否则会递归；挂载集只可能比外层更严。
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from ..contracts import InnerLaunchRequest, LaunchPlan
from ..policy.models import Profile
from . import SandboxBuildError
from .mounts import DEFAULT_READ_BLACKLIST, inner_mounts
from .paths import RuntimePaths, probe_paths

INNER_REAL_BASH = "/usr/bin/real-bash"


def build_inner(
    profile: Profile,
    req: InnerLaunchRequest,
    *,
    profile_path: Path,
    paths: RuntimePaths | None = None,
    seccomp_fd: int | None = None,
    defaults: Sequence[tuple[str, str]] = DEFAULT_READ_BLACKLIST,
    supports_tmp_size: bool = True,
) -> LaunchPlan:
    """生成内层 bwrap argv；``shell_argv`` 不含 real-bash 自身。"""
    runtime = paths if paths is not None else probe_paths(profile)

    if not profile_path.exists():
        raise SandboxBuildError(f"profile 不存在：{profile_path}")

    args: list[str] = [
        "bwrap",
        "--die-with-parent",
        "--unshare-pid",
        "--unshare-ipc",
        "--unshare-uts",
        "--cap-drop",
        "ALL",
        "--ro-bind",
        "/",
        "/",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
    ]
    args.extend(_tmpfs_args(profile, supports_tmp_size))
    args.extend(inner_mounts(profile, runtime, defaults=defaults).args)

    for executable in profile.inner.masked_executables:
        if executable.exists():
            args.extend(("--ro-bind", "/dev/null", str(executable)))

    pass_fds: tuple[int, ...] = ()
    if seccomp_fd is not None:
        args.extend(("--seccomp", str(seccomp_fd)))
        pass_fds = (seccomp_fd,)

    args.extend(("--setenv", "SECSAND_DEPTH", str(req.depth + 1)))
    args.extend(("--setenv", "SECSAND_PROFILE", str(profile_path)))
    args.extend(("--chdir", str(req.cwd)))
    args.append(INNER_REAL_BASH)
    args.extend(req.shell_argv)
    return LaunchPlan(argv=tuple(args), pass_fds=pass_fds)


def _tmpfs_args(profile: Profile, supports_size: bool) -> tuple[str, ...]:
    # bwrap 要求 --size 紧邻其后的 --tmpfs；0.6.1 不认识 --size，降级为普通 tmpfs。
    if supports_size and profile.filesystem.tmp_size_bytes > 0:
        return (
            "--size",
            str(profile.filesystem.tmp_size_bytes),
            "--tmpfs",
            "/tmp",
        )
    return ("--tmpfs", "/tmp")
