"""外层 bwrap：本体层文件视图与网关入口替换（§4.6）。"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from ..contracts import LaunchPlan
from ..policy.models import Profile
from . import SandboxBuildError
from .mounts import DEFAULT_READ_BLACKLIST, outer_mounts
from .paths import RuntimePaths, probe_paths


def build_outer(
    profile: Profile,
    profile_path: Path,
    *,
    safe_exec: Path,
    paths: RuntimePaths | None = None,
    seccomp_fd: int | None = None,
    defaults: Sequence[tuple[str, str]] = DEFAULT_READ_BLACKLIST,
    supports_tmp_size: bool = True,
) -> LaunchPlan:
    """生成本体层 bwrap argv；真 bash 备份为 ``/usr/bin/real-bash``。"""
    runtime = paths if paths is not None else probe_paths(profile)

    if runtime.real_bash is None:
        raise SandboxBuildError("未找到可用的 bash")
    if not safe_exec.exists():
        raise SandboxBuildError(f"网关入口不存在：{safe_exec}")
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
    args.extend(outer_mounts(profile, runtime, defaults=defaults).args)
    args.extend(("--ro-bind", str(runtime.real_bash), "/usr/bin/real-bash"))

    for target in _bash_targets(runtime):
        args.extend(("--ro-bind", str(safe_exec), str(target)))

    args.extend(("--ro-bind", str(profile_path), str(profile_path)))
    args.extend(("--setenv", "SECSAND_PROFILE", str(profile_path)))
    args.extend(("--setenv", "SECSAND_DEPTH", "0"))
    args.extend(("--setenv", "SECSAND_REAL_BASH", "/usr/bin/real-bash"))

    pass_fds: tuple[int, ...] = ()
    if seccomp_fd is not None:
        args.extend(("--seccomp", str(seccomp_fd)))
        pass_fds = (seccomp_fd,)

    args.extend(("--chdir", str(runtime.workspace)))
    args.append("/usr/bin/bash")
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


def _bash_targets(runtime: RuntimePaths) -> tuple[Path, ...]:
    targets: list[Path] = [Path("/usr/bin/bash")]
    for path in runtime.bash_paths:
        if path not in targets:
            targets.append(path)
    return tuple(targets)
