"""按附录 A 生成 bwrap 挂载参数（外层/内层）。

- 源路径不存在则跳过并记录；
- 写绑定必须出现在读黑名单之前（内核对同一路径的后续绑定时后写生效）；
- 内层可写集 ⊆ 外层（内层只保留 workspace 与审计目录可写，并把
  ``~/.claude``、``~/.claude.json`` 锁回只读）。
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

from ..policy.models import BlacklistAction, Profile
from ..util.paths import expand_path
from .paths import RuntimePaths, probe_paths

# 附录 A.1 默认读黑名单：(路径, action)
DEFAULT_READ_BLACKLIST: tuple[tuple[str, str], ...] = (
    ("$HOME/.ssh", "mask"),
    ("$HOME/.gnupg", "mask"),
    ("$HOME/.password-store", "mask"),
    ("$HOME/.aws", "mask"),
    ("$HOME/.config/gcloud", "mask"),
    ("$HOME/.kube", "mask"),
    ("$HOME/.config/azure", "mask"),
    ("$HOME/.terraform.d", "mask"),
    ("$HOME/.config/doctl", "mask"),
    ("$HOME/.npmrc", "devnull"),
    ("$HOME/.pypirc", "devnull"),
    ("$HOME/.netrc", "devnull"),
    ("$HOME/.vault-token", "devnull"),
    ("$HOME/.git-credentials", "devnull"),
    ("$HOME/.config/gh", "mask"),
    ("$HOME/.docker/config.json", "devnull"),
    ("$HOME/.local/share/keyrings", "mask"),
    ("$HOME/.bash_history", "devnull"),
    ("$HOME/.zsh_history", "devnull"),
    ("$HOME/.python_history", "devnull"),
    ("/etc/shadow", "devnull"),
    ("/etc/gshadow", "devnull"),
    ("/etc/sudoers", "devnull"),
    ("/etc/sudoers.d", "mask"),
)

# 内层额外遮蔽项（附录 A.1 最后一行）
INNER_EXTRA_BLACKLIST: tuple[tuple[str, str], ...] = (
    ("$HOME/.config", "mask"),
    ("$HOME/.gitconfig", "devnull"),
)


@dataclass(frozen=True)
class MountSpec:
    """bwrap 挂载参数片段与因源不存在而跳过的路径。"""

    args: tuple[str, ...] = ()
    skipped: tuple[Path, ...] = field(default_factory=tuple)


def outer_mounts(
    profile: Profile,
    paths: RuntimePaths | None = None,
    *,
    defaults: Sequence[tuple[str, str]] = DEFAULT_READ_BLACKLIST,
) -> MountSpec:
    """本体层挂载：写绑定在前，读黑名单在后。"""
    runtime = paths if paths is not None else probe_paths(profile)
    args: list[str] = []
    skipped: list[Path] = []

    _bind_if_present(args, skipped, "--bind", runtime.workspace)
    _bind_if_present(args, skipped, "--bind", runtime.home / ".claude")
    _bind_if_present(args, skipped, "--bind", runtime.home / ".claude.json")
    _bind_if_present(args, skipped, "--bind", runtime.audit_dir)

    _append_blacklist(args, skipped, profile, defaults)
    return MountSpec(tuple(args), tuple(skipped))


def inner_mounts(
    profile: Profile,
    paths: RuntimePaths | None = None,
    *,
    defaults: Sequence[tuple[str, str]] = DEFAULT_READ_BLACKLIST,
) -> MountSpec:
    """内层挂载：workspace 可写，其余写绑定锁回只读。"""
    runtime = paths if paths is not None else probe_paths(profile)
    args: list[str] = []
    skipped: list[Path] = []

    _bind_if_present(args, skipped, "--bind", runtime.workspace)

    _append_blacklist(args, skipped, profile, defaults)
    _append_blacklist(args, skipped, profile, INNER_EXTRA_BLACKLIST)

    # 外层可写项在内层锁回只读
    _bind_if_present(args, skipped, "--ro-bind", runtime.home / ".claude")
    _bind_if_present(args, skipped, "--ro-bind", runtime.home / ".claude.json")

    return MountSpec(tuple(args), tuple(skipped))


def _append_blacklist(
    args: list[str],
    skipped: list[Path],
    profile: Profile,
    defaults: Sequence[tuple[str, str]],
) -> None:
    seen: set[Path] = set()

    for entry in profile.filesystem.read_blacklist:
        _append_mask(args, skipped, seen, entry.path, entry.action.value)

    for raw_path, action in defaults:
        try:
            path = expand_path(raw_path)
        except ValueError:
            skipped.append(Path(raw_path))
            continue
        _append_mask(args, skipped, seen, path, action)


def _append_mask(
    args: list[str],
    skipped: list[Path],
    seen: set[Path],
    path: Path,
    action: str,
) -> None:
    if path in seen:
        return
    seen.add(path)

    if not path.exists():
        skipped.append(path)
        return

    if path.is_dir():
        if action == BlacklistAction.RO_BIND.value:
            args.extend(("--ro-bind", str(path), str(path)))
        else:
            args.extend(("--tmpfs", str(path)))
        return

    if action == BlacklistAction.RO_BIND.value:
        args.extend(("--ro-bind", str(path), str(path)))
    else:
        args.extend(("--ro-bind", "/dev/null", str(path)))


def _bind_if_present(
    args: list[str],
    skipped: list[Path],
    flag: str,
    path: Path,
) -> None:
    if not path.exists():
        skipped.append(path)
        return
    args.extend((flag, str(path), str(path)))
