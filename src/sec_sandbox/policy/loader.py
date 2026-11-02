"""``profile.json`` 的加载与原子写入。

对应《实现级架构设计》§5.1：位置 ``$HOME/.config/sandbox/profile.json``；
写入先写同目录临时文件，``os.replace`` 原子替换，权限 0600。
"""

from __future__ import annotations

import json
import os
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from ..util import logging as internal_log
from .models import Profile
from .schema import ValidationIssue, parse_profile


class ProfileError(Exception):
    """profile 无法读取或校验失败。"""

    def __init__(self, message: str, issues: Sequence[ValidationIssue] = ()) -> None:
        super().__init__(message)
        self.issues: tuple[ValidationIssue, ...] = tuple(issues)


def default_profile_path() -> Path:
    """默认 profile 路径：``$HOME/.config/sandbox/profile.json``。"""
    return Path.home() / ".config" / "sandbox" / "profile.json"


def load_profile(
    path: str | Path | None = None,
    *,
    check_workspace: bool = True,
) -> Profile:
    """读取并校验 profile；任何错误抛 :class:`ProfileError` 并携带全部问题。"""
    profile_path = Path(path) if path is not None else default_profile_path()
    try:
        raw = profile_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ProfileError(f"无法读取 profile：{profile_path}") from exc

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ProfileError(f"profile 不是合法 JSON：{profile_path}：{exc}") from exc

    if not isinstance(data, Mapping):
        raise ProfileError(f"profile 顶层必须是 JSON 对象：{profile_path}")

    result = parse_profile(data, check_workspace=check_workspace)
    for issue in result.warnings:
        internal_log.warning(f"profile 警告 {issue.path}: {issue.message}")

    if result.profile is None:
        detail = "；".join(
            f"{issue.path}: {issue.message}" for issue in result.errors
        )
        raise ProfileError(
            f"profile 校验失败（{len(result.errors)} 项）：{detail}",
            result.issues,
        )
    return result.profile


def save_profile(profile: Profile, path: str | Path | None = None) -> Path:
    """原子写入 profile（0600），返回实际写入路径。"""
    target = Path(path) if path is not None else default_profile_path()
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

    text = json.dumps(
        profile_to_dict(profile), ensure_ascii=False, indent=2
    ) + "\n"

    fd, tmp_name = tempfile.mkstemp(dir=target.parent, prefix=".profile-", suffix=".json")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, target)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise
    return target


def profile_to_dict(profile: Profile) -> dict[str, Any]:
    """把 :class:`Profile` 序列化为 JSON 兼容的字典；``$HOME`` 下的路径写回前缀形式。"""
    return {
        "schema_version": profile.schema_version,
        "profile_name": profile.profile_name,
        "workspace": _externalize(profile.workspace),
        "workspace_write_mode": profile.workspace_write_mode.value,
        "filesystem": {
            "read_blacklist": [
                {"path": _externalize(entry.path), "action": entry.action.value}
                for entry in profile.filesystem.read_blacklist
            ],
            "write_whitelist": [
                _externalize(path) for path in profile.filesystem.write_whitelist
            ],
            "tmp_size_bytes": profile.filesystem.tmp_size_bytes,
        },
        "resources": {
            "memory_max": profile.resources.memory_max,
            "pids_max": profile.resources.pids_max,
            "cpu_quota": profile.resources.cpu_quota,
        },
        "bash": {
            "utility_whitelist": list(profile.bash.utility_whitelist),
            "trusted_path": [_externalize(path) for path in profile.bash.trusted_path],
            "allow_scripts": profile.bash.allow_scripts,
            "max_script_bytes": profile.bash.max_script_bytes,
        },
        "python": {
            "allowed_interpreters": [
                _externalize(path) for path in profile.python.allowed_interpreters
            ],
            "max_source_bytes": profile.python.max_source_bytes,
        },
        "network": {
            "enabled": profile.network.enabled,
            "safe_domains": list(profile.network.safe_domains),
            "llm_judge": {
                "enabled": profile.network.llm_judge.enabled,
                "endpoint": profile.network.llm_judge.endpoint,
                "model": profile.network.llm_judge.model,
                "timeout_ms": profile.network.llm_judge.timeout_ms,
                "allow_remote": profile.network.llm_judge.allow_remote,
            },
        },
        "inner": {
            "max_depth": profile.inner.max_depth,
            "masked_executables": [
                _externalize(path) for path in profile.inner.masked_executables
            ],
            "seccomp_denylist": list(profile.inner.seccomp_denylist),
        },
        "audit": {
            "log_dir": _externalize(profile.audit.log_dir),
            "log_command_text": profile.audit.log_command_text,
            "max_bytes": profile.audit.max_bytes,
            "backups": profile.audit.backups,
        },
        "notices": {"class3_notice": profile.notices.class3_notice},
    }


def _externalize(path: Path) -> str:
    """``$HOME`` 下的路径写回 ``$HOME/...``，其余保持绝对路径。"""
    home = Path(os.path.realpath(Path.home()))
    try:
        relative = path.relative_to(home)
    except ValueError:
        return str(path)
    return "$HOME" if relative == Path(".") else f"$HOME/{relative.as_posix()}"
