"""``profile.json`` 的手写校验器（不引入 jsonschema 依赖）。

对应《实现级架构设计》§5.1：

- 一次返回**全部**问题，不在第一条处停止；
- 未知字段告警并忽略，未知枚举值拒绝；
- 路径在加载时展开为规范绝对路径，含 ``..`` 的路径一律拒绝。
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..util.paths import canonicalize, is_under
from .models import (
    AuditConfig,
    BashConfig,
    BlacklistAction,
    FilesystemConfig,
    InnerConfig,
    LlmJudgeConfig,
    NetworkConfig,
    NoticesConfig,
    Profile,
    PythonConfig,
    ReadBlacklistEntry,
    ResourceLimits,
    WorkspaceWriteMode,
)

ERROR = "error"
WARNING = "warning"

_MEMORY_RE = re.compile(r"^\d+[KMG]?$")
_CPU_QUOTA_RE = re.compile(r"^\d+(\.\d+)?%$")

_TOP_KEYS = frozenset(
    {
        "schema_version",
        "profile_name",
        "workspace",
        "workspace_write_mode",
        "filesystem",
        "resources",
        "bash",
        "python",
        "network",
        "inner",
        "audit",
        "notices",
    }
)
_FILESYSTEM_KEYS = frozenset({"read_blacklist", "write_whitelist", "tmp_size_bytes"})
_BLACKLIST_ENTRY_KEYS = frozenset({"path", "action"})
_RESOURCE_KEYS = frozenset({"memory_max", "pids_max", "cpu_quota"})
_BASH_KEYS = frozenset(
    {"utility_whitelist", "trusted_path", "allow_scripts", "max_script_bytes"}
)
_PYTHON_KEYS = frozenset({"allowed_interpreters", "max_source_bytes"})
_NETWORK_KEYS = frozenset({"enabled", "safe_domains", "llm_judge"})
_LLM_KEYS = frozenset({"enabled", "endpoint", "model", "timeout_ms", "allow_remote"})
_INNER_KEYS = frozenset({"max_depth", "masked_executables", "seccomp_denylist"})
_AUDIT_KEYS = frozenset({"log_dir", "log_command_text", "max_bytes", "backups"})
_NOTICES_KEYS = frozenset({"class3_notice"})

_PLACEHOLDER_WORKSPACE = Path("/")
_PLACEHOLDER_LOG_DIR = Path("/")


@dataclass(frozen=True)
class ValidationIssue:
    """一条校验问题。"""

    path: str
    message: str
    severity: str = ERROR


@dataclass(frozen=True)
class ValidationResult:
    """校验结果；``profile`` 为 ``None`` 表示存在错误。"""

    profile: Profile | None
    issues: tuple[ValidationIssue, ...] = ()

    @property
    def ok(self) -> bool:
        return self.profile is not None

    @property
    def errors(self) -> tuple[ValidationIssue, ...]:
        return tuple(issue for issue in self.issues if issue.severity == ERROR)

    @property
    def warnings(self) -> tuple[ValidationIssue, ...]:
        return tuple(issue for issue in self.issues if issue.severity == WARNING)


class _Collector:
    """收集问题；所有解析函数共用，保证不中断。"""

    def __init__(self) -> None:
        self.issues: list[ValidationIssue] = []

    @property
    def errors(self) -> list[ValidationIssue]:
        return [issue for issue in self.issues if issue.severity == ERROR]

    def error(self, path: str, message: str) -> None:
        self.issues.append(ValidationIssue(path, message, ERROR))

    def warning(self, path: str, message: str) -> None:
        self.issues.append(ValidationIssue(path, message, WARNING))

    def unknown(self, data: Mapping[str, Any], allowed: frozenset[str], prefix: str) -> None:
        for key in data:
            if key not in allowed:
                self.warning(_join(prefix, str(key)), "未知字段，已忽略")


def parse_profile(
    data: Mapping[str, Any],
    *,
    check_workspace: bool = True,
) -> ValidationResult:
    """校验并构造 :class:`Profile`。

    Args:
        data: ``json.loads`` 得到的对象。
        check_workspace: 是否要求 ``workspace`` 已存在且为目录
            （预设加载传 ``False``，启动时再校验）。
    """
    collector = _Collector()
    if not isinstance(data, Mapping):
        collector.error("", "profile 顶层必须是 JSON 对象")
        return ValidationResult(None, tuple(collector.issues))

    collector.unknown(data, _TOP_KEYS, "")

    schema_version = data.get("schema_version")
    if isinstance(schema_version, bool) or schema_version != 1:
        collector.error("schema_version", "必须为 1（不支持的版本）")
        schema_version = 0

    profile_name = _string(collector, data, "profile_name", "")
    workspace = _path_field(collector, data, "workspace", "")
    write_mode = _write_mode(collector, data.get("workspace_write_mode"))

    filesystem = _filesystem(collector, data)
    resources = _resources(collector, data)
    bash = _bash(collector, data)
    python = _python(collector, data)
    network = _network(collector, data)
    inner = _inner(collector, data)
    audit = _audit(collector, data)
    notices = _notices(collector, data)

    if workspace is not None and check_workspace and not workspace.is_dir():
        collector.error("workspace", f"必须存在且为目录：{workspace}")

    _check_write_whitelist(
        collector,
        filesystem.write_whitelist,
        workspace,
        audit.log_dir,
    )

    profile = Profile(
        schema_version=schema_version,
        profile_name=profile_name,
        workspace=workspace if workspace is not None else _PLACEHOLDER_WORKSPACE,
        workspace_write_mode=write_mode,
        filesystem=filesystem,
        resources=resources,
        bash=bash,
        python=python,
        network=network,
        inner=inner,
        audit=audit,
        notices=notices,
    )
    return ValidationResult(profile if not collector.errors else None, tuple(collector.issues))


def _write_mode(collector: _Collector, raw: Any) -> WorkspaceWriteMode:
    if raw is None:
        collector.error("workspace_write_mode", "必须为 bind")
        return WorkspaceWriteMode.BIND
    try:
        return WorkspaceWriteMode(raw)
    except (ValueError, TypeError):
        collector.error("workspace_write_mode", f"未知取值：{raw!r}")
        return WorkspaceWriteMode.BIND


def _filesystem(collector: _Collector, data: Mapping[str, Any]) -> FilesystemConfig:
    section = _mapping(collector, data, "filesystem", "", _FILESYSTEM_KEYS)

    entries: list[ReadBlacklistEntry] = []
    raw_entries = section.get("read_blacklist")
    if not isinstance(raw_entries, list):
        collector.error("filesystem.read_blacklist", "必须是数组")
    else:
        for index, item in enumerate(raw_entries):
            entry_path = f"filesystem.read_blacklist[{index}]"
            if not isinstance(item, Mapping):
                collector.error(entry_path, "必须是对象")
                continue
            collector.unknown(item, _BLACKLIST_ENTRY_KEYS, entry_path)
            path = _path_value(collector, item.get("path"), f"{entry_path}.path")
            action = _blacklist_action(collector, item.get("action"), f"{entry_path}.action")
            if path is not None and action is not None:
                entries.append(ReadBlacklistEntry(path, action))

    write_whitelist = _path_list(collector, section, "write_whitelist", "filesystem")
    tmp_size_bytes = _integer(
        collector, section, "tmp_size_bytes", "filesystem", default=0, minimum=0
    )
    return FilesystemConfig(tuple(entries), write_whitelist, tmp_size_bytes)


def _blacklist_action(
    collector: _Collector, raw: Any, path: str
) -> BlacklistAction | None:
    try:
        return BlacklistAction(raw)
    except (ValueError, TypeError):
        collector.error(path, f"未知取值：{raw!r}（允许 mask/devnull/ro_bind）")
        return None


def _resources(collector: _Collector, data: Mapping[str, Any]) -> ResourceLimits:
    section = _mapping(collector, data, "resources", "", _RESOURCE_KEYS)
    memory_max = _string(collector, section, "memory_max", "resources")
    if memory_max and not _MEMORY_RE.match(memory_max):
        collector.error("resources.memory_max", "格式必须匹配 ^\\d+[KMG]?$")
    pids_max = _integer(collector, section, "pids_max", "resources", default=0, minimum=1)
    cpu_quota = _string(collector, section, "cpu_quota", "resources")
    if cpu_quota and not _CPU_QUOTA_RE.match(cpu_quota):
        collector.error("resources.cpu_quota", "格式必须匹配 ^\\d+(\\.\\d+)?%$")
    return ResourceLimits(memory_max, pids_max, cpu_quota)


def _bash(collector: _Collector, data: Mapping[str, Any]) -> BashConfig:
    section = _mapping(collector, data, "bash", "", _BASH_KEYS)
    return BashConfig(
        utility_whitelist=_string_list(collector, section, "utility_whitelist", "bash"),
        trusted_path=_path_list(collector, section, "trusted_path", "bash"),
        allow_scripts=_boolean(collector, section, "allow_scripts", "bash", default=False),
        max_script_bytes=_integer(
            collector, section, "max_script_bytes", "bash", default=0, minimum=0
        ),
    )


def _python(collector: _Collector, data: Mapping[str, Any]) -> PythonConfig:
    section = _mapping(collector, data, "python", "", _PYTHON_KEYS)
    return PythonConfig(
        allowed_interpreters=_path_list(
            collector, section, "allowed_interpreters", "python"
        ),
        max_source_bytes=_integer(
            collector, section, "max_source_bytes", "python", default=0, minimum=0
        ),
    )


def _network(collector: _Collector, data: Mapping[str, Any]) -> NetworkConfig:
    section = _mapping(collector, data, "network", "", _NETWORK_KEYS)
    llm_section = _mapping(
        collector, section, "llm_judge", "network", _LLM_KEYS
    )
    llm = LlmJudgeConfig(
        enabled=_boolean(
            collector, llm_section, "enabled", "network.llm_judge", default=False
        ),
        endpoint=_string(collector, llm_section, "endpoint", "network.llm_judge"),
        model=_string(collector, llm_section, "model", "network.llm_judge"),
        timeout_ms=_integer(
            collector, llm_section, "timeout_ms", "network.llm_judge", default=0, minimum=1
        ),
        allow_remote=_boolean(
            collector, llm_section, "allow_remote", "network.llm_judge", default=False
        ),
    )
    return NetworkConfig(
        enabled=_boolean(collector, section, "enabled", "network", default=True),
        safe_domains=_string_list(collector, section, "safe_domains", "network"),
        llm_judge=llm,
    )


def _inner(collector: _Collector, data: Mapping[str, Any]) -> InnerConfig:
    section = _mapping(collector, data, "inner", "", _INNER_KEYS)
    return InnerConfig(
        max_depth=_integer(collector, section, "max_depth", "inner", default=1, minimum=0),
        masked_executables=_path_list(
            collector, section, "masked_executables", "inner"
        ),
        seccomp_denylist=_string_list(
            collector, section, "seccomp_denylist", "inner"
        ),
    )


def _audit(collector: _Collector, data: Mapping[str, Any]) -> AuditConfig:
    section = _mapping(collector, data, "audit", "", _AUDIT_KEYS)
    log_dir = _path_field(collector, section, "log_dir", "audit")
    if log_dir is not None and not is_under(
        log_dir, canonicalize("$HOME/.local/state")
    ):
        # 防止用 profile 自身的 log_dir 为任意写白名单自我授权（§8.3）
        collector.error("audit.log_dir", "必须位于 $HOME/.local/state 下")
    return AuditConfig(
        log_dir=log_dir if log_dir is not None else _PLACEHOLDER_LOG_DIR,
        log_command_text=_boolean(
            collector, section, "log_command_text", "audit", default=False
        ),
        max_bytes=_integer(collector, section, "max_bytes", "audit", default=0, minimum=1),
        backups=_integer(collector, section, "backups", "audit", default=0, minimum=0),
    )


def _notices(collector: _Collector, data: Mapping[str, Any]) -> NoticesConfig:
    section = _mapping(collector, data, "notices", "", _NOTICES_KEYS)
    return NoticesConfig(
        class3_notice=_boolean(
            collector, section, "class3_notice", "notices", default=True
        )
    )


def _check_write_whitelist(
    collector: _Collector,
    write_whitelist: tuple[Path, ...],
    workspace: Path | None,
    log_dir: Path,
) -> None:
    home = canonicalize("$HOME")
    runtime_required = {home / ".claude", home / ".claude.json", log_dir}
    for index, path in enumerate(write_whitelist):
        if path in runtime_required:
            continue
        if workspace is not None and is_under(path, workspace):
            continue
        collector.error(
            f"filesystem.write_whitelist[{index}]",
            "必须是 workspace 的子路径或运行必需目录（~/.claude、~/.claude.json、审计目录）",
        )


def _mapping(
    collector: _Collector,
    data: Mapping[str, Any],
    key: str,
    prefix: str,
    allowed: frozenset[str],
) -> Mapping[str, Any]:
    path = _join(prefix, key)
    value = data.get(key)
    if not isinstance(value, Mapping):
        collector.error(path, "必须是对象")
        return {}
    collector.unknown(value, allowed, path)
    return value


def _string(
    collector: _Collector,
    data: Mapping[str, Any],
    key: str,
    prefix: str,
) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value:
        collector.error(_join(prefix, key), "必须是非空字符串")
        return ""
    return value


def _boolean(
    collector: _Collector,
    data: Mapping[str, Any],
    key: str,
    prefix: str,
    *,
    default: bool,
) -> bool:
    value = data.get(key)
    if not isinstance(value, bool):
        collector.error(_join(prefix, key), "必须是布尔值")
        return default
    return value


def _integer(
    collector: _Collector,
    data: Mapping[str, Any],
    key: str,
    prefix: str,
    *,
    default: int,
    minimum: int,
) -> int:
    value = data.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        collector.error(_join(prefix, key), f"必须是 >= {minimum} 的整数")
        return default
    return value


def _string_list(
    collector: _Collector,
    data: Mapping[str, Any],
    key: str,
    prefix: str,
) -> tuple[str, ...]:
    value = data.get(key)
    path = _join(prefix, key)
    if not isinstance(value, list):
        collector.error(path, "必须是字符串数组")
        return ()
    result: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item:
            collector.error(f"{path}[{index}]", "必须是非空字符串")
            continue
        result.append(item)
    return tuple(result)


def _path_field(
    collector: _Collector,
    data: Mapping[str, Any],
    key: str,
    prefix: str,
) -> Path | None:
    return _path_value(collector, data.get(key), _join(prefix, key))


def _path_list(
    collector: _Collector,
    data: Mapping[str, Any],
    key: str,
    prefix: str,
) -> tuple[Path, ...]:
    value = data.get(key)
    path = _join(prefix, key)
    if not isinstance(value, list):
        collector.error(path, "必须是路径字符串数组")
        return ()
    result: list[Path] = []
    for index, item in enumerate(value):
        parsed = _path_value(collector, item, f"{path}[{index}]")
        if parsed is not None:
            result.append(parsed)
    return tuple(result)


def _path_value(collector: _Collector, value: Any, path: str) -> Path | None:
    if not isinstance(value, str) or not value:
        collector.error(path, "必须是非空路径字符串")
        return None
    if ".." in Path(value).parts:
        collector.error(path, "路径不得包含 ..")
        return None
    try:
        return canonicalize(value)
    except ValueError as exc:
        collector.error(path, str(exc))
        return None


def _join(prefix: str, key: str) -> str:
    return f"{prefix}.{key}" if prefix else key
