"""``profile.json`` 的数据模型。

对应《实现级架构设计》§5.1。路径字段在加载时已展开为规范绝对路径；
所有模型不可变，修改策略请构造新对象。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class BlacklistAction(str, Enum):
    """读黑名单动作（§5.1 校验规则 4）。"""

    MASK = "mask"        # 用 tmpfs 盖空
    DEVNULL = "devnull"  # 绑定到 /dev/null
    RO_BIND = "ro_bind"  # 只读绑定


class WorkspaceWriteMode(str, Enum):
    """workspace 的写入方式。"""

    BIND = "bind"


@dataclass(frozen=True)
class ReadBlacklistEntry:
    """读黑名单条目。"""

    path: Path
    action: BlacklistAction


@dataclass(frozen=True)
class FilesystemConfig:
    """文件视图配置。"""

    read_blacklist: tuple[ReadBlacklistEntry, ...] = ()
    write_whitelist: tuple[Path, ...] = ()
    tmp_size_bytes: int = 0


@dataclass(frozen=True)
class ResourceLimits:
    """cgroup 资源限制。"""

    memory_max: str = "0"
    pids_max: int = 0
    cpu_quota: str = "0%"


@dataclass(frozen=True)
class BashConfig:
    """类 1 白名单与脚本限制。"""

    utility_whitelist: tuple[str, ...] = ()
    trusted_path: tuple[Path, ...] = ()
    allow_scripts: bool = False
    max_script_bytes: int = 0


@dataclass(frozen=True)
class PythonConfig:
    """类 2 解释器与源码限制。"""

    allowed_interpreters: tuple[Path, ...] = ()
    max_source_bytes: int = 0


@dataclass(frozen=True)
class LlmJudgeConfig:
    """LLM 兜底配置。"""

    enabled: bool = False
    endpoint: str = ""
    model: str = ""
    timeout_ms: int = 0
    allow_remote: bool = False


@dataclass(frozen=True)
class NetworkConfig:
    """网络外发审查配置。"""

    enabled: bool = True
    safe_domains: tuple[str, ...] = ()
    llm_judge: LlmJudgeConfig = field(default_factory=LlmJudgeConfig)


@dataclass(frozen=True)
class InnerConfig:
    """内层沙箱配置。"""

    max_depth: int = 1
    masked_executables: tuple[Path, ...] = ()
    seccomp_denylist: tuple[str, ...] = ()


@dataclass(frozen=True)
class AuditConfig:
    """审计日志配置。"""

    log_dir: Path = Path(".")
    log_command_text: bool = False
    max_bytes: int = 0
    backups: int = 0


@dataclass(frozen=True)
class NoticesConfig:
    """用户提示开关。"""

    class3_notice: bool = True


@dataclass(frozen=True)
class Profile:
    """完整的运行时策略。"""

    schema_version: int
    profile_name: str
    workspace: Path
    workspace_write_mode: WorkspaceWriteMode
    filesystem: FilesystemConfig = field(default_factory=FilesystemConfig)
    resources: ResourceLimits = field(default_factory=ResourceLimits)
    bash: BashConfig = field(default_factory=BashConfig)
    python: PythonConfig = field(default_factory=PythonConfig)
    network: NetworkConfig = field(default_factory=NetworkConfig)
    inner: InnerConfig = field(default_factory=InnerConfig)
    audit: AuditConfig = field(default_factory=AuditConfig)
    notices: NoticesConfig = field(default_factory=NoticesConfig)
