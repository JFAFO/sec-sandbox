"""跨模块传递的不可变数据模型。

对应《实现级架构设计》§4.1；``InnerLaunchRequest`` 来自 §4.6，``JudgeRequest``
来自 §4.8。所有模型均为 ``frozen=True`` 的 dataclass，跨模块只传值、不在原地修改。
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

from .enums import (
    CommandShape,
    Decision,
    InvocationMode,
    JudgeVerdict,
    NetworkDecision,
    ReasonCode,
)


@dataclass(frozen=True)
class CommandRequest:
    """一次 ``safe-exec`` 调用的输入。"""

    argv: tuple[str, ...]  # safe-exec 收到的参数（不含 argv[0]）
    mode: InvocationMode
    command_text: str | None  # -c 文本 / 脚本文本 / stdin 文本
    script_path: Path | None
    cwd: Path
    env: Mapping[str, str]
    depth: int


@dataclass(frozen=True)
class AuditContext:
    """审计器可用的路径上下文（由网关在边界构造）。"""

    cwd: Path
    home: Path
    workspace: Path


@dataclass(frozen=True)
class ParsedBash:
    """bashlex 解析结果；失败时 ``ok=False``，不抛异常。"""

    text: str
    nodes: tuple[object, ...]  # bashlex AST；只有 bash_audit/netpolicy 解释
    ok: bool
    error: str | None  # 解析失败原因（内部用）


@dataclass(frozen=True)
class AuditVerdict:
    """执行线裁决。"""

    decision: Decision
    reason: ReasonCode
    rule_ids: tuple[str, ...] = ()
    details: Mapping[str, str] = field(default_factory=dict)  # 内部证据，已脱敏


@dataclass(frozen=True)
class BashAnalysis:
    """M2 的完整分析结果。"""

    shape: CommandShape
    verdict: AuditVerdict  # shape != SIMPLE 时固定为 DOWNGRADE


@dataclass(frozen=True)
class NetworkVerdict:
    """网络线裁决。"""

    decision: NetworkDecision
    reason: ReasonCode
    rule_ids: tuple[str, ...] = ()
    consulted_llm: bool = False
    llm_latency_ms: int | None = None


@dataclass(frozen=True)
class ExecutionResult:
    """执行器返回的结果。"""

    exit_code: int  # 已映射为 0-255 的 shell 语义
    signal: int | None  # 被信号终止时的信号号
    duration_ms: int


@dataclass(frozen=True)
class LaunchPlan:
    """待执行的 argv 与环境。"""

    argv: tuple[str, ...]
    env: Mapping[str, str] = field(default_factory=dict)
    pass_fds: tuple[int, ...] = ()


@dataclass(frozen=True)
class InnerLaunchRequest:
    """内层 bwrap 需要启动的 shell 命令（§4.6）。"""

    shell_argv: tuple[str, ...]  # 交给 real-bash 的参数（如 -c text）
    cwd: Path
    depth: int


@dataclass(frozen=True)
class JudgeRequest:
    """送交 LLM 兜底判定的脱敏请求（§4.8）。"""

    redacted_command: str
    target: str
    method: str  # fetch / send
    ambiguous_items: tuple[str, ...]


__all__ = [
    "AuditContext",
    "AuditVerdict",
    "BashAnalysis",
    "CommandRequest",
    "ExecutionResult",
    "InnerLaunchRequest",
    "JudgeRequest",
    "LaunchPlan",
    "NetworkVerdict",
    "ParsedBash",
    # 便于调用方只导入 models 时也能拿到枚举
    "CommandShape",
    "Decision",
    "JudgeVerdict",
    "InvocationMode",
    "NetworkDecision",
    "ReasonCode",
]
