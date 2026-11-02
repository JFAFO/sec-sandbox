"""契约层：模块共享的枚举、数据模型与 Protocol。

本包只依赖标准库；任何内部模块依赖都视为破坏架构（§7）。
"""

from .enums import (
    CommandClass,
    CommandShape,
    Decision,
    ExitCode,
    InvocationMode,
    JudgeVerdict,
    NetworkDecision,
    ReasonCode,
)
from .models import (
    AuditContext,
    AuditVerdict,
    BashAnalysis,
    CommandRequest,
    ExecutionResult,
    InnerLaunchRequest,
    JudgeRequest,
    LaunchPlan,
    NetworkVerdict,
    ParsedBash,
)
from .protocols import (
    BashAuditor,
    LlmJudge,
    NetworkAnalyzer,
    PythonAuditor,
    SandboxBuilder,
)

__all__ = [
    # enums
    "CommandClass",
    "CommandShape",
    "Decision",
    "ExitCode",
    "InvocationMode",
    "JudgeVerdict",
    "NetworkDecision",
    "ReasonCode",
    # models
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
    # protocols
    "BashAuditor",
    "LlmJudge",
    "NetworkAnalyzer",
    "PythonAuditor",
    "SandboxBuilder",
]
