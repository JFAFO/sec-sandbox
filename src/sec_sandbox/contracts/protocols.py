"""跨模块接口 Protocol。

对应《实现级架构设计》§4.3-§4.8。实现类在组合根
（``gateway/cli.py``、``frontend/app.py``）注入，调用方只依赖这里的 Protocol。

``policy.models`` 只在类型检查期导入，保证 ``contracts`` 运行时零内部依赖（§7）。
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from .enums import JudgeVerdict
from .models import (
    AuditContext,
    AuditVerdict,
    BashAnalysis,
    InnerLaunchRequest,
    JudgeRequest,
    LaunchPlan,
    NetworkVerdict,
    ParsedBash,
)

if TYPE_CHECKING:
    from ..policy.models import Profile, ResourceLimits


@runtime_checkable
class BashAuditor(Protocol):
    """M2：bash AST 审计。"""

    def analyze(self, parsed: ParsedBash, ctx: AuditContext) -> BashAnalysis: ...


@runtime_checkable
class PythonAuditor(Protocol):
    """M3：Python 静态审计。"""

    def analyze_source(self, source: str, ctx: AuditContext) -> AuditVerdict: ...


@runtime_checkable
class NetworkAnalyzer(Protocol):
    """网络外发审查：①-⑥ 分流。"""

    def analyze(self, parsed: ParsedBash | None, ctx: AuditContext) -> NetworkVerdict: ...


@runtime_checkable
class SandboxBuilder(Protocol):
    """M4：生成外层/内层 bwrap 与 cgroup 的 LaunchPlan。"""

    def build_outer(self, profile: Profile, profile_path: Path) -> LaunchPlan: ...

    def build_inner(self, profile: Profile, req: InnerLaunchRequest) -> LaunchPlan: ...

    def build_cgroup(self, plan: LaunchPlan, limits: ResourceLimits) -> LaunchPlan: ...


@runtime_checkable
class LlmJudge(Protocol):
    """LLM 兜底判定；超时或无法解析一律按 Deny 处理。"""

    def judge(self, req: JudgeRequest, timeout_s: float) -> JudgeVerdict: ...


__all__ = [
    "BashAuditor",
    "LlmJudge",
    "NetworkAnalyzer",
    "PythonAuditor",
    "SandboxBuilder",
]
