"""三类路由与交互模式判定（《实现级架构设计》§2.3）。

铁律：**拿不准一律类 3**。只有能证明"纯 bash utility 且全部命中白名单"或
"纯 python 且通过类 2 准入"时才不走内层沙箱。

本模块只做路由，不执行 Deny 规则；Deny 判定由 Broker 在分类前统一执行。
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ..bash_audit.astutil import command_argv
from ..bash_audit.parser import parse
from ..bash_audit.rules import RuleSet, is_allowlisted
from ..contracts import (
    AuditContext,
    CommandClass,
    CommandRequest,
    InvocationMode,
    ReasonCode,
)
from ..policy.models import Profile
from ..python_audit.static import is_python_invocation


@dataclass(frozen=True)
class Classification:
    """路由结果；交互模式 ``command_class`` 为 ``None``。"""

    command_class: CommandClass | None
    reason: ReasonCode


def classify_request(
    request: CommandRequest,
    profile: Profile,
    *,
    home: Path | None = None,
) -> Classification:
    """把一次网关调用路由到类 1 / 类 2 / 类 3 或交互模式。"""
    if request.mode is InvocationMode.INTERACTIVE:
        return Classification(None, ReasonCode.INTERACTIVE_SHELL)
    if request.mode is InvocationMode.SCRIPT:
        return Classification(CommandClass.SANDBOXED, ReasonCode.SCRIPT_DEFAULT_DOWNGRADE)
    if request.mode is InvocationMode.UNKNOWN:
        return Classification(CommandClass.SANDBOXED, ReasonCode.NOT_WHITELISTED)

    text = request.command_text
    if text is None:
        return Classification(CommandClass.SANDBOXED, ReasonCode.NOT_WHITELISTED)

    parsed = parse(text)
    if not parsed.ok:
        return Classification(CommandClass.SANDBOXED, ReasonCode.PARSE_FAILED)

    if _is_pure_python(parsed, profile):
        return Classification(CommandClass.PYTHON_SCRIPT, ReasonCode.PYTHON_STATIC_OK)

    context = AuditContext(
        cwd=request.cwd,
        home=home if home is not None else Path.home(),
        workspace=profile.workspace,
    )
    if is_allowlisted(parsed, context, RuleSet.from_profile(profile)):
        return Classification(CommandClass.BASH_UTILITY, ReasonCode.SAFE_WHITELISTED)

    return Classification(CommandClass.SANDBOXED, ReasonCode.NOT_WHITELISTED)


def _is_pure_python(parsed, profile: Profile) -> bool:
    """恰为单个字面量命令，且是允许的解释器 + 合规调用形式。"""
    if len(parsed.nodes) != 1:
        return False
    node = parsed.nodes[0]
    if getattr(node, "kind", None) != "command":
        return False
    argv = command_argv(node)
    return argv is not None and is_python_invocation(argv, profile)
