"""``BashAuditor`` 实现：规则匹配 → ``BashAnalysis``（§4.4）。"""

from __future__ import annotations

from ..contracts import (
    AuditContext,
    AuditVerdict,
    BashAnalysis,
    CommandShape,
    Decision,
    ParsedBash,
    ReasonCode,
)
from .classifier import classify
from .rules import RuleSet, find_deny, is_allowlisted


class BashAnalyzer:
    """类 1 审计器；规则集由组合根从 profile 注入。"""

    def __init__(self, rules: RuleSet | None = None) -> None:
        self.rules = rules if rules is not None else RuleSet()

    def analyze(self, parsed: ParsedBash, ctx: AuditContext) -> BashAnalysis:
        shape = classify(parsed)

        deny = find_deny(parsed, ctx, self.rules)
        if deny is not None:
            return BashAnalysis(shape=shape, verdict=deny)

        if shape is CommandShape.UNPARSEABLE:
            return _result(shape, ReasonCode.PARSE_FAILED)
        if shape is CommandShape.COMPOUND:
            return _result(shape, ReasonCode.COMPOUND_COMMAND)
        if is_allowlisted(parsed, ctx, self.rules):
            return _result(shape, ReasonCode.SAFE_WHITELISTED, Decision.ALLOW)
        return _result(shape, ReasonCode.NOT_WHITELISTED)


def _result(
    shape: CommandShape,
    reason: ReasonCode,
    decision: Decision = Decision.DOWNGRADE,
) -> BashAnalysis:
    return BashAnalysis(shape=shape, verdict=AuditVerdict(decision, reason))
