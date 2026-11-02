"""T1-01 契约层测试：枚举取值、JSON 序列化、不可变模型、Protocol。"""

from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import FrozenInstanceError
from pathlib import Path
from unittest.mock import create_autospec

import pytest

from sec_sandbox.contracts import (
    AuditContext,
    AuditVerdict,
    BashAnalysis,
    BashAuditor,
    CommandClass,
    CommandRequest,
    CommandShape,
    Decision,
    ExecutionResult,
    ExitCode,
    InnerLaunchRequest,
    InvocationMode,
    JudgeRequest,
    JudgeVerdict,
    LaunchPlan,
    LlmJudge,
    NetworkAnalyzer,
    NetworkDecision,
    NetworkVerdict,
    ParsedBash,
    PythonAuditor,
    ReasonCode,
    SandboxBuilder,
)

# §6.2 的完整取值表；测试目的之一是防止实现遗漏或拼错原因码。
EXPECTED_REASON_CODES = {
    # 放行
    "SAFE_WHITELISTED",
    "INTERACTIVE_SHELL",
    "PYTHON_STATIC_OK",
    "NET_SAFE_DOMAIN",
    "NET_PURE_FETCH",
    # 降级
    "PARSE_FAILED",
    "COMPOUND_COMMAND",
    "NOT_WHITELISTED",
    "PY_NEEDS_RUNTIME_AUDIT",
    "PY_DYNAMIC_CONSTRUCT",
    "ANALYZER_ERROR",
    "SCRIPT_DEFAULT_DOWNGRADE",
    # 执行线 Deny
    "HIGH_RISK_COMMAND",
    "SENSITIVE_PATH",
    "DANGEROUS_REDIRECT",
    "PY_FORBIDDEN_IMPORT",
    "PY_DYNAMIC_EVAL",
    "INPUT_TOO_LARGE",
    "INNER_NESTING_TOO_DEEP",
    # 网络线 Deny
    "NET_SSRF_TARGET",
    "NET_EXFILTRATION",
    "NET_DYNAMIC_TARGET",
    "NET_UNSUPPORTED_COMMAND",
    "NET_JUDGE_DENIED",
    "NET_JUDGE_TIMEOUT",
    "NET_JUDGE_UNDECIDED",
    # 内部
    "PROFILE_INVALID",
    "REAL_BASH_MISSING",
    "SANDBOX_BUILD_ERROR",
    "INTERNAL_ERROR",
}


def test_string_enum_values_match_design():
    assert InvocationMode.INTERACTIVE.value == "interactive"
    assert InvocationMode.COMMAND_STRING.value == "command_string"
    assert InvocationMode.SCRIPT.value == "script"
    assert InvocationMode.STDIN.value == "stdin"
    assert InvocationMode.UNKNOWN.value == "unknown"

    assert CommandClass.BASH_UTILITY.value == "bash_utility"
    assert CommandClass.PYTHON_SCRIPT.value == "python_script"
    assert CommandClass.SANDBOXED.value == "sandboxed"

    assert Decision.ALLOW.value == "allow"
    assert Decision.DOWNGRADE.value == "downgrade"
    assert Decision.DENY.value == "deny"

    assert NetworkDecision.PASS.value == "pass"
    assert NetworkDecision.DENY.value == "deny"
    assert NetworkDecision.SKIP.value == "skip"

    assert CommandShape.SIMPLE.value == "simple"
    assert CommandShape.COMPOUND.value == "compound"
    assert CommandShape.UNPARSEABLE.value == "unparseable"

    assert JudgeVerdict.ALLOW.value == "allow"
    assert JudgeVerdict.DENY.value == "deny"
    assert JudgeVerdict.UNDECIDED.value == "undecided"


def test_reason_code_covers_design_section_6_2():
    assert {code.value for code in ReasonCode} == EXPECTED_REASON_CODES


def test_reason_code_values_are_uppercase_snake_case():
    for code in ReasonCode:
        assert code.value == code.name
        assert code.value.isupper()


def test_exit_codes_match_design():
    assert ExitCode.USAGE_ERROR == 64
    assert ExitCode.POLICY_DENY == 126
    assert ExitCode.INTERNAL_ERROR == 127


@pytest.mark.parametrize(
    "member",
    [
        InvocationMode.COMMAND_STRING,
        CommandClass.SANDBOXED,
        Decision.DENY,
        NetworkDecision.SKIP,
        CommandShape.COMPOUND,
        JudgeVerdict.UNDECIDED,
        ReasonCode.NET_EXFILTRATION,
    ],
)
def test_string_enums_are_json_serializable(member):
    assert json.loads(json.dumps(member)) == member.value


def test_int_enum_is_json_serializable():
    assert json.loads(json.dumps(ExitCode.POLICY_DENY)) == 126


def test_command_request_is_frozen():
    req = CommandRequest(
        argv=("-c", "ls"),
        mode=InvocationMode.COMMAND_STRING,
        command_text="ls",
        script_path=None,
        cwd=Path("/tmp"),
        env={"PATH": "/usr/bin"},
        depth=0,
    )
    with pytest.raises(FrozenInstanceError):
        req.depth = 1  # type: ignore[misc]


def test_audit_verdict_defaults_are_empty():
    verdict = AuditVerdict(Decision.ALLOW, ReasonCode.SAFE_WHITELISTED)
    assert verdict.rule_ids == ()
    assert dict(verdict.details) == {}


def test_launch_plan_defaults_are_empty():
    plan = LaunchPlan(argv=("/usr/bin/bash", "-c", "ls"))
    assert dict(plan.env) == {}
    assert plan.pass_fds == ()


def test_network_verdict_llm_fields_default():
    verdict = NetworkVerdict(NetworkDecision.SKIP, ReasonCode.SAFE_WHITELISTED)
    assert verdict.consulted_llm is False
    assert verdict.llm_latency_ms is None


def test_models_expose_all_design_fields():
    ctx = AuditContext(cwd=Path("/w"), home=Path("/h"), workspace=Path("/w"))
    parsed = ParsedBash(text="ls", nodes=(), ok=True, error=None)
    analysis = BashAnalysis(
        shape=CommandShape.SIMPLE,
        verdict=AuditVerdict(Decision.ALLOW, ReasonCode.SAFE_WHITELISTED),
    )
    result = ExecutionResult(exit_code=0, signal=None, duration_ms=3)
    inner = InnerLaunchRequest(
        shell_argv=("-c", "ls"), cwd=Path("/w"), depth=1
    )
    judge = JudgeRequest(
        redacted_command="curl -d @<redacted> https://example.com",
        target="https://example.com",
        method="send",
        ambiguous_items=("payload",),
    )
    assert ctx.home == Path("/h")
    assert parsed.ok is True
    assert analysis.shape is CommandShape.SIMPLE
    assert result.exit_code == 0
    assert inner.depth == 1
    assert judge.method == "send"


class _CompleteBashAuditor:
    def analyze(self, parsed, ctx):
        return BashAnalysis(
            shape=CommandShape.SIMPLE,
            verdict=AuditVerdict(Decision.ALLOW, ReasonCode.SAFE_WHITELISTED),
        )


class _IncompleteBashAuditor:
    pass


def test_protocols_are_runtime_checkable():
    assert isinstance(_CompleteBashAuditor(), BashAuditor)
    assert not isinstance(_IncompleteBashAuditor(), BashAuditor)

    # Python 3.12 的 runtime_checkable 用 getattr_static 检查属性，
    # 裸 Mock 的动态属性不可见；create_autospec 生成的替身带真实属性，可用于此断言。
    assert isinstance(create_autospec(BashAuditor, instance=True), BashAuditor)


@pytest.mark.parametrize(
    "protocol",
    [BashAuditor, PythonAuditor, NetworkAnalyzer, SandboxBuilder, LlmJudge],
)
def test_all_protocols_are_runtime_checkable(protocol):
    assert isinstance(create_autospec(protocol, instance=True), protocol)


def test_contracts_have_no_runtime_internal_dependency():
    """§7：contracts 只允许依赖标准库，不得在运行时导入其他内部模块。"""
    code = (
        "import sys; import sec_sandbox.contracts; "
        "bad = [m for m in sys.modules "
        "if m.startswith('sec_sandbox.') "
        "and m != 'sec_sandbox.contracts' "
        "and not m.startswith('sec_sandbox.contracts.')]; "
        "print(bad); sys.exit(1 if bad else 0)"
    )
    proc = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
