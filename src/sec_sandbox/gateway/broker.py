"""M1 Broker：分类、判定合成、深度控制、执行与审计（§2.3、§4.3）。

判定合成表：

====================  ====================  ==================
执行判定               网络判定               结果
====================  ====================  ==================
ALLOW                 PASS / SKIP           外层 real-bash 执行
ALLOW                 DENY                  Deny 126
DOWNGRADE             PASS / SKIP           内层 bwrap 执行
DOWNGRADE             DENY                  Deny 126
DENY                  任意                  Deny 126
====================  ====================  ==================

执行线异常 → DOWNGRADE；网络线异常 → DENY。``handle`` 绝不抛异常。
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import traceback
from pathlib import Path

from ..bash_audit.astutil import command_argv
from ..bash_audit.parser import parse
from ..bash_audit.rules import RuleSet, find_deny
from ..policy.builtin.sensitive_paths import SENSITIVE_PATH_PATTERNS
from ..contracts import (
    AuditContext,
    AuditVerdict,
    BashAnalysis,
    CommandClass,
    CommandRequest,
    Decision,
    ExecutionResult,
    InnerLaunchRequest,
    InvocationMode,
    LaunchPlan,
    NetworkDecision,
    NetworkVerdict,
    ParsedBash,
    ReasonCode,
)
from ..policy.models import Profile
from ..util import logging as internal_log
from .audit_log import AuditEvent, AuditLog
from .classifier import Classification, classify_request
from .executor import Executor
from .messages import INTERNAL_ERROR, message_for

_DENY_EXIT = 126
_INTERNAL_EXIT = 127
_DEFAULT_REAL_BASH = "/usr/bin/real-bash"
_SITECUSTOMIZE_DIR = Path(__file__).resolve().parents[1] / "python_audit"
_SRC_DIR = Path(__file__).resolve().parents[2]


class Broker:
    """单条网关调用的调度器；依赖全部由组合根注入。"""

    def __init__(
        self,
        profile: Profile,
        bash_auditor: object,
        python_auditor: object,
        network_analyzer: object,
        sandbox: object,
        executor: Executor,
        audit: AuditLog,
        *,
        real_bash: str | None = None,
        profile_hash: str = "",
    ) -> None:
        self.profile = profile
        self.bash_auditor = bash_auditor
        self.python_auditor = python_auditor
        self.network_analyzer = network_analyzer
        self.sandbox = sandbox
        self.executor = executor
        self.audit = audit
        self.real_bash = real_bash or os.environ.get("SECSAND_REAL_BASH", _DEFAULT_REAL_BASH)
        self.profile_hash = profile_hash

    def handle(self, req: CommandRequest) -> int:
        """处理一次调用并返回退出码；任何异常都转为 127。"""
        try:
            return self._handle(req)
        except Exception:  # noqa: BLE001 - 契约要求绝不抛异常
            internal_log.debug(traceback.format_exc())
            self._write_event(
                req,
                decision=Decision.DENY,
                reason=ReasonCode.INTERNAL_ERROR,
                error=type(sys.exc_info()[1]).__name__,
                exit_code=_INTERNAL_EXIT,
            )
            print(INTERNAL_ERROR, file=sys.stderr)
            return _INTERNAL_EXIT

    def _handle(self, req: CommandRequest) -> int:
        if req.depth > self.profile.inner.max_depth:
            return self._deny(
                req, ReasonCode.INNER_NESTING_TOO_DEEP, command_class=None
            )

        classification = classify_request(req, self.profile)
        if classification.command_class is None:
            self._write_event(
                req,
                decision=Decision.ALLOW,
                reason=ReasonCode.INTERACTIVE_SHELL,
                mode="interactive",
                command_class=None,
                exit_code=0,
            )
            return 0

        ctx = AuditContext(
            cwd=req.cwd,
            home=Path.home(),
            workspace=self.profile.workspace,
        )
        parsed = _parse_request(req)

        deny = find_deny(parsed, ctx, RuleSet.from_profile(self.profile))
        if deny is not None:
            return self._deny(
                req,
                deny.reason,
                command_class=classification.command_class,
                rule_ids=deny.rule_ids,
            )

        exec_verdict = self._execution_verdict(req, classification.command_class, parsed, ctx)
        if exec_verdict.decision is Decision.DENY:
            return self._deny(
                req,
                exec_verdict.reason,
                command_class=classification.command_class,
                rule_ids=exec_verdict.rule_ids,
            )

        network = self._network_verdict(parsed, ctx)
        if network.decision is NetworkDecision.DENY:
            return self._deny(
                req,
                network.reason,
                command_class=classification.command_class,
                network=network,
            )

        if exec_verdict.decision is Decision.ALLOW:
            return self._execute_outer(req, exec_verdict, network, classification)

        return self._execute_inner(req, exec_verdict, network, classification)

    def _execution_verdict(
        self,
        req: CommandRequest,
        command_class: CommandClass,
        parsed: ParsedBash,
        ctx: AuditContext,
    ) -> AuditVerdict:
        if command_class is CommandClass.BASH_UTILITY:
            return self._bash_verdict(parsed, ctx)
        if command_class is CommandClass.PYTHON_SCRIPT:
            return self._python_verdict(req, ctx)
        return AuditVerdict(Decision.DOWNGRADE, ReasonCode.NOT_WHITELISTED)

    def _bash_verdict(self, parsed: ParsedBash, ctx: AuditContext) -> AuditVerdict:
        try:
            analysis: BashAnalysis = self.bash_auditor.analyze(parsed, ctx)
            return analysis.verdict
        except Exception:  # noqa: BLE001 - 执行线异常降级
            internal_log.debug(traceback.format_exc())
            return AuditVerdict(Decision.DOWNGRADE, ReasonCode.ANALYZER_ERROR)

    def _python_verdict(self, req: CommandRequest, ctx: AuditContext) -> AuditVerdict:
        source, error = _python_source(req, self.profile)
        if error == "too_large":
            return AuditVerdict(Decision.DENY, ReasonCode.INPUT_TOO_LARGE)
        if source is None:
            return AuditVerdict(Decision.DOWNGRADE, ReasonCode.NOT_WHITELISTED)
        try:
            return self.python_auditor.analyze_source(source, ctx)
        except Exception:  # noqa: BLE001
            internal_log.debug(traceback.format_exc())
            return AuditVerdict(Decision.DOWNGRADE, ReasonCode.ANALYZER_ERROR)

    def _network_verdict(self, parsed: ParsedBash, ctx: AuditContext) -> NetworkVerdict:
        if self.network_analyzer is None:
            return NetworkVerdict(NetworkDecision.SKIP, ReasonCode.NET_UNSUPPORTED_COMMAND)
        try:
            return self.network_analyzer.analyze(parsed, ctx)
        except Exception:  # noqa: BLE001 - 网络线异常必须 fail-closed
            internal_log.debug(traceback.format_exc())
            return NetworkVerdict(NetworkDecision.DENY, ReasonCode.NET_UNSUPPORTED_COMMAND)

    def _execute_outer(
        self,
        req: CommandRequest,
        verdict: AuditVerdict,
        network: NetworkVerdict,
        classification: Classification,
    ) -> int:
        argv = _shell_argv(req, self.real_bash)
        env = req.env
        policy_file: Path | None = None

        if classification.command_class is CommandClass.PYTHON_SCRIPT:
            policy_file = _write_runtime_policy(self.profile, self.audit)
            existing = req.env.get("PYTHONPATH", "")
            pythonpath = os.pathsep.join([str(_SITECUSTOMIZE_DIR), str(_SRC_DIR)])
            if existing:
                pythonpath = pythonpath + os.pathsep + existing
            env = {
                **req.env,
                "SECSAND_RUNTIME_POLICY": str(policy_file),
                "PYTHONPATH": pythonpath,
            }

        try:
            result = self.executor.run(argv, env=env, cwd=req.cwd)
        finally:
            if policy_file is not None:
                policy_file.unlink(missing_ok=True)

        self._write_executed(req, verdict, network, classification, result, Decision.ALLOW)
        return result.exit_code

    def _execute_inner(
        self,
        req: CommandRequest,
        verdict: AuditVerdict,
        network: NetworkVerdict,
        classification: Classification,
    ) -> int:
        plan: LaunchPlan = self.sandbox.build_inner(
            self.profile,
            InnerLaunchRequest(
                shell_argv=_shell_argv(req, self.real_bash),
                cwd=req.cwd,
                depth=req.depth + 1,
            ),
        )
        result = self.executor.run(
            plan.argv,
            env={**req.env, **plan.env},
            cwd=req.cwd,
            pass_fds=plan.pass_fds,
        )
        self._write_executed(
            req, verdict, network, classification, result, Decision.DOWNGRADE
        )
        return result.exit_code

    def _deny(
        self,
        req: CommandRequest,
        reason: ReasonCode,
        *,
        command_class: CommandClass | None,
        rule_ids: tuple[str, ...] = (),
        network: NetworkVerdict | None = None,
    ) -> int:
        print(message_for(reason) or INTERNAL_ERROR, file=sys.stderr)
        self._write_event(
            req,
            decision=Decision.DENY,
            reason=reason,
            command_class=command_class,
            rule_ids=rule_ids,
            network=network,
            exit_code=_DENY_EXIT,
        )
        return _DENY_EXIT

    def _write_executed(
        self,
        req: CommandRequest,
        verdict: AuditVerdict,
        network: NetworkVerdict,
        classification: Classification,
        result: ExecutionResult,
        decision: Decision,
    ) -> None:
        self._write_event(
            req,
            decision=decision,
            reason=verdict.reason,
            command_class=classification.command_class,
            rule_ids=verdict.rule_ids,
            network=network,
            exit_code=result.exit_code,
            signal=result.signal,
            duration_ms=result.duration_ms,
        )

    def _write_event(
        self,
        req: CommandRequest,
        *,
        decision: Decision,
        reason: ReasonCode,
        command_class: CommandClass | None = None,
        rule_ids: tuple[str, ...] = (),
        network: NetworkVerdict | None = None,
        mode: str | None = None,
        exit_code: int | None = None,
        signal: int | None = None,
        duration_ms: int = 0,
        error: str | None = None,
    ) -> None:
        self.audit.append(
            AuditEvent(
                source="gateway",
                decision=decision.value,
                reason=reason.value,
                mode=mode if mode is not None else req.mode.value,
                command_class=command_class.value if command_class is not None else None,
                rule_ids=rule_ids,
                depth=req.depth,
                network=_network_record(network),
                command_text=req.command_text,
                exit_code=exit_code,
                signal=signal,
                duration_ms=duration_ms,
                profile_hash=self.profile_hash,
                error=error,
            )
        )


def _write_runtime_policy(profile: Profile, audit: object) -> Path:
    """按 §5.3 生成类 2 运行时策略临时文件（0600）。"""
    audit_path = getattr(audit, "path", Path("/tmp/secsand-audit.jsonl"))
    payload = {
        "sensitive_patterns": list(SENSITIVE_PATH_PATTERNS),
        "sensitive_dirs": [],
        "workspace": str(profile.workspace),
        "safe_domains": list(profile.network.safe_domains),
        "audit_log": str(audit_path),
        "pid": os.getpid(),
    }
    fd, name = tempfile.mkstemp(prefix="secsand-policy-", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False)
        os.chmod(name, 0o600)
    except Exception:
        Path(name).unlink(missing_ok=True)
        raise
    return Path(name)


def _parse_request(req: CommandRequest) -> ParsedBash:
    if req.command_text is None:
        return ParsedBash(text="", nodes=(), ok=False, error="no text")
    return parse(req.command_text)


def _shell_argv(req: CommandRequest, real_bash: str) -> tuple[str, ...]:
    if req.mode is InvocationMode.SCRIPT and req.script_path is not None:
        return (real_bash, str(req.script_path))
    if req.mode is InvocationMode.UNKNOWN:
        return (real_bash, *req.argv)
    return (real_bash, "-c", req.command_text or "")


def _python_source(
    req: CommandRequest,
    profile: Profile,
) -> tuple[str | None, str | None]:
    """从类 2 调用中取出 Python 源码；返回 ``(source, error)``。"""
    parsed = _parse_request(req)
    if not parsed.ok or not parsed.nodes:
        return None, "invalid"
    argv = command_argv(parsed.nodes[0])
    if argv is None:
        return None, "invalid"

    if "-c" in argv:
        index = argv.index("-c")
        if index + 1 >= len(argv):
            return None, "invalid"
        return argv[index + 1], None

    if len(argv) < 2:
        return None, "invalid"
    script = Path(argv[1])
    if not script.is_absolute():
        script = req.cwd / script
    try:
        if script.stat().st_size > profile.python.max_source_bytes:
            return None, "too_large"
        data = script.read_bytes()
    except OSError:
        return None, "unreadable"
    if len(data) > profile.python.max_source_bytes:
        return None, "too_large"
    return data.decode("utf-8", errors="replace"), None


def _network_record(network: NetworkVerdict | None) -> dict[str, object] | None:
    if network is None:
        return None
    return {
        "decision": network.decision.value,
        "reason": network.reason.value,
        "consulted_llm": network.consulted_llm,
    }
