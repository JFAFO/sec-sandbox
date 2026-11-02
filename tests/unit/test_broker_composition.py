"""T4-02 Broker 判定合成、深度控制、异常兜底与审计测试。"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from sec_sandbox.contracts import (
    AuditVerdict,
    BashAnalysis,
    CommandRequest,
    CommandShape,
    Decision,
    ExecutionResult,
    InvocationMode,
    LaunchPlan,
    NetworkDecision,
    NetworkVerdict,
    ReasonCode,
)
from sec_sandbox.gateway.broker import Broker
from sec_sandbox.policy.presets import get_preset


class RecordingAudit:
    def __init__(self) -> None:
        self.events = []

    def append(self, event) -> None:
        self.events.append(event)


class FakeBashAuditor:
    def __init__(self, verdict: AuditVerdict, *, error: bool = False) -> None:
        self.verdict = verdict
        self.error = error

    def analyze(self, parsed, ctx) -> BashAnalysis:
        if self.error:
            raise RuntimeError("boom")
        return BashAnalysis(CommandShape.SIMPLE, self.verdict)


class FakePythonAuditor:
    def __init__(self, verdict: AuditVerdict, *, error: bool = False) -> None:
        self.verdict = verdict
        self.error = error
        self.sources: list[str] = []

    def analyze_source(self, source, ctx) -> AuditVerdict:
        if self.error:
            raise RuntimeError("boom")
        self.sources.append(source)
        return self.verdict


class FakeNetwork:
    def __init__(self, verdict: NetworkVerdict, *, error: bool = False) -> None:
        self.verdict = verdict
        self.error = error

    def analyze(self, parsed, ctx) -> NetworkVerdict:
        if self.error:
            raise RuntimeError("network down")
        return self.verdict


class FakeSandbox:
    def __init__(self, *, error: bool = False) -> None:
        self.error = error
        self.calls = []

    def build_outer(self, profile, profile_path):
        raise AssertionError("Broker 不应调用 build_outer")

    def build_inner(self, profile, req):
        if self.error:
            raise RuntimeError("sandbox boom")
        self.calls.append(req)
        return LaunchPlan(argv=("inner", *req.shell_argv))

    def build_cgroup(self, plan, limits):
        return plan


class FakeExecutor:
    def __init__(self, *, error: bool = False) -> None:
        self.error = error
        self.calls = []

    def run(self, argv, *, env=None, cwd=None, pass_fds=()):
        if self.error:
            raise RuntimeError("exec boom")
        self.calls.append(tuple(argv))
        return ExecutionResult(exit_code=0, signal=None, duration_ms=1)


ALLOW = AuditVerdict(Decision.ALLOW, ReasonCode.SAFE_WHITELISTED)
DOWNGRADE = AuditVerdict(Decision.DOWNGRADE, ReasonCode.NOT_WHITELISTED)
DENY = AuditVerdict(Decision.DENY, ReasonCode.SENSITIVE_PATH)
PASS = NetworkVerdict(NetworkDecision.PASS, ReasonCode.NET_PURE_FETCH)
SKIP = NetworkVerdict(NetworkDecision.SKIP, ReasonCode.NET_UNSUPPORTED_COMMAND)
NET_DENY = NetworkVerdict(NetworkDecision.DENY, ReasonCode.NET_EXFILTRATION)


@pytest.fixture
def profile(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    (tmp_path / "work").mkdir()
    monkeypatch.setenv("HOME", str(home))
    return get_preset("standard", workspace=tmp_path / "work")


def make_broker(
    profile,
    *,
    exec_verdict=ALLOW,
    net_verdict=PASS,
    bash_error=False,
    python_error=False,
    network_error=False,
    executor_error=False,
    sandbox_error=False,
):
    audit = RecordingAudit()
    executor = FakeExecutor(error=executor_error)
    sandbox = FakeSandbox(error=sandbox_error)
    python = FakePythonAuditor(exec_verdict, error=python_error)
    broker = Broker(
        profile,
        FakeBashAuditor(exec_verdict, error=bash_error),
        python,
        FakeNetwork(net_verdict, error=network_error),
        sandbox,
        executor,
        audit,
        real_bash="/usr/bin/real-bash",
        profile_hash="hash",
    )
    return broker, audit, executor, sandbox, python


def request(text="ls", *, mode=InvocationMode.COMMAND_STRING, depth=0, cwd=None):
    return CommandRequest(
        argv=(text,),
        mode=mode,
        command_text=text,
        script_path=None,
        cwd=cwd or Path("/tmp"),
        env={},
        depth=depth,
    )


def test_allow_and_pass_executes_outer(profile):
    broker, audit, executor, sandbox, _ = make_broker(profile)

    code = broker.handle(request())

    assert code == 0
    assert executor.calls == [("/usr/bin/real-bash", "-c", "ls")]
    assert sandbox.calls == []
    assert len(audit.events) == 1
    assert audit.events[0].decision == "allow"


def test_allow_and_network_deny(profile, capsys):
    broker, audit, executor, _, _ = make_broker(profile, net_verdict=NET_DENY)

    code = broker.handle(request())

    assert code == 126
    assert executor.calls == []
    assert "数据外发" in capsys.readouterr().err
    assert audit.events[0].decision == "deny"


def test_downgrade_and_pass_executes_inner(profile):
    broker, audit, executor, sandbox, _ = make_broker(profile, exec_verdict=DOWNGRADE)

    code = broker.handle(request())

    assert code == 0
    assert len(sandbox.calls) == 1
    assert sandbox.calls[0].depth == 1
    assert executor.calls == [("inner", "/usr/bin/real-bash", "-c", "ls")]
    assert audit.events[0].decision == "downgrade"


def test_downgrade_and_network_deny(profile):
    broker, _, executor, _, _ = make_broker(
        profile, exec_verdict=DOWNGRADE, net_verdict=NET_DENY
    )

    assert broker.handle(request()) == 126
    assert executor.calls == []


def test_execution_deny_wins(profile):
    broker, _, executor, _, _ = make_broker(profile, exec_verdict=DENY, net_verdict=SKIP)

    assert broker.handle(request()) == 126
    assert executor.calls == []


def test_allow_and_skip_executes_outer(profile):
    broker, _, executor, _, _ = make_broker(profile, net_verdict=SKIP)

    assert broker.handle(request()) == 0
    assert len(executor.calls) == 1


def test_depth_limit_denied(profile):
    broker, audit, executor, _, _ = make_broker(profile)

    code = broker.handle(request(depth=profile.inner.max_depth + 1))

    assert code == 126
    assert executor.calls == []
    assert audit.events[0].reason == "INNER_NESTING_TOO_DEEP"


def test_bash_analyzer_exception_downgrades(profile):
    broker, audit, executor, sandbox, _ = make_broker(profile, bash_error=True)

    assert broker.handle(request()) == 0
    assert len(sandbox.calls) == 1
    assert audit.events[0].reason == "ANALYZER_ERROR"


def test_network_exception_denies(profile, capsys):
    broker, audit, executor, _, _ = make_broker(profile, network_error=True)

    assert broker.handle(request()) == 126
    assert executor.calls == []
    assert audit.events[0].decision == "deny"


def test_interactive_writes_one_event_and_does_not_execute(profile):
    broker, audit, executor, _, _ = make_broker(profile)

    code = broker.handle(request(None, mode=InvocationMode.INTERACTIVE))

    assert code == 0
    assert executor.calls == []
    assert len(audit.events) == 1
    assert audit.events[0].mode == "interactive"
    assert audit.events[0].command_class is None


def test_deny_rule_applies_before_classification(profile, capsys):
    broker, audit, executor, _, _ = make_broker(profile)

    code = broker.handle(request("rm -rf /"))

    assert code == 126
    assert executor.calls == []
    assert audit.events[0].rule_ids == ("B1.RM",)


def test_python_c_source_is_analyzed(profile):
    broker, _, _, _, python = make_broker(profile)

    assert broker.handle(request('python3 -c "print(1)"')) == 0
    assert python.sources == ["print(1)"]


def test_python_script_source_is_read(profile, tmp_path):
    script = tmp_path / "app.py"
    script.write_text("print(2)\n", encoding="utf-8")
    broker, _, _, _, python = make_broker(profile)

    assert broker.handle(request(f"python3 {script}")) == 0
    assert python.sources == ["print(2)\n"]


def test_python_script_too_large_denied(profile, tmp_path):
    script = tmp_path / "big.py"
    script.write_text("x" * 50, encoding="utf-8")
    small = replace(profile, python=replace(profile.python, max_source_bytes=10))
    broker, audit, executor, _, _ = make_broker(small)

    assert broker.handle(request(f"python3 {script}")) == 126
    assert executor.calls == []
    assert audit.events[0].reason == "INPUT_TOO_LARGE"


def test_internal_error_returns_127(profile):
    broker, audit, executor, _, _ = make_broker(profile, sandbox_error=True, exec_verdict=DOWNGRADE)

    code = broker.handle(request())

    assert code == 127
    assert executor.calls == []
    assert audit.events[0].reason == "INTERNAL_ERROR"


def test_each_non_interactive_call_writes_exactly_one_event(profile):
    broker, audit, _, _, _ = make_broker(profile)

    broker.handle(request("ls"))
    broker.handle(request("ls | grep x"))

    assert len(audit.events) == 2
    assert {event.source for event in audit.events} == {"gateway"}
    assert all(event.profile_hash == "hash" for event in audit.events)
