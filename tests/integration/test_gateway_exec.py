"""T4-08 网关集成测试：真实 Popen + 假 SandboxBuilder。"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sec_sandbox.bash_audit.analyzer import BashAnalyzer
from sec_sandbox.bash_audit.rules import RuleSet
from sec_sandbox.contracts import (
    CommandRequest,
    InvocationMode,
    LaunchPlan,
)
from sec_sandbox.gateway.audit_log import AuditLog
from sec_sandbox.gateway.broker import Broker
from sec_sandbox.gateway.executor import Executor
from sec_sandbox.netpolicy.analyzer import NetworkAnalyzerImpl, NetworkRules
from sec_sandbox.policy.presets import get_preset
from sec_sandbox.python_audit.static import PythonStaticAuditor


class FakeSandbox:
    def __init__(self) -> None:
        self.calls = []

    def build_outer(self, profile, profile_path):
        raise AssertionError("Broker 不应调用 build_outer")

    def build_inner(self, profile, req):
        self.calls.append(req)
        return LaunchPlan(argv=("/bin/bash", *req.shell_argv))

    def build_cgroup(self, plan, limits):
        return plan


@pytest.fixture
def gateway(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.setenv("HOME", str(home))

    profile = get_preset("standard", workspace=work)
    audit_path = tmp_path / "state" / "audit.jsonl"
    sandbox = FakeSandbox()
    broker = Broker(
        profile,
        BashAnalyzer(RuleSet.from_profile(profile)),
        PythonStaticAuditor(),
        NetworkAnalyzerImpl(NetworkRules.from_profile(profile)),
        sandbox,
        Executor(profile.bash.trusted_path),
        AuditLog(audit_path),
        real_bash="/bin/bash",
        profile_hash="test",
    )
    return broker, audit_path, sandbox, work


def make_request(text, *, cwd: Path, mode=InvocationMode.COMMAND_STRING, depth=0):
    return CommandRequest(
        argv=(text,),
        mode=mode,
        command_text=text,
        script_path=None,
        cwd=cwd,
        env={},
        depth=depth,
    )


def read_events(path: Path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_allow_executes_real_process(gateway):
    broker, audit_path, sandbox, work = gateway

    assert broker.handle(make_request("ls", cwd=work)) == 0

    assert sandbox.calls == []
    events = read_events(audit_path)
    assert len(events) == 1
    assert events[0]["decision"] == "allow"
    assert events[0]["class"] == "bash_utility"


def test_deny_does_not_produce_side_effect(gateway):
    broker, audit_path, sandbox, work = gateway
    marker = Path.home() / ".ssh" / "marker"

    assert broker.handle(make_request("touch ~/.ssh/marker", cwd=work)) == 126

    assert not marker.exists()
    assert sandbox.calls == []
    event = read_events(audit_path)[0]
    assert event["decision"] == "deny"
    assert event["reason"] == "SENSITIVE_PATH"


def test_downgrade_executes_through_inner(gateway):
    broker, audit_path, sandbox, work = gateway

    code = broker.handle(make_request("ls | grep x", cwd=work))

    assert code in {0, 1}
    assert len(sandbox.calls) == 1
    event = read_events(audit_path)[0]
    assert event["decision"] == "downgrade"
    assert event["class"] == "sandboxed"


def test_depth_limit_denied(gateway):
    broker, audit_path, _, work = gateway
    profile_depth = broker.profile.inner.max_depth

    assert broker.handle(make_request("ls", cwd=work, depth=profile_depth + 1)) == 126

    event = read_events(audit_path)[0]
    assert event["reason"] == "INNER_NESTING_TOO_DEEP"


def test_python_class2_allowed(gateway):
    broker, audit_path, sandbox, work = gateway

    assert broker.handle(make_request('python3 -c "print(1)"', cwd=work)) == 0

    assert sandbox.calls == []
    event = read_events(audit_path)[0]
    assert event["class"] == "python_script"
    assert event["decision"] == "allow"


def test_python_runtime_hook_blocks_sensitive_open(gateway):
    broker, _, _, work = gateway
    env_file = work / ".env"

    code = "open('.env', 'w')"
    result = broker.handle(make_request(f'python3 -c "{code}"', cwd=work))

    assert result != 0
    assert not env_file.exists()


def test_network_deny_does_not_execute(gateway):
    broker, audit_path, sandbox, work = gateway

    assert broker.handle(make_request("curl http://127.0.0.1/admin", cwd=work)) == 126

    assert sandbox.calls == []
    event = read_events(audit_path)[0]
    assert event["decision"] == "deny"
    assert event["network"]["decision"] == "deny"
