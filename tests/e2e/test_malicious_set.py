"""T7-01/T7-02 恶意用例集驱动与拦截率/误报率统计。"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sec_sandbox.bash_audit.analyzer import BashAnalyzer
from sec_sandbox.bash_audit.rules import RuleSet
from sec_sandbox.contracts import (
    AuditVerdict,
    CommandRequest,
    ExecutionResult,
    LaunchPlan,
)
from sec_sandbox.gateway.audit_log import AuditEvent
from sec_sandbox.gateway.broker import Broker
from sec_sandbox.gateway.parser import parse_invocation
from sec_sandbox.netpolicy.analyzer import NetworkAnalyzerImpl, NetworkRules
from sec_sandbox.policy.presets import get_preset
from sec_sandbox.python_audit.static import PythonStaticAuditor

CASES_FILE = Path(__file__).resolve().parents[1] / "cases" / "cases.json"


class RecordingAudit:
    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def append(self, event: AuditEvent) -> None:
        self.events.append(event)


class FakeSandbox:
    def build_outer(self, profile, profile_path):
        raise AssertionError("用例驱动不应构建外层")

    def build_inner(self, profile, req):
        return LaunchPlan(argv=("/bin/true",))

    def build_cgroup(self, plan, limits):
        return plan


class FakeExecutor:
    def __init__(self) -> None:
        self.calls: list[tuple[str, ...]] = []

    def run(self, argv, *, env=None, cwd=None, pass_fds=()):
        self.calls.append(tuple(argv))
        return ExecutionResult(exit_code=0, signal=None, duration_ms=0)


def load_cases() -> list[dict]:
    return json.loads(CASES_FILE.read_text(encoding="utf-8"))


@pytest.fixture
def workspace(tmp_path, monkeypatch) -> Path:
    home = tmp_path / "home"
    home.mkdir()
    work = tmp_path / "work"
    work.mkdir()
    (work / "README.md").write_text("hello\n", encoding="utf-8")
    (work / ".env").write_text("TOKEN=secret\n", encoding="utf-8")
    (work / "script.py").write_text("print('ok')\n", encoding="utf-8")
    (work / "build").mkdir()
    monkeypatch.setenv("HOME", str(home))
    return work


def run_case(case: dict, workspace: Path) -> tuple[str, str, str]:
    profile = get_preset("standard", workspace=workspace)
    audit = RecordingAudit()
    broker = Broker(
        profile,
        BashAnalyzer(RuleSet.from_profile(profile)),
        PythonStaticAuditor(),
        NetworkAnalyzerImpl(NetworkRules.from_profile(profile)),
        FakeSandbox(),
        FakeExecutor(),
        audit,
        real_bash="/bin/true",
        profile_hash="cases",
    )
    request = parse_invocation(
        ["-c", case["command"]],
        stdin_is_tty=False,
        max_input_bytes=profile.bash.max_script_bytes,
        cwd=workspace,
        env={},
        stdin=None,
    )
    broker.handle(request)
    event = audit.events[-1]
    network = "skip"
    if event.network is not None:
        network = str(event.network["decision"])
    return event.command_class or "sandboxed", event.decision, network


def test_cases_have_required_fields():
    cases = load_cases()
    assert cases
    ids = [case["id"] for case in cases]
    assert len(ids) == len(set(ids))
    for case in cases:
        assert {
            "id",
            "tags",
            "command",
            "expect_class",
            "expect_decision",
            "expect_network",
            "reason_category",
        } <= set(case)


def test_malicious_set_results(workspace):
    cases = load_cases()
    failures: list[str] = []

    for case in cases:
        actual_class, actual_decision, actual_network = run_case(case, workspace)
        if (
            actual_class != case["expect_class"]
            or actual_decision != case["expect_decision"]
            or actual_network != case["expect_network"]
        ):
            failures.append(
                f"{case['id']}: got {actual_class}/{actual_decision}/{actual_network}, "
                f"want {case['expect_class']}/{case['expect_decision']}/{case['expect_network']}"
            )

    assert not failures, "\n".join(failures)


def test_block_and_false_positive_rates(workspace, capsys):
    cases = load_cases()
    malicious = [case for case in cases if "malicious" in case["tags"]]
    benign = [case for case in cases if "benign" in case["tags"]]

    denied_malicious = sum(
        run_case(case, workspace)[1] == "deny" for case in malicious
    )
    denied_benign = sum(run_case(case, workspace)[1] == "deny" for case in benign)

    block_rate = denied_malicious / len(malicious)
    false_positive_rate = denied_benign / len(benign)
    report = {
        "malicious_total": len(malicious),
        "malicious_denied": denied_malicious,
        "normal_total": len(benign),
        "normal_false_positive": denied_benign,
        "block_rate": block_rate,
        "false_positive_rate": false_positive_rate,
        "environment": "wsl-development",
    }
    print(json.dumps(report, ensure_ascii=False))

    assert block_rate == 1.0
    assert false_positive_rate == 0.0
    assert "block_rate" in capsys.readouterr().out
