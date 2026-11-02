"""T4-01 三类分类器测试（§2.3）。"""

from __future__ import annotations

from pathlib import Path

import pytest

from sec_sandbox.contracts import (
    CommandClass,
    CommandRequest,
    InvocationMode,
    ReasonCode,
)
from sec_sandbox.gateway.classifier import Classification, classify_request
from sec_sandbox.policy.presets import get_preset


@pytest.fixture
def profile(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    return get_preset("standard", workspace=tmp_path / "work")


def make_request(
    text: str | None,
    *,
    mode: InvocationMode = InvocationMode.COMMAND_STRING,
    cwd: Path | None = None,
) -> CommandRequest:
    return CommandRequest(
        argv=(() if text is None else (text,)),
        mode=mode,
        command_text=text,
        script_path=None,
        cwd=cwd or Path("/tmp"),
        env={},
        depth=0,
    )


def classify(text: str, profile, **kwargs) -> Classification:
    return classify_request(make_request(text, **kwargs), profile)


def test_interactive_mode(profile):
    result = classify_request(
        make_request(None, mode=InvocationMode.INTERACTIVE), profile
    )
    assert result.command_class is None
    assert result.reason is ReasonCode.INTERACTIVE_SHELL


def test_script_mode_defaults_to_class3(profile):
    result = classify_request(
        make_request("print(1)", mode=InvocationMode.SCRIPT), profile
    )
    assert result.command_class is CommandClass.SANDBOXED
    assert result.reason is ReasonCode.SCRIPT_DEFAULT_DOWNGRADE


def test_unknown_mode_is_class3(profile):
    result = classify_request(
        make_request(None, mode=InvocationMode.UNKNOWN), profile
    )
    assert result.command_class is CommandClass.SANDBOXED


@pytest.mark.parametrize(
    "text",
    ["ls", "ls -la /tmp", "ls && pwd", "ls; pwd", "cat /etc/hosts"],
)
def test_class1_bash_utility(text, profile):
    result = classify(text, profile)
    assert result.command_class is CommandClass.BASH_UTILITY
    assert result.reason is ReasonCode.SAFE_WHITELISTED


@pytest.mark.parametrize(
    "text",
    [
        "python3 script.py",
        "python3 script.py arg1",
        'python3 -c "print(1)"',
        "/usr/bin/python3 -c 'x = 1'",
    ],
)
def test_class2_python(text, profile):
    result = classify(text, profile)
    assert result.command_class is CommandClass.PYTHON_SCRIPT


@pytest.mark.parametrize(
    "text",
    [
        "python3 -m http.server",
        "python3 -S script.py",
        "python3 -E script.py",
        "python3 -I script.py",
        "python3 -",
        "python3 script.py && ls",
        "ls && python3 script.py",
        "bash -c 'ls'",
        "ls | sh",
        "cat $HOME/x",
        "echo $(date)",
        "./ls",
        "rm -rf /",
        "chmod 644 file",
        "echo 'unclosed",
    ],
)
def test_class3_everything_else(text, profile):
    result = classify(text, profile)
    assert result.command_class is CommandClass.SANDBOXED


def test_stdin_mode_is_analyzed_like_c(profile):
    result = classify(
        "python3 script.py",
        profile,
        mode=InvocationMode.STDIN,
    )
    assert result.command_class is CommandClass.PYTHON_SCRIPT


def test_empty_command_routes_to_class1(profile):
    assert classify("", profile).command_class is CommandClass.BASH_UTILITY
