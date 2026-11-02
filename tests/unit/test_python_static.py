"""T3-01 Python 静态扫描与类 2 准入测试（附录 C.1）。"""

from __future__ import annotations

from dataclasses import replace

import pytest

from sec_sandbox.contracts import AuditContext, Decision, ReasonCode
from sec_sandbox.policy.presets import get_preset
from sec_sandbox.python_audit.static import analyze_source, is_python_invocation


@pytest.fixture
def ctx(tmp_path, monkeypatch) -> AuditContext:
    home = tmp_path / "home"
    home.mkdir()
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.setenv("HOME", str(home))
    return AuditContext(cwd=work, home=home, workspace=work)


@pytest.fixture
def profile(ctx):
    return get_preset("standard", workspace=ctx.workspace)


def scan(source: str, ctx: AuditContext):
    return analyze_source(source, ctx)


def test_safe_source_allowed(ctx):
    verdict = scan('print("hello")\n', ctx)
    assert verdict.decision is Decision.ALLOW
    assert verdict.reason is ReasonCode.PYTHON_STATIC_OK


@pytest.mark.parametrize(
    "source",
    [
        "import ctypes",
        "import ctypes.util",
        "from ctypes import CDLL",
    ],
)
def test_ctypes_denied(source, ctx):
    verdict = scan(source, ctx)
    assert verdict.decision is Decision.DENY
    assert verdict.reason is ReasonCode.PY_FORBIDDEN_IMPORT
    assert "C1.CTYPES" in verdict.rule_ids


@pytest.mark.parametrize(
    "source",
    [
        'eval("1 + 1")',
        'exec("x = 1")',
        'compile("1", "<x>", "eval")',
        '__import__("os")',
        'builtins.eval("1")',
    ],
)
def test_dynamic_execution_denied(source, ctx):
    verdict = scan(source, ctx)
    assert verdict.decision is Decision.DENY
    assert verdict.reason is ReasonCode.PY_DYNAMIC_EVAL


@pytest.mark.parametrize(
    "source",
    [
        "import subprocess\nsubprocess.run(['ls'])",
        "from subprocess import Popen\nPopen(['ls'])",
        "import subprocess as sp\nsp.Popen(['ls'])",
        "import os\nos.system('ls')",
        "from os import system\nsystem('ls')",
        "import os\nos.execv('/bin/ls', ['ls'])",
        "import pickle\npickle.loads(b'')",
        "from pickle import loads\nloads(b'')",
        "import marshal\nmarshal.loads(b'')",
        "import yaml\nyaml.unsafe_load('x')",
    ],
)
def test_runtime_sinks_downgraded(source, ctx):
    verdict = scan(source, ctx)
    assert verdict.decision is Decision.DOWNGRADE
    assert verdict.reason is ReasonCode.PY_NEEDS_RUNTIME_AUDIT


@pytest.mark.parametrize(
    "source",
    [
        "import socket",
        "import urllib.request",
        "import requests",
        "from http.client import HTTPConnection",
    ],
)
def test_network_imports_allowed_and_recorded(source, ctx):
    verdict = scan(source, ctx)
    assert verdict.decision is Decision.ALLOW
    assert "C1.NETWORK" in verdict.rule_ids


def test_deny_takes_priority(ctx):
    verdict = scan("import ctypes\nimport subprocess\n", ctx)
    assert verdict.decision is Decision.DENY


def test_syntax_error_downgraded(ctx):
    verdict = scan("def f(:\n", ctx)
    assert verdict.decision is Decision.DOWNGRADE
    assert verdict.reason is ReasonCode.PARSE_FAILED


def test_empty_source_allowed(ctx):
    assert scan("", ctx).decision is Decision.ALLOW


def test_is_python_invocation_accepts_script_and_c(profile):
    assert is_python_invocation(["/usr/bin/python3", "script.py"], profile)
    assert is_python_invocation(["/usr/bin/python3", "-c", "print(1)"], profile)


@pytest.mark.parametrize(
    "argv",
    [
        ["/usr/bin/python3"],
        ["/usr/bin/python3", "-m", "http.server"],
        ["/usr/bin/python3", "-S", "-c", "x"],
        ["/usr/bin/python3", "-E", "script.py"],
        ["/usr/bin/python3", "-I", "script.py"],
        ["/usr/bin/python3", "-"],
        ["/usr/bin/python3", "-u", "script.py"],
        ["/usr/bin/other", "script.py"],
        ["/usr/bin/python3", "-c"],
    ],
)
def test_is_python_invocation_rejects(argv, profile):
    assert not is_python_invocation(argv, profile)


def test_is_python_invocation_checks_source_size(profile):
    small = replace(profile, python=replace(profile.python, max_source_bytes=10))

    assert is_python_invocation(["/usr/bin/python3", "-c", "x" * 10], small)
    assert not is_python_invocation(["/usr/bin/python3", "-c", "x" * 11], small)
