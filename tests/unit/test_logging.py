"""T1-02 内部日志测试：只写 stderr、调试开关、自动脱敏。"""

from __future__ import annotations

from sec_sandbox.util import logging as internal_log


def test_warning_goes_to_stderr_only(capsys):
    internal_log.warning("disk almost full")
    captured = capsys.readouterr()
    assert "disk almost full" in captured.err
    assert captured.out == ""


def test_debug_disabled_by_default(capsys, monkeypatch):
    monkeypatch.delenv("SECSAND_DEBUG", raising=False)
    internal_log.debug("trace message")
    captured = capsys.readouterr()
    assert captured.err == ""
    assert captured.out == ""


def test_debug_enabled_by_env(capsys, monkeypatch):
    monkeypatch.setenv("SECSAND_DEBUG", "1")
    internal_log.debug("trace message")
    assert "trace message" in capsys.readouterr().err


def test_warning_redacts_credentials(capsys):
    internal_log.warning("GITHUB_TOKEN=ghp_secret_value")
    err = capsys.readouterr().err
    assert "ghp_secret_value" not in err
    assert "[REDACTED]" in err
