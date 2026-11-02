"""T6-02/T6-03 ``safe-exec`` 入口集成测试。"""

from __future__ import annotations

from pathlib import Path

import pytest

from sec_sandbox.gateway.cli import main as cli_main
from sec_sandbox.policy.loader import save_profile
from sec_sandbox.policy.presets import get_preset


@pytest.fixture
def profile_file(tmp_path, monkeypatch) -> Path:
    home = tmp_path / "home"
    home.mkdir()
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("SECSAND_DEPTH", raising=False)
    monkeypatch.delenv("SECSAND_REAL_BASH", raising=False)

    path = tmp_path / "profile.json"
    save_profile(get_preset("standard", workspace=work), path)
    monkeypatch.setenv("SECSAND_PROFILE", str(path))
    return path


def test_cli_allows_whitelisted_command(profile_file):
    assert cli_main(["-c", "ls"]) == 0

    audit = profile_file.parent / "home" / ".local" / "state" / "sec-sandbox" / "audit.jsonl"
    assert audit.is_file()


def test_cli_denies_sensitive_path(profile_file):
    assert cli_main(["-c", "cat ~/.ssh/id_rsa"]) == 126


def test_cli_python_class2(profile_file):
    assert cli_main(["-c", 'python3 -c "print(1)"']) == 0


def test_cli_reports_usage_error(profile_file, capsys):
    assert cli_main(["-c"]) == 64

    assert "无法执行" in capsys.readouterr().err


def test_cli_missing_profile(monkeypatch):
    monkeypatch.delenv("SECSAND_PROFILE", raising=False)

    assert cli_main(["-c", "ls"]) == 127


def test_cli_invalid_profile(tmp_path, monkeypatch):
    path = tmp_path / "bad.json"
    path.write_text("{not json", encoding="utf-8")
    monkeypatch.setenv("SECSAND_PROFILE", str(path))

    assert cli_main(["-c", "ls"]) == 127
