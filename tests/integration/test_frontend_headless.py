"""T6-01/T6-03 前端 headless 与入口路径测试。"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from sec_sandbox.frontend.app import main
from sec_sandbox.frontend.screens import ProfileForm
from sec_sandbox.policy.loader import default_profile_path, save_profile
from sec_sandbox.policy.presets import get_preset
from sec_sandbox.sandbox.selfcheck import CheckResult


@pytest.fixture
def home(tmp_path, monkeypatch) -> Path:
    monkeypatch.setenv("HOME", str(tmp_path))
    (tmp_path / "work").mkdir()
    return tmp_path


def test_form_submit_returns_profile(home):
    profile = get_preset("standard", workspace=home / "work")

    async def drive():
        form = ProfileForm(profile)
        async with form.run_test(size=(120, 50)) as pilot:
            await pilot.click("#save")
            await pilot.pause()
        return form.return_value

    result = asyncio.run(drive())

    assert result is not None
    assert result.workspace == home / "work"


def test_form_cancel_returns_none(home):
    profile = get_preset("standard", workspace=home / "work")

    async def drive():
        form = ProfileForm(profile)
        async with form.run_test(size=(120, 50)) as pilot:
            await pilot.click("#cancel")
            await pilot.pause()
        return form.return_value

    assert asyncio.run(drive()) is None


def test_check_path(capsys):
    results = (CheckResult("bubblewrap", True, "/usr/bin/bwrap"),)

    code = main(["--check"], selfcheck=lambda: results)

    assert code == 0
    assert "[通过] bubblewrap" in capsys.readouterr().out


def test_check_path_fails_on_critical(capsys):
    results = (CheckResult("bubblewrap", False, "missing"),)

    assert main(["--check"], selfcheck=lambda: results) == 1
    assert "存在关键失败" in capsys.readouterr().out


def test_profile_path_skips_tui(home):
    profile = get_preset("standard", workspace=home / "work")
    profile_path = home / "custom-profile.json"
    save_profile(profile, profile_path)
    captured = {}

    def fake_exec(argv0, argv):
        captured["argv"] = (argv0, argv)

    code = main(["--profile", str(profile_path)], execv=fake_exec)

    assert code == 127
    assert "bwrap" in captured["argv"][1]


def test_preset_path_writes_default_profile(home):
    captured = {}

    def fake_exec(argv0, argv):
        captured["argv"] = (argv0, argv)

    code = main(["--preset", "strict"], execv=fake_exec)

    assert code == 127
    assert default_profile_path().is_file()
    assert (home / ".local" / "state" / "sec-sandbox").is_dir()
    assert captured["argv"][1]


def test_no_tui_path(home):
    captured = {}

    def fake_exec(argv0, argv):
        captured["argv"] = (argv0, argv)

    assert main(["--no-tui"], execv=fake_exec) == 127
    assert captured["argv"][1]


def test_tui_cancel_exit_code(home):
    class FakeForm:
        def __init__(self, profile):
            self.profile = profile

        def run_form(self):
            return None

    code = main([], form_factory=FakeForm, execv=lambda *args: None)

    assert code == 0


def test_help_exits_zero():
    with pytest.raises(SystemExit) as excinfo:
        main(["--help"])
    assert excinfo.value.code == 0
