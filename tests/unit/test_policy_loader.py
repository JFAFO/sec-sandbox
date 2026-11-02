"""T1-03 profile 模型、校验、加载与预设测试。"""

from __future__ import annotations

import json
import stat
from pathlib import Path
from typing import Any

import pytest

from sec_sandbox.policy.loader import (
    ProfileError,
    load_profile,
    profile_to_dict,
    save_profile,
)
from sec_sandbox.policy.models import BlacklistAction, WorkspaceWriteMode
from sec_sandbox.policy.presets import get_preset, preset_names
from sec_sandbox.policy.schema import parse_profile


@pytest.fixture
def home(tmp_path, monkeypatch) -> Path:
    """隔离 HOME，并创建默认 workspace。"""
    resolved = tmp_path.resolve()
    monkeypatch.setenv("HOME", str(resolved))
    (resolved / "project").mkdir()
    return resolved


def valid_data(home: Path) -> dict[str, Any]:
    log_dir = str(home / ".local" / "state" / "sec-sandbox")
    return {
        "schema_version": 1,
        "profile_name": "test",
        "workspace": str(home / "project"),
        "workspace_write_mode": "bind",
        "filesystem": {
            "read_blacklist": [
                {"path": str(home / ".ssh"), "action": "mask"},
                {"path": "/etc/shadow", "action": "devnull"},
            ],
            "write_whitelist": [
                str(home / "project"),
                str(home / ".claude"),
                str(home / ".claude.json"),
                log_dir,
            ],
            "tmp_size_bytes": 1024,
        },
        "resources": {"memory_max": "512M", "pids_max": 64, "cpu_quota": "50%"},
        "bash": {
            "utility_whitelist": ["ls", "cat"],
            "trusted_path": ["/usr/bin", "/bin"],
            "allow_scripts": False,
            "max_script_bytes": 1024,
        },
        "python": {
            "allowed_interpreters": ["/usr/bin/python3"],
            "max_source_bytes": 1024,
        },
        "network": {
            "enabled": True,
            "safe_domains": ["example.com"],
            "llm_judge": {
                "enabled": False,
                "endpoint": "http://127.0.0.1:11434/v1/chat/completions",
                "model": "local-judge",
                "timeout_ms": 1500,
                "allow_remote": False,
            },
        },
        "inner": {
            "max_depth": 2,
            "masked_executables": ["/usr/bin/sudo"],
            "seccomp_denylist": ["ptrace"],
        },
        "audit": {
            "log_dir": log_dir,
            "log_command_text": False,
            "max_bytes": 1024,
            "backups": 1,
        },
        "notices": {"class3_notice": True},
    }


def error_paths(result) -> set[str]:
    return {issue.path for issue in result.errors}


def test_parse_valid_profile(home):
    result = parse_profile(valid_data(home))
    assert result.ok
    assert not result.errors
    profile = result.profile
    assert profile.workspace == home / "project"
    assert profile.workspace_write_mode is WorkspaceWriteMode.BIND
    assert profile.filesystem.read_blacklist[0].action is BlacklistAction.MASK
    assert profile.resources.pids_max == 64


def test_home_prefix_is_expanded(home):
    data = valid_data(home)
    data["workspace"] = "$HOME/project"
    result = parse_profile(data)
    assert result.ok
    assert result.profile.workspace == home / "project"


def test_workspace_must_exist(home):
    data = valid_data(home)
    data["workspace"] = str(home / "missing")
    result = parse_profile(data)
    assert not result.ok
    assert "workspace" in error_paths(result)


def test_collects_all_errors(home):
    data = valid_data(home)
    data["schema_version"] = 2
    data["workspace"] = str(home / "missing")
    data["filesystem"]["read_blacklist"][0]["action"] = "unknown"
    data["filesystem"]["write_whitelist"].append("/tmp/outside")
    data["resources"]["memory_max"] = "abc"
    data["resources"]["cpu_quota"] = "50"
    data["bash"]["trusted_path"].append("relative/bin")

    result = parse_profile(data)
    assert not result.ok
    assert {
        "schema_version",
        "workspace",
        "filesystem.read_blacklist[0].action",
        "filesystem.write_whitelist[4]",
        "resources.memory_max",
        "resources.cpu_quota",
        "bash.trusted_path[2]",
    } <= error_paths(result)


def test_unknown_fields_warn_and_ignore(home):
    data = valid_data(home)
    data["extra"] = 1
    data["resources"]["extra"] = True
    result = parse_profile(data)
    assert result.ok
    assert {issue.path for issue in result.warnings} == {"extra", "resources.extra"}


def test_unknown_enum_rejected(home):
    data = valid_data(home)
    data["workspace_write_mode"] = "overlay"
    result = parse_profile(data)
    assert not result.ok
    assert "workspace_write_mode" in error_paths(result)


def test_relative_path_rejected(home):
    data = valid_data(home)
    data["workspace"] = "project"
    result = parse_profile(data)
    assert not result.ok
    assert "workspace" in error_paths(result)


def test_audit_log_dir_must_be_under_state(home):
    data = valid_data(home)
    data["audit"]["log_dir"] = "/tmp/audit"
    result = parse_profile(data)
    assert not result.ok
    assert "audit.log_dir" in error_paths(result)


def test_dotdot_path_rejected(home):
    data = valid_data(home)
    data["filesystem"]["read_blacklist"][0]["path"] = "$HOME/project/../.ssh"
    result = parse_profile(data)
    assert not result.ok
    assert "filesystem.read_blacklist[0].path" in error_paths(result)


@pytest.mark.parametrize("action", ["mask", "devnull", "ro_bind"])
def test_blacklist_actions_accepted(home, action):
    data = valid_data(home)
    data["filesystem"]["read_blacklist"][0]["action"] = action
    result = parse_profile(data)
    assert result.ok
    assert result.profile.filesystem.read_blacklist[0].action.value == action


def test_load_default_path(home):
    target = home / ".config" / "sandbox" / "profile.json"
    target.parent.mkdir(parents=True)
    target.write_text(json.dumps(valid_data(home)), encoding="utf-8")

    profile = load_profile()
    assert profile.profile_name == "test"


def test_load_missing_file(home):
    with pytest.raises(ProfileError, match="无法读取"):
        load_profile(home / "nope.json")


def test_load_invalid_json(home):
    path = home / "profile.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(ProfileError, match="不是合法 JSON"):
        load_profile(path)


def test_load_validation_error_carries_all_issues(home):
    data = valid_data(home)
    data["schema_version"] = 2
    data["resources"]["memory_max"] = "abc"
    path = home / "profile.json"
    path.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ProfileError) as excinfo:
        load_profile(path)
    assert len(excinfo.value.issues) >= 2


def test_save_profile_roundtrip(home, tmp_path):
    profile = parse_profile(valid_data(home)).profile
    target = tmp_path / "out" / "profile.json"

    save_profile(profile, target)

    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert "$HOME/project" in target.read_text(encoding="utf-8")
    assert load_profile(target) == profile


def test_save_default_path(home):
    profile = parse_profile(valid_data(home)).profile
    path = save_profile(profile)
    assert path == home / ".config" / "sandbox" / "profile.json"
    assert path.is_file()
    assert load_profile() == profile


def test_profile_to_dict_roundtrip(home):
    profile = parse_profile(valid_data(home)).profile
    again = parse_profile(profile_to_dict(profile))
    assert again.ok
    assert again.profile == profile


def test_preset_names():
    assert set(preset_names()) == {"strict", "standard", "loose"}


def test_presets_load(home):
    for name in preset_names():
        profile = get_preset(name, workspace=home / "project")
        assert profile.profile_name == name
        assert profile.workspace == home / "project"


def test_preset_differences(home):
    strict = get_preset("strict", workspace=home / "project")
    standard = get_preset("standard", workspace=home / "project")
    loose = get_preset("loose", workspace=home / "project")

    assert strict.resources.memory_max == "256M"
    assert standard.resources.memory_max == "512M"
    assert loose.resources.memory_max == "2G"
    assert strict.inner.max_depth < standard.inner.max_depth < loose.inner.max_depth
    assert not standard.bash.allow_scripts
    assert loose.bash.allow_scripts


def test_preset_default_workspace(home):
    profile = get_preset("standard")
    assert profile.workspace == home / "project"


def test_unknown_preset(home):
    with pytest.raises(ValueError, match="未知预设"):
        get_preset("nope")


def test_preset_workspace_must_be_absolute(home):
    with pytest.raises(ValueError, match="workspace"):
        get_preset("standard", workspace="relative/path")
