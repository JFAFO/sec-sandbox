"""T8 运维脚本：uninstall.sh 的隔离环境集成测试。

所有用例只操作 ``tmp_path`` 下的假 HOME/项目，不触碰真实用户目录；
``--no-sudo`` 保证不会尝试删除系统路径。
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "uninstall.sh"


@dataclass(frozen=True)
class UninstallEnv:
    """一次测试使用的最小部署产物。"""

    home: Path
    project: Path
    real_bash: Path
    profile: Path
    state: Path
    venv: Path
    source: Path
    cache: Path


@pytest.fixture
def env(tmp_path: Path) -> UninstallEnv:
    home = tmp_path / "home"
    profile = home / ".config" / "sandbox" / "profile.json"
    profile.parent.mkdir(parents=True)
    profile.write_text("{}\n", encoding="utf-8")

    state = home / ".local" / "state" / "sec-sandbox"
    state.mkdir(parents=True)
    (state / "audit.jsonl").write_text("{}\n", encoding="utf-8")

    project = tmp_path / "project"
    venv = project / ".venv" / "bin"
    venv.mkdir(parents=True)
    (venv / "python").write_text("", encoding="utf-8")

    source = project / "src"
    source.mkdir()
    (source / "keep.py").write_text("print(1)\n", encoding="utf-8")
    cache = source / "__pycache__"
    cache.mkdir()
    (cache / "x.pyc").write_text("", encoding="utf-8")

    real_bash = tmp_path / "real-bash"
    real_bash.symlink_to("/bin/bash")

    return UninstallEnv(
        home=home,
        project=project,
        real_bash=real_bash,
        profile=profile,
        state=state,
        venv=project / ".venv",
        source=source,
        cache=cache,
    )


def run(env: UninstallEnv, *extra: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "bash",
            str(SCRIPT),
            "--project-dir",
            str(env.project),
            "--home",
            str(env.home),
            "--real-bash",
            str(env.real_bash),
            "--no-sudo",
            *extra,
        ],
        capture_output=True,
        text=True,
        check=False,
        stdin=subprocess.DEVNULL,
    )


def test_dry_run_keeps_everything(env: UninstallEnv):
    result = run(env, "--dry-run")

    assert result.returncode == 0
    assert env.profile.exists()
    assert env.state.exists()
    assert env.venv.exists()
    assert env.cache.exists()
    assert "未做任何修改" in result.stdout


def test_uninstall_removes_state_and_keeps_source(env: UninstallEnv):
    result = run(env, "--yes")

    assert result.returncode == 0
    assert not env.profile.exists()
    assert not env.state.exists()
    assert not env.venv.exists()
    assert not env.cache.exists()
    assert env.source.exists()
    assert (env.source / "keep.py").exists()
    # --no-sudo 时不删除真 bash 备份
    assert env.real_bash.exists()


def test_uninstall_is_idempotent(env: UninstallEnv):
    assert run(env, "--yes").returncode == 0

    second = run(env, "--yes")

    assert second.returncode == 0
    assert "未发现需要清理" in second.stdout


def test_keep_state_preserves_config_and_audit(env: UninstallEnv):
    result = run(env, "--yes", "--keep-state")

    assert result.returncode == 0
    assert env.profile.exists()
    assert (env.state / "audit.jsonl").exists()
    assert not env.venv.exists()


def test_non_bash_real_bash_target_is_protected(env: UninstallEnv, tmp_path: Path):
    fake = tmp_path / "not-real-bash"
    fake.write_text("#!/bin/sh\n", encoding="utf-8")

    result = subprocess.run(
        [
            "bash",
            str(SCRIPT),
            "--project-dir",
            str(env.project),
            "--home",
            str(env.home),
            "--real-bash",
            str(fake),
            "--dry-run",
        ],
        capture_output=True,
        text=True,
        check=False,
        stdin=subprocess.DEVNULL,
    )

    assert result.returncode == 0
    assert "不指向系统 bash" in (result.stdout + result.stderr)
    assert fake.exists()


def test_non_interactive_without_yes_is_refused(env: UninstallEnv):
    result = run(env)

    assert result.returncode == 2
    assert "非交互环境请加 --yes" in result.stderr
    assert env.profile.exists()
