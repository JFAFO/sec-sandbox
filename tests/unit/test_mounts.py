"""T5-01 路径探测与挂载参数测试。"""

from __future__ import annotations

import pytest

from sec_sandbox.policy.presets import get_preset
from sec_sandbox.sandbox.mounts import (
    DEFAULT_READ_BLACKLIST,
    inner_mounts,
    outer_mounts,
)
from sec_sandbox.sandbox.paths import probe_paths


@pytest.fixture
def env(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    work = tmp_path / "work"
    work.mkdir()
    audit = home / ".local" / "state" / "sec-sandbox"
    audit.mkdir(parents=True)
    (home / ".claude").mkdir()
    (home / ".claude.json").write_text("{}", encoding="utf-8")
    (home / ".ssh").mkdir()
    (home / ".ssh" / "id_rsa").write_text("x", encoding="utf-8")
    (home / ".aws").mkdir()
    (home / ".npmrc").write_text("x", encoding="utf-8")
    (home / ".config").mkdir()
    (home / ".gitconfig").write_text("x", encoding="utf-8")

    monkeypatch.setenv("HOME", str(home))
    profile = get_preset("standard", workspace=work)
    return profile, home, work, audit


def test_outer_mounts_exact_order(env):
    profile, home, work, audit = env

    spec = outer_mounts(profile, defaults=())

    assert spec.args == (
        "--bind", str(work), str(work),
        "--bind", str(home / ".claude"), str(home / ".claude"),
        "--bind", str(home / ".claude.json"), str(home / ".claude.json"),
        "--bind", str(audit), str(audit),
        "--tmpfs", str(home / ".ssh"),
        "--tmpfs", str(home / ".aws"),
        "--ro-bind", "/dev/null", "/etc/shadow",
    )
    assert spec.skipped == ()


def test_write_bindings_precede_masks(env):
    profile, _, _, _ = env

    args = outer_mounts(profile, defaults=DEFAULT_READ_BLACKLIST).args

    first_mask = min(
        index for index, value in enumerate(args) if value in {"--tmpfs", "--ro-bind"}
    )
    last_bind = max(index for index, value in enumerate(args) if value == "--bind")
    assert last_bind < first_mask


def test_missing_sources_skipped(env):
    profile, home, _, _ = env

    spec = outer_mounts(profile)

    assert home / ".gnupg" in spec.skipped
    assert str(home / ".gnupg") not in spec.args


def test_default_blacklist_deduplicates(env):
    profile, home, _, _ = env

    args = outer_mounts(profile).args

    # profile 与默认表都含 ~/.ssh，只应遮蔽一次
    assert args.count(str(home / ".ssh")) == 1
    assert args.count("--tmpfs") >= 1


def test_inner_mounts_lock_claude_readonly(env):
    profile, home, work, _ = env

    args = inner_mounts(profile, defaults=()).args
    triples = _triples(args)

    assert args[:3] == ("--bind", str(work), str(work))
    assert ("--ro-bind", str(home / ".claude"), str(home / ".claude")) in triples
    assert ("--bind", str(home / ".claude"), str(home / ".claude")) not in triples
    assert ("--ro-bind", str(home / ".claude.json"), str(home / ".claude.json")) in triples


def test_inner_mounts_extra_masks(env):
    profile, home, _, _ = env

    args = inner_mounts(profile, defaults=()).args
    pairs = {tuple(args[index : index + 2]) for index in range(len(args) - 1)}

    assert ("--tmpfs", str(home / ".config")) in pairs
    assert ("--ro-bind", "/dev/null", str(home / ".gitconfig")) in _triples(args)


def test_inner_write_set_is_subset_of_outer(env):
    profile, _, _, _ = env

    outer_binds = _bind_paths(outer_mounts(profile, defaults=()).args)
    inner_binds = _bind_paths(inner_mounts(profile, defaults=()).args)

    assert inner_binds <= outer_binds


def test_inner_has_no_bash_replacement(env):
    profile, _, _, _ = env

    args = inner_mounts(profile, defaults=()).args

    assert "/bin/bash" not in args
    assert "/usr/bin/bash" not in args


def test_probe_paths(env):
    profile, home, work, audit = env

    runtime = probe_paths(profile)

    assert runtime.home == home
    assert runtime.workspace == work
    assert runtime.audit_dir == audit
    assert runtime.real_bash is not None and runtime.real_bash.exists()
    assert runtime.python is not None and runtime.python.exists()
    assert runtime.bash_paths
    assert len(set(runtime.bash_paths)) == len(runtime.bash_paths)


def _bind_paths(args: tuple[str, ...]) -> set[str]:
    result = set()
    for index, value in enumerate(args):
        if value == "--bind":
            result.add(args[index + 1])
    return result


def _triples(args: tuple[str, ...]) -> set[tuple[str, ...]]:
    return {tuple(args[index : index + 3]) for index in range(len(args) - 2)}
