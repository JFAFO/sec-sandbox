"""T5-02 / T5-03 外层与内层 bwrap argv 测试。"""

from __future__ import annotations

from dataclasses import replace

import pytest

from sec_sandbox.contracts import InnerLaunchRequest
from sec_sandbox.policy.presets import get_preset
from sec_sandbox.sandbox import SandboxBuildError
from sec_sandbox.sandbox.inner import build_inner
from sec_sandbox.sandbox.outer import build_outer
from sec_sandbox.sandbox.paths import RuntimePaths, probe_paths


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
    (home / ".aws").mkdir()

    monkeypatch.setenv("HOME", str(home))
    profile_file = tmp_path / "profile.json"
    profile_file.write_text("{}", encoding="utf-8")
    safe_exec = tmp_path / "safe-exec"
    safe_exec.write_text("#!/bin/sh\n", encoding="utf-8")
    safe_exec.chmod(0o755)
    sudo = tmp_path / "sudo"
    sudo.write_text("", encoding="utf-8")

    profile = get_preset("standard", workspace=work)
    profile = replace(
        profile,
        inner=replace(profile.inner, masked_executables=(sudo,)),
    )
    return profile, home, work, profile_file, safe_exec, sudo


def triples(args):
    return {tuple(args[index : index + 3]) for index in range(len(args) - 2)}


def pairs(args):
    return {tuple(args[index : index + 2]) for index in range(len(args) - 1)}


def test_outer_argv(env):
    profile, home, work, profile_file, safe_exec, _ = env
    runtime = probe_paths(profile)

    plan = build_outer(
        profile,
        profile_file,
        safe_exec=safe_exec,
        paths=runtime,
        defaults=(),
    )
    args = plan.argv

    assert args[0] == "bwrap"
    assert ("--ro-bind", "/", "/") in triples(args)
    assert ("--proc", "/proc") in pairs(args)
    assert ("--dev", "/dev") in pairs(args)
    assert ("--size", str(profile.filesystem.tmp_size_bytes), "--tmpfs", "/tmp") in {
        tuple(args[index : index + 4]) for index in range(len(args) - 3)
    }
    assert ("--bind", str(work), str(work)) in triples(args)
    assert ("--bind", str(home / ".claude"), str(home / ".claude")) in triples(args)
    assert ("--bind", str(home / ".claude.json"), str(home / ".claude.json")) in triples(args)
    assert ("--ro-bind", str(runtime.real_bash), "/usr/bin/real-bash") in triples(args)
    assert ("--ro-bind", str(safe_exec), "/usr/bin/bash") in triples(args)
    assert ("--ro-bind", str(profile_file), str(profile_file)) in triples(args)
    assert ("--setenv", "SECSAND_PROFILE", str(profile_file)) in triples(args)
    assert ("--setenv", "SECSAND_DEPTH", "0") in triples(args)
    assert ("--setenv", "SECSAND_REAL_BASH", "/usr/bin/real-bash") in triples(args)
    assert ("--chdir", str(work)) in pairs(args)
    assert args[-1] == "/usr/bin/bash"
    assert plan.pass_fds == ()


def test_outer_seccomp_fd(env):
    profile, _, _, profile_file, safe_exec, _ = env

    plan = build_outer(
        profile,
        profile_file,
        safe_exec=safe_exec,
        seccomp_fd=7,
        defaults=(),
    )

    assert ("--seccomp", "7") in pairs(plan.argv)
    assert plan.pass_fds == (7,)


def test_outer_rejects_missing_real_bash(env):
    profile, home, work, profile_file, safe_exec, _ = env
    runtime = RuntimePaths(
        home=home,
        workspace=work,
        audit_dir=profile.audit.log_dir,
        real_bash=None,
        python=None,
        bash_paths=(),
    )

    with pytest.raises(SandboxBuildError):
        build_outer(profile, profile_file, safe_exec=safe_exec, paths=runtime)


def test_outer_rejects_missing_safe_exec(env, tmp_path):
    profile, _, _, profile_file, _, _ = env

    with pytest.raises(SandboxBuildError):
        build_outer(profile, profile_file, safe_exec=tmp_path / "nope")


def test_outer_rejects_missing_profile(env, tmp_path):
    profile, _, _, _, safe_exec, _ = env

    with pytest.raises(SandboxBuildError):
        build_outer(profile, tmp_path / "nope.json", safe_exec=safe_exec)


def test_inner_argv(env):
    profile, home, work, profile_file, safe_exec, sudo = env
    runtime = probe_paths(profile)

    plan = build_inner(
        profile,
        InnerLaunchRequest(shell_argv=("-c", "ls"), cwd=work, depth=0),
        profile_path=profile_file,
        paths=runtime,
        defaults=(),
    )
    args = plan.argv

    assert ("--bind", str(work), str(work)) in triples(args)
    assert ("--ro-bind", str(home / ".claude"), str(home / ".claude")) in triples(args)
    assert ("--ro-bind", "/dev/null", str(sudo)) in triples(args)
    assert ("--setenv", "SECSAND_DEPTH", "1") in triples(args)
    assert ("--setenv", "SECSAND_PROFILE", str(profile_file)) in triples(args)
    assert ("--chdir", str(work)) in pairs(args)
    assert args[-3:] == ("/usr/bin/real-bash", "-c", "ls")
    assert "/usr/bin/bash" not in args
    assert "/bin/bash" not in args
    assert ("--ro-bind", str(safe_exec), "/usr/bin/bash") not in triples(args)


def test_inner_seccomp_fd(env):
    profile, _, work, profile_file, _, _ = env

    plan = build_inner(
        profile,
        InnerLaunchRequest(shell_argv=("-c", "ls"), cwd=work, depth=2),
        profile_path=profile_file,
        seccomp_fd=9,
        defaults=(),
    )

    assert ("--seccomp", "9") in pairs(plan.argv)
    assert plan.pass_fds == (9,)
    assert ("--setenv", "SECSAND_DEPTH", "3") in triples(plan.argv)


def test_inner_rejects_missing_profile(env, tmp_path):
    profile, _, work, _, _, _ = env

    with pytest.raises(SandboxBuildError):
        build_inner(
            profile,
            InnerLaunchRequest(shell_argv=("-c", "ls"), cwd=work, depth=0),
            profile_path=tmp_path / "nope.json",
        )


def test_outer_without_tmp_size_support(env):
    """bwrap 0.6.1 不认识 --size，应降级为普通 --tmpfs /tmp。"""
    profile, _, _, profile_file, safe_exec, _ = env
    runtime = probe_paths(profile)

    plan = build_outer(
        profile,
        profile_file,
        safe_exec=safe_exec,
        paths=runtime,
        defaults=(),
        supports_tmp_size=False,
    )

    assert "--size" not in plan.argv
    assert ("--tmpfs", "/tmp") in pairs(plan.argv)


def test_inner_without_tmp_size_support(env):
    profile, _, work, profile_file, _, _ = env
    runtime = probe_paths(profile)

    plan = build_inner(
        profile,
        InnerLaunchRequest(shell_argv=("-c", "ls"), cwd=work, depth=0),
        profile_path=profile_file,
        paths=runtime,
        defaults=(),
        supports_tmp_size=False,
    )

    assert "--size" not in plan.argv
    assert ("--tmpfs", "/tmp") in pairs(plan.argv)
