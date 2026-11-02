"""T1-02 路径工具测试：展开、realpath、敏感路径匹配。"""

from __future__ import annotations

from pathlib import Path

import pytest
from hypothesis import given, strategies as st

from sec_sandbox.util.paths import (
    canonicalize,
    expand_path,
    is_sensitive_path,
    is_under,
    match_sensitive_pattern,
)

SENSITIVE_PATTERNS = (
    "~/.ssh/*",
    "**/.env",
    "**/.env.*",
    "**/*.pem",
    "/etc/shadow",
)


def test_expand_tilde():
    assert expand_path("~/proj/a.txt") == Path.home() / "proj" / "a.txt"


def test_expand_home_prefix():
    assert expand_path("$HOME/.ssh") == Path.home() / ".ssh"
    assert expand_path("$HOME") == Path.home()


def test_absolute_path_unchanged():
    assert expand_path("/etc/shadow") == Path("/etc/shadow")


@pytest.mark.parametrize("raw", ["proj/a.txt", ".", "..", "a"])
def test_relative_path_rejected(raw):
    with pytest.raises(ValueError):
        expand_path(raw)


@pytest.mark.parametrize("raw", ["", "$HOMEx/a"])
def test_invalid_prefix_rejected(raw):
    with pytest.raises(ValueError):
        expand_path(raw)


def test_canonicalize_normalizes_dotdot(tmp_path):
    (tmp_path / "a").mkdir()
    assert canonicalize(str(tmp_path / "a" / "..")) == tmp_path.resolve()


def test_canonicalize_follows_symlink(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real)
    assert canonicalize(str(link / "x")) == (real / "x").resolve()


def test_ssh_key_matches():
    assert is_sensitive_path("~/.ssh/id_rsa", SENSITIVE_PATTERNS)
    assert is_sensitive_path("~/.ssh/id_ed25519", SENSITIVE_PATTERNS)


def test_directory_pattern_also_covers_directory_itself():
    # ``~/.ssh/*`` 保守地同时覆盖目录本身
    assert is_sensitive_path("~/.ssh", SENSITIVE_PATTERNS)


def test_env_file_anywhere():
    assert is_sensitive_path("/home/someone/proj/.env", SENSITIVE_PATTERNS)
    assert is_sensitive_path("/home/someone/proj/.env.local", SENSITIVE_PATTERNS)


def test_pem_anywhere():
    assert is_sensitive_path("/tmp/work/server.pem", SENSITIVE_PATTERNS)


def test_absolute_pattern():
    assert is_sensitive_path("/etc/shadow", SENSITIVE_PATTERNS)


def test_benign_path_not_matched():
    assert not is_sensitive_path("/tmp/work/notes.txt", SENSITIVE_PATTERNS)
    assert not is_sensitive_path("~/proj/main.py", SENSITIVE_PATTERNS)


def test_symlink_bypass_is_blocked(tmp_path):
    secret_dir = tmp_path / ".ssh"
    secret_dir.mkdir()
    secret = secret_dir / "id_rsa"
    secret.write_text("secret", encoding="utf-8")
    innocent = tmp_path / "innocent"
    innocent.symlink_to(secret)

    pattern = str(secret_dir / "*")
    assert is_sensitive_path(str(innocent), (pattern,))


def test_is_under(tmp_path):
    base = tmp_path / "base"
    child = base / "a" / "b"
    child.mkdir(parents=True)

    assert is_under(child, base)
    assert is_under(base, base)
    assert not is_under(tmp_path / "other", base)


def test_match_returns_first_hit():
    pattern = match_sensitive_pattern(
        "~/.ssh/id_rsa", ("**/*.pem", "~/.ssh/*")
    )
    assert pattern == "~/.ssh/*"


@given(st.text(max_size=40))
def test_expand_returns_absolute_or_raises(raw):
    try:
        path = expand_path(raw)
    except ValueError:
        return
    assert path.is_absolute()


@given(st.text(max_size=40))
def test_canonicalize_idempotent(raw):
    try:
        once = canonicalize(raw)
    except ValueError:
        return
    assert canonicalize(once) == once
