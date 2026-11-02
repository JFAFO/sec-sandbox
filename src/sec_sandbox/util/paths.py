"""路径工具：``~``/``$HOME`` 展开、realpath 与敏感路径匹配。

对应《实现级架构设计》§8。所有路径判定必须走本模块（§7 共享代码规则）。

约定：

- 路径只接受 ``~``/``$HOME`` 前缀或绝对路径，相对路径一律拒绝（§8.2）；
- 匹配前一律先展开再 ``realpath``，防止用 ``..`` 或符号链接绕过；
- 匹配策略宁可多拦、不可漏拦（安全场景下误报优于漏报）。
"""

from __future__ import annotations

import fnmatch
import os
from collections.abc import Iterable
from pathlib import Path

_HOME_PREFIX = "$HOME"


def expand_path(raw: str | os.PathLike[str]) -> Path:
    """展开 ``~``/``$HOME`` 前缀，返回绝对路径。

    Raises:
        ValueError: 路径为空或为相对路径。
    """
    text = os.fspath(raw)
    if not text:
        raise ValueError("路径不能为空")

    if text == _HOME_PREFIX or text.startswith(_HOME_PREFIX + "/"):
        text = str(Path.home()) + text[len(_HOME_PREFIX):]
    else:
        text = os.path.expanduser(text)

    path = Path(text)
    if not path.is_absolute():
        raise ValueError(f"仅支持 ~/$HOME 前缀或绝对路径：{os.fspath(raw)!r}")
    return path


def canonicalize(raw: str | os.PathLike[str]) -> Path:
    """展开并解析为规范绝对路径；不要求路径存在。"""
    return Path(os.path.realpath(expand_path(raw)))


def match_sensitive_pattern(
    path: str | os.PathLike[str],
    patterns: Iterable[str],
) -> str | None:
    """按敏感路径模式匹配，返回首个命中的模式；未命中返回 ``None``。

    模式语义为 ``fnmatch`` 通配符；``~``/``$HOME`` 前缀会先展开，
    以 ``/*`` 结尾的模式同时覆盖目录本身（如 ``~/.ssh/*`` 命中 ``~/.ssh``）。
    """
    target = str(canonicalize(path))
    for pattern in patterns:
        if _match_one(target, _expand_pattern(pattern)):
            return pattern
    return None


def is_sensitive_path(path: str | os.PathLike[str], patterns: Iterable[str]) -> bool:
    """路径是否命中任一敏感路径模式。"""
    return match_sensitive_pattern(path, patterns) is not None


def is_under(path: str | os.PathLike[str], root: str | os.PathLike[str]) -> bool:
    """``path`` 是否等于 ``root`` 或位于其下（按规范绝对路径比较）。"""
    candidate = canonicalize(path)
    base = canonicalize(root)
    return candidate == base or base in candidate.parents


def _expand_pattern(pattern: str) -> str:
    """只展开模式中的 ``~``/``$HOME`` 前缀，允许相对 glob。"""
    if pattern == _HOME_PREFIX or pattern.startswith(_HOME_PREFIX + "/"):
        return str(Path.home()) + pattern[len(_HOME_PREFIX):]
    if pattern.startswith("~"):
        return os.path.expanduser(pattern)
    return pattern


def _match_one(target: str, pattern: str) -> bool:
    if fnmatch.fnmatchcase(target, pattern):
        return True
    # ``dir/*`` 保守地同时覆盖目录本身
    return pattern.endswith("/*") and fnmatch.fnmatchcase(target, pattern[:-2])
