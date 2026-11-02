"""命令形状分类：SIMPLE / COMPOUND / UNPARSEABLE。

对应《实现级架构设计》§4.4。**拿不准一律 COMPOUND**：只有能证明是
"静态简单命令"（或以 ``;``/``&&``/``||`` 连接的静态简单命令列表）才返回
SIMPLE，其余结构一律 COMPOUND。
"""

from __future__ import annotations

import posixpath
from typing import Any

from ..contracts import CommandShape, ParsedBash
from .astutil import command_argv, is_static_word

_ALLOWED_LIST_OPERATORS = frozenset({";", "&&", "||"})
_WRAPPERS = frozenset({"xargs", "env", "command", "eval", "exec", "source", "."})
_SHELLS = frozenset({"bash", "sh", "zsh", "dash"})
_DYNAMIC_CD_CHARS = frozenset("*?[{")


def classify(parsed: ParsedBash) -> CommandShape:
    """返回命令形状；解析失败返回 UNPARSEABLE。"""
    if not parsed.ok:
        return CommandShape.UNPARSEABLE
    if not parsed.nodes:
        return CommandShape.SIMPLE
    if len(parsed.nodes) != 1:
        return CommandShape.COMPOUND
    return _classify_node(parsed.nodes[0])


def _classify_node(node: Any) -> CommandShape:
    kind = getattr(node, "kind", None)
    if kind == "command":
        return CommandShape.SIMPLE if _is_simple_command(node) else CommandShape.COMPOUND
    if kind == "list":
        return CommandShape.SIMPLE if _is_simple_list(node) else CommandShape.COMPOUND
    return CommandShape.COMPOUND


def _is_simple_list(node: Any) -> bool:
    for part in getattr(node, "parts", ()):
        kind = getattr(part, "kind", None)
        if kind == "operator":
            if getattr(part, "op", None) not in _ALLOWED_LIST_OPERATORS:
                return False
        elif kind == "command":
            if not _is_simple_command(part):
                return False
        else:
            return False
    return True


def _is_simple_command(command: Any) -> bool:
    parts = tuple(getattr(command, "parts", ()))

    if any(getattr(part, "kind", None) == "assignment" for part in parts):
        return False

    argv = command_argv(command)
    if argv is None or not argv:
        return False

    first_word = next(
        (part for part in parts if getattr(part, "kind", None) == "word"), None
    )
    if first_word is None or not is_static_word(first_word):
        return False

    if any(
        getattr(part, "kind", None) == "redirect" and not _is_static_redirect(part)
        for part in parts
    ):
        return False

    return not _is_compound_utility(argv)


def _is_static_redirect(redirect: Any) -> bool:
    if getattr(redirect, "heredoc", None):
        return False
    output = getattr(redirect, "output", None)
    if output is None or not hasattr(output, "kind"):
        return True  # 文件描述符复制，如 2>&1
    return is_static_word(output)


def _is_compound_utility(argv: tuple[str, ...]) -> bool:
    """命中时说明该命令会派生/解释新的命令，必须按复合结构处理。"""
    name = posixpath.basename(argv[0])
    args = argv[1:]

    if name in _WRAPPERS:
        return True
    if name in _SHELLS and "-c" in args:
        return True
    if name == "find" and any(arg in {"-exec", "-execdir", "-ok"} for arg in args):
        return True
    if name == "awk" and any("system(" in arg for arg in args):
        return True
    if name == "sed" and any(arg.startswith("-i") for arg in args):
        return True
    if name == "cd" and args and any(char in args[0] for char in _DYNAMIC_CD_CHARS):
        return True
    return False
