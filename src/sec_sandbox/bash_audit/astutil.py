"""bashlex AST 工具：遍历、取词与字面量判定。

任何模块需要 AST 遍历时只调用本模块（《实现级架构设计》§7）。
节点类型来自 bashlex；本模块不执行命令、不读取文件。
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

_GLOB_CHARS = frozenset("*?[{")

_CONTAINER_KINDS = frozenset(
    {"list", "pipeline", "if", "for", "while", "until", "command", "function"}
)


def walk(node: Any) -> Iterator[Any]:
    """深度优先遍历 ``node`` 及其全部后代。"""
    yield node
    for child in _children(node):
        yield from walk(child)


def iter_words(node: Any) -> Iterator[Any]:
    """按出现顺序遍历全部 ``word`` 节点（不含保留字）。"""
    for item in walk(node):
        if _kind(item) == "word":
            yield item


def word_text(node: Any) -> str | None:
    """返回无 shell 展开/替换的词的文本；含参数、命令替换或波浪号时返回 ``None``。

    注意：通配符与花括号在 bashlex 中仍是普通文本，是否静态请用
    :func:`is_static_word`。
    """
    if _kind(node) != "word":
        return None
    if getattr(node, "parts", None):
        return None
    return node.word


def is_static_word(node: Any) -> bool:
    """词是否可当作固定字符串（无替换、无通配、无花括号展开）。"""
    text = word_text(node)
    return text is not None and not any(char in _GLOB_CHARS for char in text)


def command_argv(command: Any) -> tuple[str, ...] | None:
    """取简单命令的字面量 argv；任一参数含展开/替换时返回 ``None``。

    重定向与赋值不进入 argv；``command`` 不是 command 节点时返回 ``None``。
    """
    if _kind(command) != "command":
        return None

    argv: list[str] = []
    for part in getattr(command, "parts", ()):
        if _kind(part) != "word":
            continue
        text = word_text(part)
        if text is None:
            return None
        argv.append(text)
    return tuple(argv)


def _kind(node: Any) -> str | None:
    return getattr(node, "kind", None)


def _children(node: Any) -> tuple[Any, ...]:
    kind = _kind(node)
    if kind in _CONTAINER_KINDS:
        return tuple(getattr(node, "parts", ()) or ())
    if kind == "compound":
        return (
            *tuple(getattr(node, "list", ()) or ()),
            *tuple(getattr(node, "redirects", ()) or ()),
        )
    if kind in {"word", "assignment"}:
        return tuple(getattr(node, "parts", ()) or ())
    if kind == "redirect":
        children: list[Any] = []
        output = getattr(node, "output", None)
        if _kind(output) is not None:
            children.append(output)
        heredoc = getattr(node, "heredoc", None)
        if heredoc is not None:
            children.append(heredoc)
        return tuple(children)
    if kind in {"commandsubstitution", "processsubstitution"}:
        command = getattr(node, "command", None)
        return (command,) if command is not None else ()
    return ()
