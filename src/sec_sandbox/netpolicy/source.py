"""发送侧数据源溯源（附录 D.4）。

- 明确泄密（敏感文件、字面量凭据、可识别的敏感命令替换、管道上游）→ Deny；
- 语义模糊（``$TOKEN``、无法识别的 ``$(...)``）→ 交 ⑤ LLM。
"""

from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass
from typing import Any

from ..bash_audit.astutil import command_argv, walk, word_text
from ..bash_audit.parser import parse
from ..contracts import AuditContext
from ..policy.builtin.sensitive_paths import SENSITIVE_PATH_PATTERNS
from ..util.paths import expand_word_path, is_sensitive_path
from ..util.redact import redact

_UPLOAD_FLAGS = frozenset(
    {
        "-d",
        "--data",
        "--data-raw",
        "--data-binary",
        "--data-urlencode",
        "-F",
        "--form",
        "-T",
        "--upload-file",
        "--post-data",
        "--post-file",
    }
)
_DIRECT_FILE_FLAGS = frozenset({"-T", "--upload-file", "--post-file"})
_READER_COMMANDS = frozenset(
    {"cat", "head", "tail", "grep", "strings", "base64", "tar", "dd"}
)
_AT_PATH_RE = re.compile(r"@([^\s,;]+)")
_SUBSTITUTION_RE = re.compile(r"\$\(([^)]*)\)|`([^`]*)`")
_VARIABLE_RE = re.compile(r"\$(?:\{[^}]+\}|[A-Za-z_][A-Za-z0-9_]*)")


@dataclass(frozen=True)
class SourceFinding:
    """发送源检查结果。"""

    denied: bool
    rule_id: str | None = None
    ambiguous: tuple[str, ...] = ()


def inspect_send(
    command: Any,
    upstream: tuple[Any, ...],
    ctx: AuditContext,
    patterns: tuple[str, ...] = SENSITIVE_PATH_PATTERNS,
) -> SourceFinding:
    """检查一条联网命令的上传参数与管道上游。"""
    ambiguous: list[str] = []

    for text, direct_file in _upload_values(command):
        if text is None:
            ambiguous.append("<dynamic>")
            continue
        if redact(text) != text:
            return SourceFinding(True, "D4.LITERAL")
        for raw in _file_paths(text, direct_file):
            path = expand_word_path(raw, cwd=ctx.cwd, home=ctx.home)
            if path is not None and is_sensitive_path(path, patterns):
                return SourceFinding(True, "D4.FILE")
        if _substitution_reads_sensitive(text, ctx, patterns):
            return SourceFinding(True, "D4.PIPE")
        if _VARIABLE_RE.search(text) or _SUBSTITUTION_RE.search(text):
            ambiguous.append(text)

    for upstream_command in upstream:
        if _reads_sensitive(upstream_command, ctx, patterns):
            return SourceFinding(True, "D4.PIPE")

    return SourceFinding(False, None, tuple(ambiguous))


def _upload_values(command: Any) -> list[tuple[str | None, bool]]:
    words = [
        part
        for part in getattr(command, "parts", ())
        if getattr(part, "kind", None) == "word"
    ]
    values: list[tuple[str | None, bool]] = []
    index = 1
    while index < len(words):
        text = word_text(words[index]) or getattr(words[index], "word", "") or ""
        flag, inline = _split_flag(text)
        if flag in _UPLOAD_FLAGS:
            direct = flag in _DIRECT_FILE_FLAGS
            if inline is not None:
                values.append((inline, direct))
            elif index + 1 < len(words):
                index += 1
                values.append((getattr(words[index], "word", None), direct))
        index += 1
    return values


def _split_flag(text: str) -> tuple[str, str | None]:
    if text.startswith("--"):
        if "=" in text:
            name, value = text.split("=", 1)
            return name, value
        return text, None
    if text.startswith("-") and len(text) >= 2:
        return text[:2], text[2:] or None
    return "", None


def _file_paths(text: str, direct_file: bool) -> list[str]:
    if text.startswith("@"):
        return [text[1:]]
    if direct_file:
        return [text]
    return _AT_PATH_RE.findall(text)


def _substitution_reads_sensitive(
    text: str,
    ctx: AuditContext,
    patterns: tuple[str, ...],
) -> bool:
    for match in _SUBSTITUTION_RE.finditer(text):
        inner = match.group(1) or match.group(2) or ""
        parsed = parse(inner)
        if not parsed.ok:
            continue
        for command in _iter_commands(parsed):
            if _reads_sensitive(command, ctx, patterns):
                return True
    return False


def _reads_sensitive(
    command: Any,
    ctx: AuditContext,
    patterns: tuple[str, ...],
) -> bool:
    argv = command_argv(command)
    if argv is None:
        return False
    name = posixpath.basename(argv[0])
    if name not in _READER_COMMANDS:
        return False

    for arg in argv[1:]:
        if arg.startswith("-"):
            continue
        if "=" in arg:
            arg = arg.split("=", 1)[1]
        path = expand_word_path(arg, cwd=ctx.cwd, home=ctx.home)
        if path is not None and is_sensitive_path(path, patterns):
            return True
    return False


def _iter_commands(parsed: Any):
    for root in parsed.nodes:
        for node in walk(root):
            if getattr(node, "kind", None) == "command":
                yield node
