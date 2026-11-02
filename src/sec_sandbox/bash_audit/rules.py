"""附录 B 规则匹配：Deny 优先，白名单按 basename + realpath 双重匹配。

对应《实现级架构设计》§4.4。本模块只做文本/路径分析，不执行命令。
"""

from __future__ import annotations

import os
import posixpath
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Iterator

from ..contracts import AuditContext, AuditVerdict, CommandShape, Decision, ParsedBash, ReasonCode
from ..policy.builtin.bash_high_risk import (
    DANGEROUS_WRITE_PATTERNS,
    FORK_BOMB_PATTERN,
    HIGH_RISK_COMMANDS,
    HIGH_RISK_PREFIXES,
    RECURSIVE_PERMISSION_COMMANDS,
    WRITE_COMMANDS,
)
from ..policy.builtin.sensitive_paths import SENSITIVE_PATH_PATTERNS
from ..policy.builtin.whitelist import BASH_BUILTINS, DEFAULT_UTILITY_WHITELIST
from ..util.paths import (
    expand_word_path,
    is_sensitive_path,
    is_under,
    match_sensitive_pattern,
)
from .astutil import command_argv, walk, word_text
from .classifier import classify

if TYPE_CHECKING:
    from ..policy.models import Profile

_DEFAULT_TRUSTED_PATH = (Path("/usr/local/bin"), Path("/usr/bin"), Path("/bin"))


@dataclass(frozen=True)
class RuleSet:
    """一次分析所需的规则集合（由 profile 注入）。"""

    utility_whitelist: frozenset[str] = frozenset(DEFAULT_UTILITY_WHITELIST)
    trusted_path: tuple[Path, ...] = _DEFAULT_TRUSTED_PATH
    sensitive_patterns: tuple[str, ...] = SENSITIVE_PATH_PATTERNS
    dangerous_writes: tuple[str, ...] = DANGEROUS_WRITE_PATTERNS

    @classmethod
    def from_profile(cls, profile: Profile) -> RuleSet:
        return cls(
            utility_whitelist=frozenset(profile.bash.utility_whitelist),
            trusted_path=tuple(profile.bash.trusted_path),
        )


def find_deny(parsed: ParsedBash, ctx: AuditContext, rules: RuleSet) -> AuditVerdict | None:
    """返回首个 Deny 裁决；无命中返回 ``None``。"""
    if FORK_BOMB_PATTERN.search(parsed.text):
        return AuditVerdict(Decision.DENY, ReasonCode.HIGH_RISK_COMMAND, ("B1.FORK_BOMB",))
    if not parsed.ok:
        return None

    for command in _iter_commands(parsed):
        verdict = _check_command(command, ctx, rules)
        if verdict is not None:
            return verdict
    return None


def is_allowlisted(parsed: ParsedBash, ctx: AuditContext, rules: RuleSet) -> bool:
    """当且仅当命令为 SIMPLE 且全部命中白名单 + trusted_path 时返回 ``True``。"""
    del ctx  # 白名单判定不需要工作目录，保留参数以与 Deny 检查对称
    if classify(parsed) is not CommandShape.SIMPLE:
        return False

    trusted_roots = tuple(Path(os.path.realpath(root)) for root in rules.trusted_path)
    search_path = os.pathsep.join(str(root) for root in trusted_roots)

    for command in _iter_commands(parsed):
        argv = command_argv(command)
        if argv is None or not argv:
            return False
        name = argv[0]
        if "/" in name or name not in rules.utility_whitelist:
            return False
        if name in BASH_BUILTINS:
            continue
        resolved = shutil.which(name, path=search_path)
        if resolved is None:
            return False
        if not any(is_under(resolved, root) for root in trusted_roots):
            return False
    return True


def _iter_commands(parsed: ParsedBash) -> Iterator[Any]:
    for root in parsed.nodes:
        for node in walk(root):
            if getattr(node, "kind", None) == "command":
                yield node


def _check_command(command: Any, ctx: AuditContext, rules: RuleSet) -> AuditVerdict | None:
    parts = tuple(getattr(command, "parts", ()))
    words = [part for part in parts if getattr(part, "kind", None) == "word"]
    if not words:
        return None

    command_text = word_text(words[0])
    name = posixpath.basename(command_text) if command_text else ""

    verdict = _check_command_name(name, words)
    if verdict is not None:
        return verdict

    for word in words[1:]:
        if _is_sensitive_word(word, ctx, rules):
            return AuditVerdict(Decision.DENY, ReasonCode.SENSITIVE_PATH, ("B2.SENSITIVE_PATH",))

    for part in parts:
        if getattr(part, "kind", None) != "redirect":
            continue
        verdict = _check_redirect(part, ctx, rules)
        if verdict is not None:
            return verdict

    return _check_write_targets(name, command, ctx, rules)


def _check_command_name(name: str, words: list[Any]) -> AuditVerdict | None:
    if not name:
        return None

    rule_id = HIGH_RISK_COMMANDS.get(name)
    if rule_id is not None:
        return AuditVerdict(Decision.DENY, ReasonCode.HIGH_RISK_COMMAND, (rule_id,))

    for prefix, prefix_rule in HIGH_RISK_PREFIXES:
        if name.startswith(prefix):
            return AuditVerdict(Decision.DENY, ReasonCode.HIGH_RISK_COMMAND, (prefix_rule,))

    recursive_rule = RECURSIVE_PERMISSION_COMMANDS.get(name)
    if recursive_rule is not None and _has_recursive_flag(words[1:]):
        return AuditVerdict(Decision.DENY, ReasonCode.HIGH_RISK_COMMAND, (recursive_rule,))
    return None


def _has_recursive_flag(words: list[Any]) -> bool:
    for word in words:
        text = word_text(word)
        if text is None:
            text = getattr(word, "word", "") or ""
        if text in {"-R", "--recursive"}:
            return True
        if text.startswith("-") and not text.startswith("--") and "R" in text[1:]:
            return True
    return False


def _is_sensitive_word(word: Any, ctx: AuditContext, rules: RuleSet) -> bool:
    raw = getattr(word, "word", None)
    path = _expand_word(raw, ctx)
    return path is not None and is_sensitive_path(path, rules.sensitive_patterns)


def _check_redirect(redirect: Any, ctx: AuditContext, rules: RuleSet) -> AuditVerdict | None:
    if getattr(redirect, "heredoc", None):
        return None
    output = getattr(redirect, "output", None)
    if output is None or not hasattr(output, "kind"):
        return None  # 文件描述符复制，如 2>&1

    path = _expand_word(getattr(output, "word", None), ctx)
    if path is None:
        return None
    if match_sensitive_pattern(path, rules.dangerous_writes):
        return AuditVerdict(Decision.DENY, ReasonCode.DANGEROUS_REDIRECT, ("B3.WRITE",))
    if is_sensitive_path(path, rules.sensitive_patterns):
        return AuditVerdict(Decision.DENY, ReasonCode.SENSITIVE_PATH, ("B2.SENSITIVE_PATH",))
    return None


def _check_write_targets(
    name: str,
    command: Any,
    ctx: AuditContext,
    rules: RuleSet,
) -> AuditVerdict | None:
    all_targets = WRITE_COMMANDS.get(name)
    if all_targets is None:
        return None

    # 不能走 command_argv：``~``/``$HOME`` 形式的参数不是静态词，会被整体丢弃，
    # 导致写目标检查失效（REVIEW-0015）。这里直接取 word 节点的原始文本。
    words = [
        part
        for part in getattr(command, "parts", ())
        if getattr(part, "kind", None) == "word"
    ]
    if len(words) < 2:
        return None
    targets = words[1:] if all_targets else words[-1:]
    for word in targets:
        raw = getattr(word, "word", None)
        if not raw or raw.startswith("-"):
            continue
        path = _expand_word(raw, ctx)
        if path is None:
            continue
        if match_sensitive_pattern(path, rules.dangerous_writes):
            return AuditVerdict(Decision.DENY, ReasonCode.DANGEROUS_REDIRECT, ("B3.WRITE",))
        if is_sensitive_path(path, rules.sensitive_patterns):
            return AuditVerdict(Decision.DENY, ReasonCode.SENSITIVE_PATH, ("B2.SENSITIVE_PATH",))
    return None


def _expand_word(raw: str | None, ctx: AuditContext) -> Path | None:
    return expand_word_path(raw, cwd=ctx.cwd, home=ctx.home)
