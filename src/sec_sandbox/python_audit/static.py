"""类 2 准入与 Python 静态 AST 扫描（附录 C.1）。

- ``is_python_invocation``：判断 argv 是否可作为类 2 处理；
- ``analyze_source``：Deny 项（``ctypes``、动态执行）优先，其次降级项
  （``pickle``/``subprocess``/``os.system`` 等）；解析失败与内部异常一律降级。
"""

from __future__ import annotations

import ast
import os
import shutil
from collections.abc import Sequence
from pathlib import Path

from ..contracts import AuditContext, AuditVerdict, Decision, ReasonCode
from ..policy.models import Profile

_DENY_MODULES = frozenset({"ctypes"})
_DENY_CALLS = frozenset(
    {
        "eval",
        "exec",
        "compile",
        "__import__",
        "builtins.eval",
        "builtins.exec",
        "builtins.compile",
        "builtins.__import__",
    }
)
_DOWNGRADE_CALLS = frozenset(
    {
        "pickle.loads",
        "marshal.loads",
        "yaml.unsafe_load",
        "os.system",
        "os.popen",
    }
)
_DOWNGRADE_PREFIXES = ("os.exec", "os.spawn", "subprocess.")
_NETWORK_MODULES = frozenset({"socket", "urllib", "requests", "http.client"})
_DENY_OPTS = frozenset({"-S", "-E", "-I"})


def is_python_invocation(argv: Sequence[str], profile: Profile) -> bool:
    """argv 是否为允许的类 2 调用（解释器 realpath 在允许列表且形式合规）。"""
    if not argv:
        return False

    interpreter = _resolve_path(argv[0])
    if interpreter is None:
        return False
    allowed = {
        path
        for path in (_resolve_path(item) for item in profile.python.allowed_interpreters)
        if path is not None
    }
    if interpreter not in allowed:
        return False

    args = list(argv[1:])
    if not args:
        return False

    index = 0
    while index < len(args) and args[index].startswith("-") and args[index] != "-":
        arg = args[index]
        if arg == "-c":
            if index + 1 >= len(args):
                return False
            source = args[index + 1]
            return len(source.encode("utf-8")) <= profile.python.max_source_bytes
        if arg in _DENY_OPTS:
            return False
        if arg.startswith("--"):
            return False
        if any(flag in arg[1:] for flag in "SEI"):
            return False
        return False  # -u/-B/-m/- 等其他形式一律交类 3

    # 脚本形式：python3 script.py
    return index < len(args) and args[index] != "-"


def analyze_source(source: str, ctx: AuditContext) -> AuditVerdict:
    """按附录 C.1 静态扫描；解析失败或内部异常 → 降级。"""
    del ctx  # 静态扫描不需要路径上下文；保留签名以符合 PythonAuditor
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return AuditVerdict(Decision.DOWNGRADE, ReasonCode.PARSE_FAILED)
    except Exception:  # noqa: BLE001 - 契约要求内部异常降级而非崩溃
        return AuditVerdict(Decision.DOWNGRADE, ReasonCode.ANALYZER_ERROR)

    try:
        return _inspect(tree)
    except Exception:  # noqa: BLE001
        return AuditVerdict(Decision.DOWNGRADE, ReasonCode.ANALYZER_ERROR)


def _inspect(tree: ast.AST) -> AuditVerdict:
    aliases = _collect_aliases(tree)

    deny_rules: list[str] = []
    downgrade_rules: list[str] = []
    network_rules: list[str] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                _classify_module(alias.name, "", deny_rules, downgrade_rules, network_rules)
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            _classify_module(
                module,
                ",".join(alias.name for alias in node.names),
                deny_rules,
                downgrade_rules,
                network_rules,
            )
        elif isinstance(node, ast.Call):
            call = _call_name(node, aliases)
            if call is None:
                continue
            if call in _DENY_CALLS:
                deny_rules.append("C1.DYNAMIC_EVAL")
            elif call in _DOWNGRADE_CALLS or call.startswith(_DOWNGRADE_PREFIXES):
                downgrade_rules.append("C1.RUNTIME_SINK")

    if deny_rules:
        reason = (
            ReasonCode.PY_FORBIDDEN_IMPORT
            if "C1.CTYPES" in deny_rules
            else ReasonCode.PY_DYNAMIC_EVAL
        )
        return AuditVerdict(Decision.DENY, reason, tuple(_unique(deny_rules)))

    if downgrade_rules:
        return AuditVerdict(
            Decision.DOWNGRADE,
            ReasonCode.PY_NEEDS_RUNTIME_AUDIT,
            tuple(_unique(downgrade_rules)),
        )

    return AuditVerdict(
        Decision.ALLOW,
        ReasonCode.PYTHON_STATIC_OK,
        tuple(_unique(network_rules)),
    )


def _classify_module(
    module: str,
    imported_names: str,
    deny_rules: list[str],
    downgrade_rules: list[str],
    network_rules: list[str],
) -> None:
    del imported_names  # 目前按模块判定；保留参数便于后续细化
    root = module.split(".", 1)[0]
    if root in _DENY_MODULES:
        deny_rules.append("C1.CTYPES")
    elif root == "subprocess":
        downgrade_rules.append("C1.RUNTIME_SINK")
    elif module in _NETWORK_MODULES or root in _NETWORK_MODULES:
        network_rules.append("C1.NETWORK")


def _collect_aliases(tree: ast.AST) -> dict[str, str]:
    """收集 ``import x as y`` / ``from m import n as y`` 的本地名映射。"""
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                local = alias.asname or alias.name.split(".", 1)[0]
                aliases[local] = alias.name
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for alias in node.names:
                local = alias.asname or alias.name
                aliases[local] = f"{module}.{alias.name}" if module else alias.name
    return aliases


def _call_name(call: ast.Call, aliases: dict[str, str]) -> str | None:
    path = _attribute_path(call.func)
    if path is None:
        return None
    head, _, tail = path.partition(".")
    resolved = aliases.get(head, head)
    return f"{resolved}.{tail}" if tail else resolved


def _attribute_path(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _attribute_path(node.value)
        return f"{base}.{node.attr}" if base else None
    return None


def _resolve_path(arg: str | Path) -> Path | None:
    text = os.fspath(arg)
    if "/" in text:
        return Path(os.path.realpath(text))
    found = shutil.which(text)
    return Path(os.path.realpath(found)) if found else None


def _unique(items: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result
