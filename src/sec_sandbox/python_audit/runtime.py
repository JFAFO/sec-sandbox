"""audithook 注册与运行时拦截。

- 读取 ``SECSAND_RUNTIME_POLICY`` 指向的 JSON 后立即 ``unlink``；
- ``sys.addaudithook`` 只能添加、不能移除（Python 无移除 API）；
- hook 内做重入保护，避免拦截动作自身再次触发审计事件。
"""

from __future__ import annotations

import json
import os
import sys
import threading
from datetime import datetime
from pathlib import Path
from typing import Any

from ..contracts import ReasonCode
from ..gateway.messages import INTERNAL_ERROR, message_for
from .policy import RuntimePolicy, RuntimeVerdict, evaluate_event

_local = threading.local()
_policy: RuntimePolicy | None = None
_installed = False


def install(policy_path: str | os.PathLike[str]) -> RuntimePolicy:
    """加载策略、删除临时文件并注册 hook；重复调用只更新策略。"""
    global _policy, _installed

    path = Path(policy_path)
    data = json.loads(path.read_text(encoding="utf-8"))
    try:
        path.unlink()
    except FileNotFoundError:
        pass

    policy = RuntimePolicy.from_mapping(data)
    _policy = policy
    if not _installed:
        sys.addaudithook(_hook)
        _installed = True
    return policy


def _hook(event: str, args: tuple[Any, ...]) -> None:
    policy = _policy
    if policy is None or getattr(_local, "active", False):
        return

    _local.active = True
    try:
        verdict = evaluate_event(event, args, policy)
    except Exception:  # noqa: BLE001 - 运行时异常必须 fail-closed
        verdict = RuntimeVerdict(True, ReasonCode.INTERNAL_ERROR)
    finally:
        _local.active = False

    if not verdict.denied:
        return

    _record_denial(policy, event, verdict.reason)
    message = message_for(verdict.reason) if verdict.reason is not None else None
    print(message or INTERNAL_ERROR, file=sys.stderr)
    raise PermissionError(message or INTERNAL_ERROR)


def _record_denial(policy: RuntimePolicy, event: str, reason: Any) -> None:
    """向审计日志追加一条 ``source=python_runtime`` 事件；写失败不阻断 Deny。"""
    record = {
        "schema_version": 1,
        "ts": datetime.now().astimezone().isoformat(timespec="milliseconds"),
        "source": "python_runtime",
        "pid": os.getpid(),
        "event": event,
        "decision": "deny",
        "reason": reason.value if reason is not None else "INTERNAL_ERROR",
    }
    try:
        policy.audit_log.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with open(policy.audit_log, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")
    except OSError:
        pass
