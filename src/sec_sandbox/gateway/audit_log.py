"""JSONL 审计日志：追加、轮转、权限与原文开关（§5.2、§9 S-11）。

- 目录 0700、文件 0600；
- 默认不落命令原文，只记 SHA-256；开启后也只写审计文件且先脱敏；
- 写失败不阻断命令（调用方继续执行）。
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from ..util.redact import redact

_PREVIEW_LIMIT = 256


@dataclass(frozen=True)
class AuditEvent:
    """一次调用的审计事件；``command_text`` 不会原样落盘。"""

    source: str
    decision: str
    reason: str
    mode: str | None = None
    command_class: str | None = None
    rule_ids: tuple[str, ...] = ()
    depth: int = 0
    network: Mapping[str, Any] | None = None
    command_text: str | None = None
    exit_code: int | None = None
    signal: int | None = None
    duration_ms: int = 0
    profile_hash: str = ""
    error: str | None = None


@dataclass
class AuditLog:
    """线程安全的 JSONL 追加器。"""

    path: Path
    max_bytes: int = 10 * 1024 * 1024
    backups: int = 5
    log_command_text: bool = False
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def append(self, event: AuditEvent) -> None:
        """追加一条事件；任何 I/O 失败都被吞掉，不影响命令执行。"""
        line = json.dumps(self._record(event), ensure_ascii=False) + "\n"
        with self._lock:
            try:
                self._write(line)
            except OSError:
                pass

    def _record(self, event: AuditEvent) -> dict[str, Any]:
        text = event.command_text
        return {
            "schema_version": 1,
            "event_id": str(uuid.uuid4()),
            "ts": datetime.now().astimezone().isoformat(timespec="milliseconds"),
            "source": event.source,
            "pid": os.getpid(),
            "depth": event.depth,
            "mode": event.mode,
            "class": event.command_class,
            "decision": event.decision,
            "reason": event.reason,
            "rule_ids": list(event.rule_ids),
            "network": dict(event.network) if event.network is not None else None,
            "command_sha256": (
                hashlib.sha256(text.encode("utf-8")).hexdigest() if text else None
            ),
            "command_preview": self._preview(text),
            "exit_code": event.exit_code,
            "signal": event.signal,
            "duration_ms": event.duration_ms,
            "profile_hash": event.profile_hash,
            "error": event.error,
        }

    def _preview(self, text: str | None) -> str | None:
        if not self.log_command_text or not text:
            return None
        return redact(text)[:_PREVIEW_LIMIT]

    def _write(self, line: str) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._rotate_if_needed(len(line.encode("utf-8")))

        fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        try:
            os.fchmod(fd, 0o600)
            os.write(fd, line.encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)

    def _rotate_if_needed(self, incoming: int) -> None:
        try:
            size = self.path.stat().st_size
        except OSError:
            return
        if size + incoming <= self.max_bytes:
            return

        if self.backups <= 0:
            self.path.unlink(missing_ok=True)
            return

        oldest = self.path.with_name(f"{self.path.name}.{self.backups}")
        oldest.unlink(missing_ok=True)
        for index in range(self.backups - 1, 0, -1):
            source = self.path.with_name(f"{self.path.name}.{index}")
            target = self.path.with_name(f"{self.path.name}.{index + 1}")
            if source.exists():
                source.replace(target)
        if self.path.exists():
            self.path.replace(self.path.with_name(f"{self.path.name}.1"))
