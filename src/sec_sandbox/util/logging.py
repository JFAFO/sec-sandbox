"""内部调试日志：只写 stderr，与审计日志（JSONL 文件）完全分离。

- ``warning()`` 始终输出；
- ``debug()`` 仅在 ``SECSAND_DEBUG=1`` 时输出；
- 所有消息写前先经 :func:`util.redact.redact` 脱敏（§9 S-11）。
"""

from __future__ import annotations

import os
import sys

from .redact import redact


def debug(message: str) -> None:
    """输出调试信息；默认关闭，设置 ``SECSAND_DEBUG=1`` 开启。"""
    if os.environ.get("SECSAND_DEBUG") != "1":
        return
    print(f"[sec_sandbox] DEBUG: {redact(message)}", file=sys.stderr)


def warning(message: str) -> None:
    """输出内部警告（不属于用户可见的拦截文案）。"""
    print(f"[sec_sandbox] WARNING: {redact(message)}", file=sys.stderr)
