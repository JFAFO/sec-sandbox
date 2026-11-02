"""bashlex 封装：``text → ParsedBash``。

对应《实现级架构设计》§4.4：``parse()`` **永不抛异常**；解析失败或未实现
语法一律返回 ``ParsedBash(ok=False)``，由上层按 UNPARSEABLE 降级。
"""

from __future__ import annotations

import bashlex

from ..contracts import ParsedBash


def parse(text: str) -> ParsedBash:
    """解析 bash 文本；空文本视为合法的空命令。"""
    if not text.strip():
        return ParsedBash(text=text, nodes=(), ok=True, error=None)

    try:
        nodes = bashlex.parse(text)
    except Exception as exc:  # noqa: BLE001 - 契约要求绝不向调用方抛异常
        return ParsedBash(
            text=text,
            nodes=(),
            ok=False,
            error=f"{type(exc).__name__}: {exc}",
        )

    return ParsedBash(text=text, nodes=tuple(nodes), ok=True, error=None)
