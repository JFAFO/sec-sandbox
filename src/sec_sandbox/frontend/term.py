"""终端状态兜底恢复：异常退出 TUI 后尽量恢复 termios。"""

from __future__ import annotations

import sys
import termios
from collections.abc import Iterator
from contextlib import contextmanager


@contextmanager
def terminal_guard() -> Iterator[None]:
    """保存并在退出时恢复 stdin 的 termios；非 tty 环境直接放行。"""
    if not sys.stdin.isatty():
        yield
        return

    try:
        fd = sys.stdin.fileno()
        saved = termios.tcgetattr(fd)
    except (termios.error, OSError, ValueError):
        yield
        return

    try:
        yield
    finally:
        try:
            termios.tcsetattr(fd, termios.TCSADRAIN, saved)
        except (termios.error, OSError, ValueError):
            pass
