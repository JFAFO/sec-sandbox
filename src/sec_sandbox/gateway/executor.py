"""执行器：子进程启动、信号转发、环境硬化与退出码映射。

对应《实现级架构设计》§4.3 与 §9：

- 所有子进程使用 argv 列表，禁用 ``shell=True``（S-6）；
- 清除 ``BASH_ENV``、``ENV``、``BASH_FUNC_*``，``PATH`` 固定为 ``trusted_path``（S-5）；
- 被信号终止时退出码映射为 ``128+N``。
"""

from __future__ import annotations

import os
import signal
import subprocess
import threading
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from types import FrameType
from typing import Any

from ..contracts import ExecutionResult

_FORBIDDEN_ENV = frozenset({"BASH_ENV", "ENV"})
_DEFAULT_TRUSTED_PATH = (Path("/usr/local/bin"), Path("/usr/bin"), Path("/bin"))


def harden_env(
    base: Mapping[str, str],
    trusted_path: Sequence[Path],
) -> dict[str, str]:
    """返回清除了劫持入口并固定 PATH 的环境。"""
    env = dict(base)
    for key in list(env):
        if key in _FORBIDDEN_ENV or key.startswith("BASH_FUNC_"):
            del env[key]
    env["PATH"] = os.pathsep.join(str(path) for path in trusted_path)
    return env


class Executor:
    """带信号转发的最小执行器。"""

    def __init__(self, trusted_path: Sequence[Path] | None = None) -> None:
        self.trusted_path = (
            tuple(trusted_path) if trusted_path is not None else _DEFAULT_TRUSTED_PATH
        )

    def run(
        self,
        argv: Sequence[str],
        *,
        env: Mapping[str, str] | None = None,
        cwd: Path | None = None,
        pass_fds: Sequence[int] = (),
    ) -> ExecutionResult:
        """执行 argv 并等待结束；信号转发给子进程。"""
        hardened = harden_env(os.environ if env is None else env, self.trusted_path)
        started = time.monotonic()

        process = subprocess.Popen(
            list(argv),
            shell=False,
            env=hardened,
            cwd=str(cwd) if cwd is not None else None,
            pass_fds=tuple(pass_fds),
        )
        handlers = _install_signal_forwarders(process)
        try:
            returncode = process.wait()
        finally:
            _restore_handlers(handlers)

        duration_ms = int((time.monotonic() - started) * 1000)
        if returncode < 0:
            signum = -returncode
            return ExecutionResult(
                exit_code=128 + signum,
                signal=signum,
                duration_ms=duration_ms,
            )
        return ExecutionResult(
            exit_code=returncode,
            signal=None,
            duration_ms=duration_ms,
        )


def _install_signal_forwarders(process: Any) -> dict[int, Any]:
    if threading.current_thread() is not threading.main_thread():
        return {}

    def forward(signum: int, frame: FrameType | None) -> None:
        del frame
        if process.poll() is None:
            try:
                process.send_signal(signum)
            except ProcessLookupError:
                pass

    handlers: dict[int, Any] = {}
    for signum in (signal.SIGINT, signal.SIGTERM):
        try:
            handlers[signum] = signal.signal(signum, forward)
        except (ValueError, OSError):
            pass
    return handlers


def _restore_handlers(handlers: Mapping[int, Any]) -> None:
    for signum, handler in handlers.items():
        try:
            signal.signal(signum, handler)
        except (ValueError, OSError):
            pass
