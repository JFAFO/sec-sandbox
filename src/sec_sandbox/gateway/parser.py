"""``safe-exec`` 参数解析。

对应《实现级架构设计》§2.3 第 2 步与 §4.2：

============  =====================================================
形态           解析结果
============  =====================================================
无参 + tty     ``INTERACTIVE``
``-c text``    ``COMMAND_STRING``
脚本文件        ``SCRIPT``（读取内容，受 ``max_input_bytes`` 限制）
``-s``/非 tty  ``STDIN``（读取 stdin，受同一上限限制）
``-i``/``-l``  ``INTERACTIVE``；若同时出现 ``-c`` 则按 ``COMMAND_STRING``
其他 flag       ``UNKNOWN``：不猜测，原样交给类 3
============  =====================================================

本模块**只解析，不执行任何命令**。脚本/stdin 超限抛
:class:`InputTooLargeError`，由 Broker 转为 Deny（``INPUT_TOO_LARGE``）；
用法错误抛 :class:`ParseError`，CLI 返回 64。
"""

from __future__ import annotations

import os
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import IO

from ..contracts import CommandRequest, InvocationMode


class ParseError(Exception):
    """argv 或环境变量用法错误（CLI 返回 64）。"""


class InputTooLargeError(Exception):
    """脚本或 stdin 超过 ``max_input_bytes``（Broker 应 Deny）。"""


def parse_invocation(
    argv: Sequence[str],
    *,
    stdin_is_tty: bool,
    max_input_bytes: int,
    cwd: Path | None = None,
    env: Mapping[str, str] | None = None,
    stdin: IO[str] | IO[bytes] | None = None,
) -> CommandRequest:
    """把 ``safe-exec`` 的 argv（不含程序名）解析为 :class:`CommandRequest`。"""
    args = tuple(argv)
    work_dir = Path(cwd) if cwd is not None else Path.cwd()
    environment = dict(os.environ if env is None else env)
    depth = _parse_depth(environment.get("SECSAND_DEPTH", "0"))

    mode, command_text, script_path = _classify(
        args,
        stdin_is_tty=stdin_is_tty,
        max_input_bytes=max_input_bytes,
        cwd=work_dir,
        stdin=stdin,
    )
    return CommandRequest(
        argv=args,
        mode=mode,
        command_text=command_text,
        script_path=script_path,
        cwd=work_dir,
        env=environment,
        depth=depth,
    )


def _classify(
    args: tuple[str, ...],
    *,
    stdin_is_tty: bool,
    max_input_bytes: int,
    cwd: Path,
    stdin: IO[str] | IO[bytes] | None,
) -> tuple[InvocationMode, str | None, Path | None]:
    index = 0
    while index < len(args):
        arg = args[index]
        if arg == "--" or arg == "-":
            index += 1
            break
        if not arg.startswith("-"):
            break  # 第一个非选项参数即脚本
        if arg == "-c":
            if index + 1 >= len(args):
                raise ParseError("-c 缺少命令文本")
            return InvocationMode.COMMAND_STRING, args[index + 1], None
        if arg == "-s":
            return InvocationMode.STDIN, _read_stdin(stdin, max_input_bytes), None
        if _is_interactive_flag(arg):
            index += 1
            continue
        # 不猜测未知 flag，原样交给类 3
        return InvocationMode.UNKNOWN, None, None

    if index < len(args):
        return _read_script(args[index], cwd=cwd, limit=max_input_bytes)
    if stdin_is_tty:
        return InvocationMode.INTERACTIVE, None, None
    return InvocationMode.STDIN, _read_stdin(stdin, max_input_bytes), None


def _is_interactive_flag(arg: str) -> bool:
    if arg in {"--interactive", "--login"}:
        return True
    if arg.startswith("--"):
        return False
    # 由 -i/-l 组成的短选项组合，如 -i、-l、-il、-li
    return len(arg) > 1 and set(arg[1:]) <= {"i", "l"}


def _read_stdin(
    stream: IO[str] | IO[bytes] | None,
    limit: int,
) -> str:
    source = stream if stream is not None else getattr(sys.stdin, "buffer", sys.stdin)
    data = source.read(limit + 1)
    if isinstance(data, str):
        if len(data.encode("utf-8", errors="surrogatepass")) > limit:
            raise InputTooLargeError(f"stdin 超过 {limit} 字节")
        return data
    if len(data) > limit:
        raise InputTooLargeError(f"stdin 超过 {limit} 字节")
    return data.decode("utf-8", errors="replace")


def _read_script(
    raw_path: str,
    *,
    cwd: Path,
    limit: int,
) -> tuple[InvocationMode, str, Path]:
    candidate = Path(raw_path)
    path = candidate if candidate.is_absolute() else cwd / candidate
    try:
        if not path.is_file():
            raise ParseError(f"脚本不存在或不是普通文件：{raw_path}")
        if path.stat().st_size > limit:
            raise InputTooLargeError(f"脚本超过 {limit} 字节：{raw_path}")
        data = path.read_bytes()
    except OSError as exc:
        raise ParseError(f"无法读取脚本：{raw_path}") from exc

    if len(data) > limit:
        raise InputTooLargeError(f"脚本超过 {limit} 字节：{raw_path}")
    return (
        InvocationMode.SCRIPT,
        data.decode("utf-8", errors="replace"),
        path.resolve(),
    )


def _parse_depth(raw: str) -> int:
    try:
        depth = int(raw)
    except (TypeError, ValueError) as exc:
        raise ParseError(f"SECSAND_DEPTH 非法：{raw!r}") from exc
    if depth < 0:
        raise ParseError(f"SECSAND_DEPTH 不能为负：{raw!r}")
    return depth
