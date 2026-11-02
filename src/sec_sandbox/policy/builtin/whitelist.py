"""类 1 默认 utility 白名单（唯一源）。"""

from __future__ import annotations

DEFAULT_UTILITY_WHITELIST: tuple[str, ...] = (
    "ls",
    "cat",
    "head",
    "tail",
    "grep",
    "wc",
    "echo",
    "printf",
    "pwd",
    "cd",
    "mkdir",
    "touch",
    "cp",
    "mv",
    "curl",
    "wget",
)

# bash 内建命令没有独立可执行文件，不做 realpath 校验
BASH_BUILTINS = frozenset({"cd", "echo", "printf", "pwd"})
