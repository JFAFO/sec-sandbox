"""生成 bwrap ``--seccomp`` 所需的 cBPF 程序（§4.6）。

- 用 libseccomp 解析 syscall 名；不可用时回退内置 x86_64 静态表；
- 显式拒绝 x32 ABI（syscall 号 >= 0x40000000）；
- 生成原始 ``struct sock_filter[]``，可写入 memfd 交给 bwrap。
"""

from __future__ import annotations

import ctypes
import os
import struct
from collections.abc import Callable, Sequence

from . import SandboxBuildError

# linux/filter.h
_BPF_LD_W_ABS = 0x20
_BPF_JMP_JEQ_K = 0x15
_BPF_JMP_JGE_K = 0x35
_BPF_RET_K = 0x06

# linux/seccomp.h
_SECCOMP_RET_KILL_PROCESS = 0x80000000
_SECCOMP_RET_ALLOW = 0x7FFF0000
_SECCOMP_RET_ERRNO = 0x00050000
_EPERM = 1

# linux/audit.h
_AUDIT_ARCH_X86_64 = 0xC000003E
_X32_SYSCALL_BASE = 0x40000000

_OFFSET_NR = 0
_OFFSET_ARCH = 4

# libseccomp 不可用时的 x86_64 静态表
_STATIC_X86_64: dict[str, int] = {
    "ptrace": 101,
    "mount": 165,
    "umount2": 166,
    "kexec_load": 246,
    "init_module": 175,
    "finit_module": 313,
    "delete_module": 176,
    "reboot": 169,
    "swapon": 167,
    "swapoff": 168,
    "setns": 308,
    "unshare": 272,
    "bpf": 321,
    "perf_event_open": 298,
    "keyctl": 250,
    "add_key": 248,
    "request_key": 249,
    "userfaultfd": 323,
}

_LIBRARY: ctypes.CDLL | None = None
_LIBRARY_LOADED = False


class SeccompError(SandboxBuildError):
    """seccomp 程序生成失败。"""


def generate_bpf(
    denylist: Sequence[str],
    *,
    resolver: Callable[[str], int] | None = None,
) -> bytes:
    """生成拒绝 ``denylist``、允许其余 syscall 的 cBPF 程序。"""
    resolve = resolver if resolver is not None else resolve_syscall

    numbers: list[int] = []
    for name in denylist:
        number = resolve(name)
        if number < 0:
            raise SeccompError(f"无法解析 syscall：{name!r}")
        if number not in numbers:
            numbers.append(number)
    numbers.sort()

    instructions: list[tuple[int, int, int, int]] = [
        (_BPF_LD_W_ABS, 0, 0, _OFFSET_ARCH),
        # arch 匹配则跳到 LD nr；否则执行下一条 KILL
        (_BPF_JMP_JEQ_K, 1, 0, _AUDIT_ARCH_X86_64),
        (_BPF_RET_K, 0, 0, _SECCOMP_RET_KILL_PROCESS),
        (_BPF_LD_W_ABS, 0, 0, _OFFSET_NR),
    ]

    allow_index = 5 + len(numbers)
    errno_index = allow_index + 1
    kill_index = errno_index + 1

    # x32：nr >= 0x40000000 → kill
    instructions.append(
        (_BPF_JMP_JGE_K, kill_index - 5, 0, _X32_SYSCALL_BASE)
    )

    # JEQ 命中跳到 ERRNO；不命中继续到 ALLOW（因此 ERRNO 必须放在 ALLOW 之后）
    for offset, number in enumerate(numbers):
        index = 5 + offset
        instructions.append(
            (_BPF_JMP_JEQ_K, errno_index - (index + 1), 0, number)
        )

    instructions.append((_BPF_RET_K, 0, 0, _SECCOMP_RET_ALLOW))
    instructions.append((_BPF_RET_K, 0, 0, _SECCOMP_RET_ERRNO | _EPERM))
    instructions.append((_BPF_RET_K, 0, 0, _SECCOMP_RET_KILL_PROCESS))

    del allow_index  # 显式保留索引计算，便于阅读
    return b"".join(struct.pack("<HBBI", code, jt, jf, k) for code, jt, jf, k in instructions)


def resolve_syscall(name: str) -> int:
    """优先用 libseccomp 解析；失败时查静态表。"""
    number = _resolve_with_libseccomp(name)
    if number is not None:
        return number
    if name in _STATIC_X86_64:
        return _STATIC_X86_64[name]
    raise SeccompError(f"无法解析 syscall：{name!r}")


def libseccomp_available() -> bool:
    """libseccomp 是否可加载（否则回退静态表）。"""
    return _load_library() is not None


def write_memfd(bpf: bytes, name: str = "secsand-seccomp") -> int:
    """把 BPF 写入 memfd 并返回 fd（可交给 ``--seccomp``）。"""
    fd = os.memfd_create(name, flags=os.MFD_CLOEXEC)
    try:
        os.write(fd, bpf)
        os.lseek(fd, 0, os.SEEK_SET)
    except OSError:
        os.close(fd)
        raise
    return fd


def _resolve_with_libseccomp(name: str) -> int | None:
    library = _load_library()
    if library is None:
        return None
    number = library.seccomp_syscall_resolve_name(name.encode("ascii"))
    return number if number >= 0 else None


def _load_library() -> ctypes.CDLL | None:
    global _LIBRARY, _LIBRARY_LOADED
    if _LIBRARY_LOADED:
        return _LIBRARY

    _LIBRARY_LOADED = True
    for candidate in ("libseccomp.so.2", "libseccomp.so"):
        try:
            library = ctypes.CDLL(candidate)
        except OSError:
            continue
        library.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
        library.seccomp_syscall_resolve_name.restype = ctypes.c_int
        _LIBRARY = library
        break
    return _LIBRARY
