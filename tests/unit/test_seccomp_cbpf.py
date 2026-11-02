"""T5-05 seccomp cBPF 生成测试。"""

from __future__ import annotations

import os
import struct

import pytest

from sec_sandbox.sandbox import seccomp
from sec_sandbox.sandbox.seccomp import (
    SeccompError,
    generate_bpf,
    resolve_syscall,
    write_memfd,
)

ARCH_X86_64 = 0xC000003E
X32_BASE = 0x40000000
KILL = 0x80000000
ALLOW = 0x7FFF0000
ERRNO_EPERM = 0x00050001


def decode(bpf: bytes):
    assert len(bpf) % 8 == 0
    return [
        struct.unpack_from("<HBBI", bpf, offset)
        for offset in range(0, len(bpf), 8)
    ]


def test_single_syscall_program():
    bpf = generate_bpf(("ptrace",), resolver=lambda name: 101)
    instructions = decode(bpf)

    assert instructions[0] == (0x20, 0, 0, 4)  # LD arch
    assert instructions[1] == (0x15, 1, 0, ARCH_X86_64)
    assert instructions[2] == (0x06, 0, 0, KILL)
    assert instructions[3] == (0x20, 0, 0, 0)  # LD nr
    assert instructions[4] == (0x35, 3, 0, X32_BASE)
    assert instructions[5] == (0x15, 1, 0, 101)  # JEQ ptrace -> ERRNO
    assert instructions[6] == (0x06, 0, 0, ALLOW)
    assert instructions[7] == (0x06, 0, 0, ERRNO_EPERM)
    assert instructions[8] == (0x06, 0, 0, KILL)


def test_program_bytes_prefix():
    bpf = generate_bpf(("ptrace",), resolver=lambda name: 101)

    assert bpf[:8] == struct.pack("<HBBI", 0x20, 0, 0, 4)


def test_multiple_syscalls_jump_offsets():
    numbers = {"ptrace": 101, "mount": 165, "bpf": 321}
    bpf = generate_bpf(("bpf", "ptrace", "mount"), resolver=numbers.__getitem__)
    instructions = decode(bpf)

    assert len(instructions) == 11
    assert instructions[4] == (0x35, 5, 0, X32_BASE)
    assert instructions[5] == (0x15, 3, 0, 101)
    assert instructions[6] == (0x15, 2, 0, 165)
    assert instructions[7] == (0x15, 1, 0, 321)
    assert instructions[8] == (0x06, 0, 0, ALLOW)
    assert instructions[9] == (0x06, 0, 0, ERRNO_EPERM)
    assert instructions[10] == (0x06, 0, 0, KILL)


def test_empty_denylist_still_has_arch_and_x32_checks():
    instructions = decode(generate_bpf((), resolver=lambda name: 0))

    assert instructions[1][3] == ARCH_X86_64
    assert instructions[4][3] == X32_BASE
    assert instructions[-1][3] == KILL


def test_duplicate_syscalls_are_deduplicated():
    bpf = generate_bpf(("ptrace", "ptrace"), resolver=lambda name: 101)

    assert len(decode(bpf)) == 9


def test_resolve_syscall_returns_x86_64_number():
    assert resolve_syscall("ptrace") == 101
    assert resolve_syscall("mount") == 165


def test_resolve_unknown_raises():
    with pytest.raises(SeccompError):
        resolve_syscall("definitely_not_a_syscall")


def test_static_table_fallback(monkeypatch):
    monkeypatch.setattr(seccomp, "_LIBRARY_LOADED", True)
    monkeypatch.setattr(seccomp, "_LIBRARY", None)

    assert resolve_syscall("bpf") == 321
    with pytest.raises(SeccompError):
        resolve_syscall("definitely_not_a_syscall")


def test_write_memfd_roundtrip():
    bpf = generate_bpf(("ptrace",), resolver=lambda name: 101)
    fd = write_memfd(bpf)
    try:
        os.lseek(fd, 0, os.SEEK_SET)
        assert os.read(fd, len(bpf)) == bpf
    finally:
        os.close(fd)
