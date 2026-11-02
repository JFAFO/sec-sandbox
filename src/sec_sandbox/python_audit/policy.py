"""运行时审计策略：策略文件解析与 audithook 事件裁决（附录 C.2）。

运行在类 2 子进程内。策略只存在于内存，读完临时文件立即删除。
"""

from __future__ import annotations

import ipaddress
import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..contracts import ReasonCode
from ..util.paths import match_sensitive_pattern


@dataclass(frozen=True)
class RuntimePolicy:
    """类 2 运行时策略（§5.3）。"""

    patterns: tuple[str, ...]
    workspace: Path
    safe_domains: tuple[str, ...]
    audit_log: Path
    pid: int

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> RuntimePolicy:
        home = Path.home()
        sensitive_dirs = tuple(
            _expand(item, home) for item in data.get("sensitive_dirs", ())
        )
        sensitive_names = tuple(str(item) for item in data.get("sensitive_patterns", ()))

        patterns = [str(directory) for directory in sensitive_dirs]
        patterns.extend(f"{directory}/*" for directory in sensitive_dirs)
        patterns.extend(
            name if "/" in name else f"**/{name}" for name in sensitive_names
        )

        return cls(
            patterns=tuple(patterns),
            workspace=_expand(data.get("workspace", "$HOME"), home),
            safe_domains=tuple(str(item) for item in data.get("safe_domains", ())),
            audit_log=_expand(data.get("audit_log", "$HOME/.local/state/sec-sandbox/audit.jsonl"), home),
            pid=int(data.get("pid", 0)),
        )


@dataclass(frozen=True)
class RuntimeVerdict:
    """运行时事件裁决。"""

    denied: bool
    reason: ReasonCode | None = None

    @property
    def allowed(self) -> bool:
        return not self.denied


_ALLOW = RuntimeVerdict(False)


def evaluate_event(
    event: str,
    args: tuple[Any, ...],
    policy: RuntimePolicy,
) -> RuntimeVerdict:
    """把 audithook 事件映射为裁决；网络事件见 :func:`evaluate_connect`。"""
    if event == "ctypes.dlopen":
        return RuntimeVerdict(True, ReasonCode.PY_FORBIDDEN_IMPORT)
    if event in {"os.kill", "os.setuid", "os.setgid"}:
        return RuntimeVerdict(True, ReasonCode.HIGH_RISK_COMMAND)
    if event in {"os.chmod", "os.chown"}:
        return RuntimeVerdict(True, ReasonCode.HIGH_RISK_COMMAND)
    if event == "open":
        return _check_path(args[0] if args else None, policy)
    if event in {"os.remove", "os.rmdir", "shutil.rmtree"}:
        return _check_path(args[0] if args else None, policy)
    if event == "os.rename":
        for value in args[:2]:
            verdict = _check_path(value, policy)
            if verdict.denied:
                return verdict
        return _ALLOW
    if event == "socket.connect":
        return evaluate_connect(args, policy)
    return _ALLOW


def evaluate_connect(args: tuple[Any, ...], policy: RuntimePolicy) -> RuntimeVerdict:
    """``socket.connect`` 的目标判定（附录 C.2 / §2.7）。

    内网/回环/链路本地/保留地址 → SSRF Deny；安全域放行；其余 → 外发 Deny。
    Unix domain socket（地址为路径字符串）不属于网络外发，放行。
    """
    address = args[-1] if len(args) >= 2 else (args[0] if args else None)
    host = _connect_host(address)
    if host is None:
        return _ALLOW

    ip = _parse_ip(host)
    if ip is not None:
        if _is_internal(ip):
            return RuntimeVerdict(True, ReasonCode.NET_SSRF_TARGET)
        return RuntimeVerdict(True, ReasonCode.NET_EXFILTRATION)

    if _is_safe_domain(host, policy.safe_domains):
        return _ALLOW
    return RuntimeVerdict(True, ReasonCode.NET_EXFILTRATION)


def _connect_host(address: Any) -> str | None:
    if isinstance(address, (str, bytes, bytearray)):
        return None  # AF_UNIX 路径
    if isinstance(address, tuple) and address:
        host = address[0]
        if isinstance(host, bytes):
            host = host.decode("ascii", "replace")
        if isinstance(host, str):
            return host.strip().strip("[]")
    return ""  # 未知格式交给 Deny


def _parse_ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


def _is_internal(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return (
        ip.is_loopback
        or ip.is_private
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_unspecified
    )


def _is_safe_domain(host: str, safe_domains: tuple[str, ...]) -> bool:
    normalized = host.rstrip(".").lower()
    for domain in safe_domains:
        candidate = domain.strip().lower().rstrip(".").lstrip(".")
        if candidate and (
            normalized == candidate or normalized.endswith("." + candidate)
        ):
            return True
    return False


def _check_path(value: Any, policy: RuntimePolicy) -> RuntimeVerdict:
    if not isinstance(value, (str, bytes, os.PathLike)):
        return _ALLOW
    try:
        text = os.fsdecode(value)
    except (TypeError, ValueError):
        return _ALLOW
    absolute = Path(os.path.abspath(text))
    if match_sensitive_pattern(absolute, policy.patterns) is not None:
        return RuntimeVerdict(True, ReasonCode.SENSITIVE_PATH)
    return _ALLOW


def _expand(raw: Any, home: Path) -> Path:
    text = str(raw)
    if text == "$HOME" or text.startswith("$HOME/"):
        text = str(home) + text[len("$HOME"):]
    return Path(os.path.realpath(text))
