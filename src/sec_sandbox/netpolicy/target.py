"""URL/IP/域名解析与分类（附录 D.2）。

只做字面量判定：**不做 DNS 解析**；域名解析后指向内网属于已知残余风险。
"""

from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit

_LOOPBACK_NAMES = frozenset({"localhost", "localhost.localdomain", "ip6-localhost"})


def split_host(target: str) -> str | None:
    """从 URL 或裸 ``host[:port]/path`` 中取出 host。"""
    text = target.strip()
    if not text:
        return None

    candidate = text if "://" in text else f"//{text}"
    try:
        host = urlsplit(candidate).hostname
    except ValueError:
        return None
    if not host:
        return None
    return host.rstrip(".")


def is_internal_host(host: str) -> bool:
    """回环、私网、链路本地、保留地址或 ``localhost``。"""
    lowered = host.lower()
    if lowered in _LOOPBACK_NAMES:
        return True

    try:
        address = ipaddress.ip_address(lowered)
    except ValueError:
        return False

    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    return (
        address.is_loopback
        or address.is_private
        or address.is_link_local
        or address.is_reserved
        or address.is_unspecified
    )


def is_safe_domain(host: str, safe_domains: tuple[str, ...]) -> bool:
    """host 等于安全域或为其子域。"""
    normalized = host.rstrip(".").lower()
    for domain in safe_domains:
        candidate = domain.strip().lower().rstrip(".").lstrip(".")
        if candidate and (
            normalized == candidate or normalized.endswith("." + candidate)
        ):
            return True
    return False
