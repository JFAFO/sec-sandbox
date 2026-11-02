"""凭据字面量脱敏。

用于写日志与送 LLM 之前（§4.8、§9 S-11）。覆盖：

- AWS access key（``AKIA…``/``ASIA…``）；
- JWT（``eyJ…`` 三段式）；
- PEM 私钥块（RSA/EC/DSA/OPENSSH/PGP 等）；
- ``*TOKEN*`` 形式的环境变量或配置项的值。
"""

from __future__ import annotations

import re

REDACTED = "[REDACTED]"

_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY[A-Z ]*-----.*?"
    r"-----END [A-Z0-9 ]*PRIVATE KEY[A-Z ]*-----",
    re.DOTALL,
)
_AWS_KEY_RE = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")
_JWT_RE = re.compile(
    r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*"
)
_TOKEN_ASSIGN_RE = re.compile(
    r"(?<![A-Za-z0-9_])([\"']?[A-Za-z_][A-Za-z0-9_]*TOKEN[A-Za-z0-9_]*[\"']?)"
    r"(\s*[=:]\s*)"
    r"('[^']*'|\"[^\"]*\"|\S+)",
    re.IGNORECASE,
)


def redact(text: str) -> str:
    """返回脱敏后的文本；空串原样返回。"""
    if not text:
        return text
    text = _PRIVATE_KEY_RE.sub(REDACTED, text)
    text = _AWS_KEY_RE.sub(REDACTED, text)
    text = _JWT_RE.sub(REDACTED, text)
    return _TOKEN_ASSIGN_RE.sub(_redact_assignment, text)


def _redact_assignment(match: re.Match[str]) -> str:
    """保留键名、分隔符与引号，只替换值。"""
    name, sep, value = match.groups()
    if value[:1] in {"'", '"'}:
        quote = value[0]
        value = f"{quote}{REDACTED}{quote}"
    else:
        value = REDACTED
    return f"{name}{sep}{value}"
