"""T1-05 用户文案覆盖与泄漏测试（§6.3、§9 S-3）。"""

from __future__ import annotations

import inspect
import re

import pytest

from sec_sandbox.contracts import ReasonCode
from sec_sandbox.gateway.messages import (
    CLASS3_NOTICE,
    INTERNAL_ERROR,
    MESSAGES,
    message_for,
)

ALLOW_OR_DOWNGRADE = {
    ReasonCode.SAFE_WHITELISTED,
    ReasonCode.INTERACTIVE_SHELL,
    ReasonCode.PYTHON_STATIC_OK,
    ReasonCode.NET_SAFE_DOMAIN,
    ReasonCode.NET_PURE_FETCH,
    ReasonCode.PARSE_FAILED,
    ReasonCode.COMPOUND_COMMAND,
    ReasonCode.NOT_WHITELISTED,
    ReasonCode.PY_NEEDS_RUNTIME_AUDIT,
    ReasonCode.PY_DYNAMIC_CONSTRUCT,
    ReasonCode.ANALYZER_ERROR,
    ReasonCode.SCRIPT_DEFAULT_DOWNGRADE,
}

EXPECTED_DENY = set(ReasonCode) - ALLOW_OR_DOWNGRADE

LEAK_PATTERNS = [
    re.compile(r"rule", re.IGNORECASE),
    re.compile(r"regex", re.IGNORECASE),
    re.compile(r"\d"),  # 数字阈值
    re.compile(r"[/\\^$*+?{}\[\]|]"),  # ASCII 正则/路径元字符
]


def test_every_reason_is_covered():
    assert set(MESSAGES) == EXPECTED_DENY
    assert EXPECTED_DENY | ALLOW_OR_DOWNGRADE == set(ReasonCode)


@pytest.mark.parametrize("reason", sorted(EXPECTED_DENY, key=lambda item: item.name))
def test_deny_reason_renders_template(reason):
    message = message_for(reason)
    assert isinstance(message, str)
    assert message.startswith("[sec-sandbox] ")
    assert message.endswith("。")


@pytest.mark.parametrize(
    "reason", sorted(ALLOW_OR_DOWNGRADE, key=lambda item: item.name)
)
def test_non_deny_reason_has_no_message(reason):
    assert message_for(reason) is None


@pytest.mark.parametrize("reason", sorted(EXPECTED_DENY, key=lambda item: item.name))
def test_message_does_not_leak(reason):
    message = message_for(reason)
    body = message[len("[sec-sandbox] ") :]

    for pattern in LEAK_PATTERNS:
        assert not pattern.search(body), f"文案泄漏判据：{message}"

    assert reason.name not in message
    assert reason.value not in message


def test_messages_are_one_of_the_nine_templates():
    templates = {
        MESSAGES[ReasonCode.HIGH_RISK_COMMAND],
        MESSAGES[ReasonCode.SENSITIVE_PATH],
        MESSAGES[ReasonCode.DANGEROUS_REDIRECT],
        MESSAGES[ReasonCode.NET_EXFILTRATION],
        MESSAGES[ReasonCode.NET_SSRF_TARGET],
        MESSAGES[ReasonCode.INNER_NESTING_TOO_DEEP],
        MESSAGES[ReasonCode.INPUT_TOO_LARGE],
        INTERNAL_ERROR,
    }
    assert set(MESSAGES.values()) == templates
    assert CLASS3_NOTICE not in MESSAGES.values()


def test_message_api_takes_only_reason():
    parameters = list(inspect.signature(message_for).parameters)
    assert parameters == ["reason"]


def test_class3_notice_and_internal_error_do_not_leak():
    for message in (CLASS3_NOTICE, INTERNAL_ERROR):
        assert message.startswith("[sec-sandbox] ")
        assert "rule" not in message.lower()
        assert not any(char.isdigit() for char in message)
