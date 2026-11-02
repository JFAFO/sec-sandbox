"""T1-02 脱敏测试：AKIA、eyJ、私钥块、*TOKEN* 赋值。"""

from __future__ import annotations

import pytest
from hypothesis import given, strategies as st

from sec_sandbox.util.redact import REDACTED, redact

AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_TEMP_KEY = "ASIAIOSFODNN7EXAMPLE"
JWT = (
    "eyJhbGciOiJIUzI1NiJ9."
    "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
    "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
)
PRIVATE_KEY = (
    "-----BEGIN OPENSSH PRIVATE KEY-----\n"
    "b3BlbnNzaC1rZXktdjEAAAAA\n"
    "-----END OPENSSH PRIVATE KEY-----"
)


@pytest.mark.parametrize("key", [AWS_KEY, AWS_TEMP_KEY])
def test_aws_access_key_redacted(key):
    out = redact(f"aws_access_key_id = {key}")
    assert key not in out
    assert REDACTED in out


def test_jwt_redacted():
    out = redact(f"Authorization: Bearer {JWT}")
    assert JWT not in out
    assert REDACTED in out


@pytest.mark.parametrize(
    "header",
    ["RSA PRIVATE KEY", "EC PRIVATE KEY", "OPENSSH PRIVATE KEY"],
)
def test_private_key_block_redacted(header):
    pem = (
        f"-----BEGIN {header}-----\n"
        "MIIEowIBAAKCAQEA\n"
        f"-----END {header}-----"
    )
    out = redact(f"before\n{pem}\nafter")
    assert "MIIEowIBAAKCAQEA" not in out
    assert "BEGIN" not in out
    assert out.startswith("before")
    assert out.endswith("after")


def test_pgp_private_key_block_redacted():
    pem = (
        "-----BEGIN PGP PRIVATE KEY BLOCK-----\n"
        "lQOYBGExamplePayload\n"
        "-----END PGP PRIVATE KEY BLOCK-----"
    )
    out = redact(pem)
    assert "lQOYBGExamplePayload" not in out
    assert REDACTED in out


@pytest.mark.parametrize(
    "text, secret",
    [
        ("GITHUB_TOKEN=ghp_secret_value", "ghp_secret_value"),
        ("MY_API_TOKEN: abc123", "abc123"),
        ('{"api_token": "s3cr3t"}', "s3cr3t"),
        ("export npm_TOKEN='tok_live_1'", "tok_live_1"),
        ("_TOKEN=hidden_value", "hidden_value"),
    ],
)
def test_token_assignment_redacted(text, secret):
    out = redact(text)
    assert secret not in out
    assert REDACTED in out


def test_json_structure_preserved():
    out = redact('{"api_token": "s3cr3t"}')
    assert out == '{"api_token": "[REDACTED]"}'


def test_benign_text_untouched():
    text = "tokenizer 和 hello world，没有赋值语句"
    assert redact(text) == text


def test_empty_text():
    assert redact("") == ""


@given(st.text(max_size=100))
def test_redact_idempotent(text):
    once = redact(text)
    assert redact(once) == once
