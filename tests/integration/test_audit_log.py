"""T4-04 审计日志测试：schema、权限、脱敏、轮转、写失败不阻断。"""

from __future__ import annotations

import hashlib
import json
import stat

from sec_sandbox.gateway.audit_log import AuditEvent, AuditLog


def make_event(**kwargs) -> AuditEvent:
    params = {
        "source": "gateway",
        "decision": "allow",
        "reason": "SAFE_WHITELISTED",
        "mode": "command_string",
        "command_class": "bash_utility",
        "command_text": "ls",
    }
    params.update(kwargs)
    return AuditEvent(**params)


def read_records(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_append_schema_and_permissions(tmp_path):
    path = tmp_path / "state" / "audit.jsonl"
    log = AuditLog(path)

    log.append(make_event())

    assert path.is_file()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700

    record = read_records(path)[0]
    assert set(record) == {
        "schema_version",
        "event_id",
        "ts",
        "source",
        "pid",
        "depth",
        "mode",
        "class",
        "decision",
        "reason",
        "rule_ids",
        "network",
        "command_sha256",
        "command_preview",
        "exit_code",
        "signal",
        "duration_ms",
        "profile_hash",
        "error",
    }
    assert record["schema_version"] == 1
    assert record["command_sha256"] == hashlib.sha256(b"ls").hexdigest()
    assert record["command_preview"] is None


def test_command_text_is_not_logged_by_default(tmp_path):
    path = tmp_path / "audit.jsonl"
    AuditLog(path).append(make_event(command_text="cat ~/.ssh/id_rsa"))

    raw = path.read_text(encoding="utf-8")
    assert "id_rsa" not in raw
    assert "command_preview\": null" in raw


def test_command_preview_is_redacted_when_enabled(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path, log_command_text=True)

    log.append(make_event(command_text="GITHUB_TOKEN=ghp_secret ls"))

    preview = read_records(path)[0]["command_preview"]
    assert "ghp_secret" not in preview
    assert "[REDACTED]" in preview


def test_rotation_keeps_backup_limit(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path, max_bytes=1000, backups=2)

    for _ in range(20):
        log.append(make_event())

    assert path.exists()
    assert (tmp_path / "audit.jsonl.1").exists()
    assert not (tmp_path / "audit.jsonl.3").exists()


def test_write_failure_does_not_raise(tmp_path):
    AuditLog(tmp_path).append(make_event())  # 目标是目录，open 必然失败


def test_network_and_rule_ids_are_serialized(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)

    log.append(
        make_event(
            decision="deny",
            reason="SENSITIVE_PATH",
            rule_ids=("B2.SSH_KEY",),
            network={"decision": "deny", "reason": "NET_EXFILTRATION", "consulted_llm": False},
        )
    )

    record = read_records(path)[0]
    assert record["rule_ids"] == ["B2.SSH_KEY"]
    assert record["network"]["reason"] == "NET_EXFILTRATION"
