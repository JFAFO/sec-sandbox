"""T3-02 / T3-03 / T3-04 运行时 audithook 测试。"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from sec_sandbox.contracts import ReasonCode
from sec_sandbox.python_audit.policy import RuntimePolicy, evaluate_connect

REPO_ROOT = Path(__file__).resolve().parents[2]
SRC_DIR = REPO_ROOT / "src"
INJECT_DIR = SRC_DIR / "sec_sandbox" / "python_audit"


def make_policy(safe_domains: tuple[str, ...] = ("example.com",)) -> RuntimePolicy:
    return RuntimePolicy(
        patterns=(),
        workspace=Path("/tmp"),
        safe_domains=safe_domains,
        audit_log=Path("/tmp/secsand-audit.jsonl"),
        pid=0,
    )


@pytest.mark.parametrize(
    "host",
    [
        "127.0.0.1",
        "10.0.0.1",
        "192.168.1.1",
        "169.254.169.254",
        "::1",
        "::ffff:127.0.0.1",
    ],
)
def test_internal_targets_denied(host):
    verdict = evaluate_connect((object(), (host, 80)), make_policy())
    assert verdict.denied
    assert verdict.reason is ReasonCode.NET_SSRF_TARGET


@pytest.mark.parametrize("host", ["example.com", "api.example.com"])
def test_safe_domains_allowed(host):
    assert not evaluate_connect((object(), (host, 443)), make_policy()).denied


@pytest.mark.parametrize("host", ["evil.com", "8.8.8.8"])
def test_other_targets_denied(host):
    verdict = evaluate_connect((object(), (host, 443)), make_policy())
    assert verdict.denied
    assert verdict.reason is ReasonCode.NET_EXFILTRATION


def test_unix_socket_allowed():
    assert not evaluate_connect(("/tmp/sock",), make_policy()).denied


def write_policy(path: Path, safe_domains: tuple[str, ...] = ()) -> Path:
    data = {
        "sensitive_patterns": [".env", "*.pem", "id_rsa*"],
        "sensitive_dirs": ["$HOME/.ssh"],
        "workspace": "$HOME/work",
        "safe_domains": list(safe_domains),
        "audit_log": "$HOME/.local/state/sec-sandbox/audit.jsonl",
        "pid": 0,
    }
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def run_python(code: str, home: Path, policy_path: Path | None = None):
    env = dict(os.environ)
    env["HOME"] = str(home)
    existing = env.get("PYTHONPATH", "")
    parts = [str(INJECT_DIR), str(SRC_DIR)]
    if existing:
        parts.append(existing)
    env["PYTHONPATH"] = os.pathsep.join(parts)
    if policy_path is None:
        env.pop("SECSAND_RUNTIME_POLICY", None)
    else:
        env["SECSAND_RUNTIME_POLICY"] = str(policy_path)

    return subprocess.run(
        [sys.executable, "-c", code],
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )


@pytest.fixture
def home(tmp_path) -> Path:
    work = tmp_path / "work"
    work.mkdir()
    return tmp_path


def test_sensitive_open_denied_and_audited(home, tmp_path):
    policy = write_policy(tmp_path / "policy.json")
    code = """
import os
try:
    open(os.path.expanduser("~/work/.env"), "w")
except PermissionError:
    print("DENIED")
"""

    proc = run_python(code, home, policy)

    assert proc.returncode == 0
    assert "DENIED" in proc.stdout
    assert "敏感数据访问" in proc.stderr
    assert not policy.exists()

    audit = home / ".local" / "state" / "sec-sandbox" / "audit.jsonl"
    records = [json.loads(line) for line in audit.read_text().splitlines()]
    assert any(record["source"] == "python_runtime" for record in records)
    assert any(record["reason"] == "SENSITIVE_PATH" for record in records)


def test_os_kill_denied(home, tmp_path):
    policy = write_policy(tmp_path / "policy.json")
    code = """
import os
try:
    os.kill(os.getpid(), 0)
except PermissionError:
    print("DENIED")
"""

    proc = run_python(code, home, policy)

    assert "DENIED" in proc.stdout


def test_ctypes_dlopen_denied(home, tmp_path):
    policy = write_policy(tmp_path / "policy.json")
    code = """
try:
    import ctypes
    ctypes.CDLL("libc.so.6")
except PermissionError:
    print("DENIED")
"""

    proc = run_python(code, home, policy)

    assert "DENIED" in proc.stdout


def test_os_chmod_denied(home, tmp_path):
    policy = write_policy(tmp_path / "policy.json")
    code = """
import os
try:
    os.chmod(os.path.expanduser("~/work/x"), 0o600)
except PermissionError:
    print("DENIED")
"""

    proc = run_python(code, home, policy)

    assert "DENIED" in proc.stdout


def test_benign_open_allowed(home, tmp_path):
    policy = write_policy(tmp_path / "policy.json")
    code = """
import os
open(os.path.expanduser("~/work/safe.txt"), "w").write("x")
print("OK")
"""

    proc = run_python(code, home, policy)

    assert proc.returncode == 0
    assert "OK" in proc.stdout
    assert (home / "work" / "safe.txt").is_file()


def test_without_policy_no_hook(home):
    code = """
import os
open(os.path.expanduser("~/work/.env"), "w").write("x")
print("OK")
"""

    proc = run_python(code, home, None)

    assert proc.returncode == 0
    assert "OK" in proc.stdout


def test_broken_policy_fails_closed(home, tmp_path):
    policy = tmp_path / "policy.json"
    policy.write_text("{not json", encoding="utf-8")

    proc = run_python("print('SHOULD NOT RUN')", home, policy)

    assert proc.returncode == 127
    assert "SHOULD NOT RUN" not in proc.stdout
    assert "内部错误" in proc.stderr


def test_socket_connect_loopback_denied(home, tmp_path):
    policy = write_policy(tmp_path / "policy.json")
    code = """
import socket
s = socket.socket()
try:
    s.connect(("127.0.0.1", 9))
except PermissionError:
    print("DENIED")
except OSError:
    print("OSERROR")
"""

    proc = run_python(code, home, policy)

    assert "DENIED" in proc.stdout
