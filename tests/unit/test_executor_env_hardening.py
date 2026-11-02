"""T4-03 执行器与环境硬化测试。"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

from sec_sandbox.gateway.executor import Executor, harden_env

TRUSTED = (Path("/usr/local/bin"), Path("/usr/bin"), Path("/bin"))


def test_harden_env_removes_hijack_entries():
    env = {
        "PATH": "/tmp/evil:/usr/bin",
        "BASH_ENV": "/tmp/evil.sh",
        "ENV": "/tmp/evil2.sh",
        "BASH_FUNC_ls%%": "() { echo hijacked; }",
        "HOME": "/tmp/home",
    }

    hardened = harden_env(env, TRUSTED)

    assert "BASH_ENV" not in hardened
    assert "ENV" not in hardened
    assert "BASH_FUNC_ls%%" not in hardened
    assert hardened["HOME"] == "/tmp/home"
    assert hardened["PATH"] == "/usr/local/bin:/usr/bin:/bin"


def test_hardened_env_visible_in_child():
    executor = Executor(TRUSTED)
    code = (
        "import os, sys; "
        "bad = 'BASH_ENV' in os.environ or os.environ['PATH'] != '/usr/local/bin:/usr/bin:/bin'; "
        "sys.exit(9 if bad else 0)"
    )

    result = executor.run(
        [sys.executable, "-c", code],
        env={"PATH": "/tmp/evil", "BASH_ENV": "/tmp/evil.sh"},
    )

    assert result.exit_code == 0
    assert result.signal is None


def test_exit_code_passthrough():
    executor = Executor(TRUSTED)
    result = executor.run([sys.executable, "-c", "raise SystemExit(3)"])
    assert result.exit_code == 3
    assert result.signal is None


def test_signal_exit_code_mapping():
    executor = Executor(TRUSTED)
    code = "import os, signal; os.kill(os.getpid(), signal.SIGTERM)"

    result = executor.run([sys.executable, "-c", code])

    assert result.signal == signal.SIGTERM
    assert result.exit_code == 128 + signal.SIGTERM


def test_popen_uses_shell_false_and_argv(monkeypatch):
    captured = {}

    class FakeProcess:
        returncode = 0

        def wait(self):
            return 0

        def poll(self):
            return 0

    def fake_popen(argv, **kwargs):
        captured["argv"] = argv
        captured["kwargs"] = kwargs
        return FakeProcess()

    monkeypatch.setattr(subprocess, "Popen", fake_popen)

    Executor(TRUSTED).run(["ls", "-la"], cwd=Path("/tmp"))

    assert captured["argv"] == ["ls", "-la"]
    assert captured["kwargs"]["shell"] is False
    assert captured["kwargs"]["cwd"] == "/tmp"


def test_signal_is_forwarded_to_child():
    executor = Executor(TRUSTED)
    child = [sys.executable, "-c", "import time; time.sleep(5)"]
    result_holder = {}

    def send_signal():
        time.sleep(0.5)
        os.kill(os.getpid(), signal.SIGTERM)

    sender = threading.Thread(target=send_signal)
    sender.start()
    try:
        result_holder["result"] = executor.run(child)
    finally:
        sender.join(timeout=5)

    result = result_holder["result"]
    assert result.signal == signal.SIGTERM
    assert result.exit_code == 128 + signal.SIGTERM
    assert result.duration_ms >= 0
