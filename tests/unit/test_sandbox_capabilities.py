"""bwrap 能力探测测试（Ubuntu 22.04 的 0.6.1 与新版行为差异）。"""

from __future__ import annotations

from pathlib import Path

from sec_sandbox.sandbox.capabilities import probe_bwrap


def _fake_bwrap(tmp_path: Path, help_text: str) -> Path:
    script = tmp_path / "bwrap"
    script.write_text(
        "#!/bin/sh\ncat <<'EOF'\n" + help_text + "\nEOF\n",
        encoding="utf-8",
    )
    script.chmod(0o755)
    return script


def test_probe_detects_size_support(tmp_path):
    fake = _fake_bwrap(tmp_path, "Usage: bwrap [OPTIONS]\n  --size BYTES")

    assert probe_bwrap(str(fake)).supports_size is True


def test_probe_detects_missing_size_support(tmp_path):
    fake = _fake_bwrap(tmp_path, "Usage: bwrap [OPTIONS]\n  --tmpfs DIR")

    assert probe_bwrap(str(fake)).supports_size is False


def test_probe_missing_binary_is_unsupported(tmp_path):
    assert probe_bwrap(str(tmp_path / "nope")).supports_size is False
