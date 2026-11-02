"""``safe-exec`` 组合根：加载 profile、解析 argv、构造 Broker 并处理交互模式。"""

from __future__ import annotations

import hashlib
import os
import shutil
import sys
from pathlib import Path

from ..bash_audit.analyzer import BashAnalyzer
from ..bash_audit.rules import RuleSet
from ..contracts import InvocationMode, ReasonCode
from ..llm.judge import LlmJudgeImpl
from ..netpolicy.analyzer import NetworkAnalyzerImpl, NetworkRules
from ..policy.loader import ProfileError, load_profile
from ..policy.models import Profile
from ..python_audit.static import PythonStaticAuditor
from ..sandbox.builder import SandboxBuilderImpl
from ..sandbox.paths import probe_paths
from ..sandbox.seccomp import generate_bpf, write_memfd
from ..util import logging as internal_log
from .audit_log import AuditLog
from .broker import Broker
from .executor import Executor
from .messages import INTERNAL_ERROR, USAGE_ERROR, message_for
from .parser import InputTooLargeError, ParseError, parse_invocation


def main(argv: list[str] | None = None) -> int:
    profile_path_text = os.environ.get("SECSAND_PROFILE")
    if not profile_path_text:
        print(INTERNAL_ERROR, file=sys.stderr)
        return 127

    profile_path = Path(profile_path_text)
    try:
        profile = load_profile(profile_path)
    except ProfileError as exc:
        internal_log.debug(f"profile 加载失败：{exc}")
        print(INTERNAL_ERROR, file=sys.stderr)
        return 127

    try:
        request = parse_invocation(
            sys.argv[1:] if argv is None else argv,
            stdin_is_tty=sys.stdin.isatty(),
            max_input_bytes=profile.bash.max_script_bytes,
            cwd=Path.cwd(),
            env=os.environ,
        )
    except InputTooLargeError:
        print(message_for(ReasonCode.INPUT_TOO_LARGE), file=sys.stderr)
        return 126
    except ParseError as exc:
        internal_log.debug(f"参数解析失败：{exc}")
        print(USAGE_ERROR, file=sys.stderr)
        return 64

    broker = _build_broker(profile, profile_path)

    if request.mode is InvocationMode.INTERACTIVE:
        broker.handle(request)
        real_bash = _real_bash(profile)
        os.execv(real_bash, [real_bash])
        return 127

    return broker.handle(request)


def _build_broker(profile: Profile, profile_path: Path) -> Broker:
    paths = probe_paths(profile)
    seccomp_fd = None
    if profile.inner.seccomp_denylist:
        try:
            seccomp_fd = write_memfd(generate_bpf(profile.inner.seccomp_denylist))
        except Exception as exc:  # noqa: BLE001 - seccomp 失败时记录并继续（外层仍有限制）
            internal_log.warning(f"seccomp 生成失败，本次不装载过滤器：{exc}")
            seccomp_fd = None

    sandbox = SandboxBuilderImpl(
        safe_exec=_safe_exec_path(),
        profile_path=profile_path,
        paths=paths,
        seccomp_fd=seccomp_fd,
    )
    audit = AuditLog(
        profile.audit.log_dir / "audit.jsonl",
        max_bytes=profile.audit.max_bytes,
        backups=profile.audit.backups,
        log_command_text=profile.audit.log_command_text,
    )
    judge = (
        LlmJudgeImpl(profile.network.llm_judge)
        if profile.network.llm_judge.enabled
        else None
    )
    network = NetworkAnalyzerImpl(
        NetworkRules.from_profile(profile),
        judge=judge,
        timeout_s=profile.network.llm_judge.timeout_ms / 1000,
    )

    return Broker(
        profile,
        BashAnalyzer(RuleSet.from_profile(profile)),
        PythonStaticAuditor(),
        network,
        sandbox,
        Executor(profile.bash.trusted_path),
        audit,
        real_bash=_real_bash(profile),
        profile_hash=_profile_hash(profile_path),
    )


def _safe_exec_path() -> Path:
    candidate = Path(__file__).resolve().parents[3] / "bin" / "safe-exec"
    if candidate.exists():
        return candidate
    found = shutil.which("safe-exec")
    return Path(found) if found else candidate


def _real_bash(profile: Profile) -> str:
    configured = os.environ.get("SECSAND_REAL_BASH")
    if configured and Path(configured).exists():
        return configured
    runtime = probe_paths(profile)
    return str(runtime.real_bash) if runtime.real_bash is not None else "/usr/bin/bash"


def _profile_hash(profile_path: Path) -> str:
    try:
        return hashlib.sha256(profile_path.read_bytes()).hexdigest()
    except OSError:
        return ""
