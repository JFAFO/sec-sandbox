"""网络外发审查 ①–③：SSRF、安全域、纯取数（§4.7、附录 D）。"""

from __future__ import annotations

import posixpath
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from ..bash_audit.astutil import walk, word_text
from ..contracts import (
    AuditContext,
    JudgeRequest,
    JudgeVerdict,
    NetworkDecision,
    NetworkVerdict,
    ParsedBash,
    ReasonCode,
)
from ..util.redact import redact
from .source import inspect_send
from .target import is_internal_host, is_safe_domain, split_host

if TYPE_CHECKING:
    from ..policy.models import Profile

_NETWORK_COMMANDS = frozenset(
    {
        "curl",
        "wget",
        "git",
        "pip",
        "pip3",
        "npm",
        "apt",
        "apt-get",
        "ssh",
        "scp",
        "sftp",
        "nc",
        "ncat",
        "socat",
        "telnet",
    }
)
_GENERIC_CHANNELS = frozenset({"ssh", "scp", "sftp", "nc", "ncat", "socat", "telnet"})
_PASSTHROUGH_INSTALLERS = frozenset({"pip", "pip3", "npm", "apt", "apt-get"})

_UPLOAD_FLAGS = frozenset(
    {
        "-d",
        "--data",
        "--data-raw",
        "--data-binary",
        "--data-urlencode",
        "-F",
        "--form",
        "-T",
        "--upload-file",
        "--post-data",
        "--post-file",
    }
)
_VALUE_FLAGS = _UPLOAD_FLAGS | frozenset(
    {
        "-o",
        "--output",
        "-O",
        "--output-document",
        "-H",
        "--header",
        "-X",
        "--request",
        "-u",
        "--user",
        "-A",
        "--user-agent",
        "-e",
        "--referer",
        "-b",
        "--cookie",
        "-c",
        "--cookie-jar",
        "-w",
        "--write-out",
        "--connect-timeout",
        "--max-time",
        "--timeout",
        "--retry",
    }
)

_SKIP = NetworkVerdict(NetworkDecision.SKIP, ReasonCode.NET_UNSUPPORTED_COMMAND)


@dataclass(frozen=True)
class NetworkRules:
    """网络审查规则（由 profile 注入）。"""

    safe_domains: tuple[str, ...] = ()

    @classmethod
    def from_profile(cls, profile: Profile) -> NetworkRules:
        return cls(safe_domains=tuple(profile.network.safe_domains))


class NetworkAnalyzerImpl:
    """按命令识别 → 取/发 → 目标分类的顺序给出裁决。"""

    def __init__(
        self,
        rules: NetworkRules | None = None,
        judge: object | None = None,
        timeout_s: float = 1.5,
    ) -> None:
        self.rules = rules if rules is not None else NetworkRules()
        self.judge = judge
        self.timeout_s = timeout_s

    def analyze(
        self,
        parsed: ParsedBash | None,
        ctx: AuditContext,
    ) -> NetworkVerdict:
        if parsed is None or not parsed.ok:
            return _SKIP

        upstream = _pipeline_upstream(parsed)
        passed: NetworkVerdict | None = None
        for command in _iter_commands(parsed):
            name = _command_name(command)
            if name not in _NETWORK_COMMANDS:
                continue
            verdict = self._analyze_command(
                name, command, upstream.get(id(command), ()), parsed, ctx
            )
            if verdict.decision is NetworkDecision.DENY:
                return verdict
            if verdict.decision is NetworkDecision.PASS and passed is None:
                passed = verdict
        return passed if passed is not None else _SKIP

    def _analyze_command(
        self,
        name: str,
        command: Any,
        upstream: tuple[Any, ...],
        parsed: ParsedBash,
        ctx: AuditContext,
    ) -> NetworkVerdict:
        if name in _GENERIC_CHANNELS:
            return NetworkVerdict(
                NetworkDecision.DENY, ReasonCode.NET_UNSUPPORTED_COMMAND, ("D3.GENERIC",)
            )

        words = _word_nodes(command)

        if name in {"curl", "wget"}:
            return self._analyze_http(words, command, upstream, parsed, ctx)
        if name == "git":
            return self._analyze_git(words, parsed, ctx)
        if name in _PASSTHROUGH_INSTALLERS:
            return self._analyze_installer(words)
        return _SKIP

    def _analyze_http(
        self,
        words: list[Any],
        command: Any,
        upstream: tuple[Any, ...],
        parsed: ParsedBash,
        ctx: AuditContext,
    ) -> NetworkVerdict:
        method = _http_method(words)
        targets = _positional_targets(words)

        if not targets:
            return _SKIP

        hosts: list[str] = []
        for word in targets:
            text = word_text(word)
            if text is None:
                return NetworkVerdict(
                    NetworkDecision.DENY, ReasonCode.NET_DYNAMIC_TARGET, ("D6.DYNAMIC",)
                )
            host = split_host(text)
            if host is None:
                return NetworkVerdict(
                    NetworkDecision.DENY, ReasonCode.NET_DYNAMIC_TARGET, ("D6.DYNAMIC",)
                )
            if is_internal_host(host):
                return NetworkVerdict(
                    NetworkDecision.DENY, ReasonCode.NET_SSRF_TARGET, ("D2.SSRF",)
                )
            hosts.append(host)

        if method == "send":
            finding = inspect_send(command, upstream, ctx)
            if finding.denied:
                return NetworkVerdict(
                    NetworkDecision.DENY,
                    ReasonCode.NET_EXFILTRATION,
                    (finding.rule_id or "D4.SEND",),
                )
            return self._judge(parsed, hosts[0], "send", finding.ambiguous)

        for host in hosts:
            if is_safe_domain(host, self.rules.safe_domains):
                return NetworkVerdict(
                    NetworkDecision.PASS, ReasonCode.NET_SAFE_DOMAIN, ("D1.SAFE_DOMAIN",)
                )
        return NetworkVerdict(
            NetworkDecision.PASS, ReasonCode.NET_PURE_FETCH, ("D3.PURE_FETCH",)
        )

    def _analyze_git(
        self,
        words: list[Any],
        parsed: ParsedBash,
        ctx: AuditContext,
    ) -> NetworkVerdict:
        args = [word_text(word) for word in words[1:]]
        if not args or args[0] is None:
            return _SKIP
        subcommand = args[0]

        if subcommand in {"clone", "pull", "fetch"}:
            if subcommand == "clone" and len(args) > 1 and args[1] is not None:
                host = split_host(args[1])
                if host is None:
                    return NetworkVerdict(
                        NetworkDecision.DENY,
                        ReasonCode.NET_DYNAMIC_TARGET,
                        ("D6.DYNAMIC",),
                    )
                if is_internal_host(host):
                    return NetworkVerdict(
                        NetworkDecision.DENY, ReasonCode.NET_SSRF_TARGET, ("D2.SSRF",)
                    )
                if is_safe_domain(host, self.rules.safe_domains):
                    return NetworkVerdict(
                        NetworkDecision.PASS, ReasonCode.NET_SAFE_DOMAIN, ("D1.SAFE_DOMAIN",)
                    )
            return NetworkVerdict(
                NetworkDecision.PASS, ReasonCode.NET_PURE_FETCH, ("D3.PURE_FETCH",)
            )

        if subcommand == "push":
            # 无可见 payload，进入 ⑤；LLM 未启用时由 _judge 返回 Deny
            return self._judge(parsed, "", "send", ())
        return _SKIP

    def _judge(
        self,
        parsed: ParsedBash,
        target: str,
        method: str,
        ambiguous: tuple[str, ...],
    ) -> NetworkVerdict:
        if self.judge is None:
            return NetworkVerdict(
                NetworkDecision.DENY, ReasonCode.NET_JUDGE_UNDECIDED, ("D5.LLM_DISABLED",)
            )

        request = JudgeRequest(
            redacted_command=redact(parsed.text),
            target=target,
            method=method,
            ambiguous_items=ambiguous,
        )
        try:
            verdict = self.judge.judge(request, self.timeout_s)
        except Exception:  # noqa: BLE001 - LLM 异常按超时处理
            return NetworkVerdict(
                NetworkDecision.DENY, ReasonCode.NET_JUDGE_TIMEOUT, ("D5.TIMEOUT",)
            )

        if verdict is JudgeVerdict.ALLOW:
            return NetworkVerdict(
                NetworkDecision.PASS, ReasonCode.NET_PURE_FETCH, ("D5.ALLOW",)
            )
        if verdict is JudgeVerdict.DENY:
            return NetworkVerdict(
                NetworkDecision.DENY, ReasonCode.NET_JUDGE_DENIED, ("D5.DENY",)
            )
        return NetworkVerdict(
            NetworkDecision.DENY, ReasonCode.NET_JUDGE_UNDECIDED, ("D5.UNDECIDED",)
        )

    def _analyze_installer(self, words: list[Any]) -> NetworkVerdict:
        args = [word_text(word) for word in words[1:]]
        if args and args[0] in {"install", "download"}:
            return NetworkVerdict(
                NetworkDecision.PASS, ReasonCode.NET_PURE_FETCH, ("D3.PURE_FETCH",)
            )
        return _SKIP

def _pipeline_upstream(parsed: ParsedBash) -> dict[int, tuple[Any, ...]]:
    """记录每个命令在管道中的前序命令（用于 ④ 管道上游溯源）。"""
    mapping: dict[int, tuple[Any, ...]] = {}
    for root in parsed.nodes:
        for node in walk(root):
            if getattr(node, "kind", None) != "pipeline":
                continue
            commands = [
                part
                for part in getattr(node, "parts", ())
                if getattr(part, "kind", None) == "command"
            ]
            for index, command in enumerate(commands):
                mapping[id(command)] = tuple(commands[:index])
    return mapping


def _iter_commands(parsed: ParsedBash):
    for root in parsed.nodes:
        for node in walk(root):
            if getattr(node, "kind", None) == "command":
                yield node


def _command_name(command: Any) -> str:
    for part in getattr(command, "parts", ()):
        if getattr(part, "kind", None) == "word":
            text = word_text(part)
            return posixpath.basename(text) if text else ""
    return ""


def _word_nodes(command: Any) -> list[Any]:
    return [
        part for part in getattr(command, "parts", ()) if getattr(part, "kind", None) == "word"
    ]


def _is_upload_arg(text: str) -> bool:
    if text in _UPLOAD_FLAGS:
        return True
    for flag in _UPLOAD_FLAGS:
        if flag.startswith("--") and text.startswith(flag + "="):
            return True
        if not flag.startswith("--") and text.startswith(flag) and len(text) > len(flag):
            return True
    return False


def _http_method(words: list[Any]) -> str:
    texts = [word_text(word) or "" for word in words[1:]]
    index = 0
    while index < len(texts):
        text = texts[index]
        if _is_upload_arg(text):
            return "send"
        if text in {"-X", "--request"} and index + 1 < len(texts):
            if texts[index + 1].upper() in {"POST", "PUT", "PATCH"}:
                return "send"
        if text.startswith("-X") and text[2:].upper() in {"POST", "PUT", "PATCH"}:
            return "send"
        index += 1
    return "fetch"


def _positional_targets(words: list[Any]) -> list[Any]:
    """跳过选项及其值，返回位置参数（URL）。"""
    targets: list[Any] = []
    index = 1
    while index < len(words):
        text = word_text(words[index])
        raw = text if text is not None else (getattr(words[index], "word", "") or "")
        if raw.startswith("-"):
            index += 2 if raw in _VALUE_FLAGS and index + 1 < len(words) else 1
            continue
        targets.append(words[index])
        index += 1
    return targets
