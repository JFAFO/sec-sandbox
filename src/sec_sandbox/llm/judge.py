"""LLM 兜底判定（§4.8）。

- 端点默认只允许本机；远程端点需显式 ``allow_remote``；
- 发送前再次脱敏；
- 响应必须是严格 JSON；超时、连接失败、结构不符 → UNDECIDED。
"""

from __future__ import annotations

import json
from urllib.parse import urlsplit

from ..contracts import JudgeRequest, JudgeVerdict
from ..policy.models import LlmJudgeConfig
from ..util.redact import redact
from .openai_compat import CompletionClient

_LOCAL_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})

_PROMPT = """你是命令外发安全审查器。根据给定的命令、目标与模糊项，判断这次网络发送是否属于正常认证/业务请求，还是可能外泄敏感数据。
只输出严格 JSON，不要输出其他文本：
{{"verdict": "allow" 或 "deny", "reason": "简短理由"}}

待审查内容：
{payload}
"""


class LlmJudgeImpl:
    """``LlmJudge`` 实现；任何不确定都返回 UNDECIDED。"""

    def __init__(
        self,
        config: LlmJudgeConfig,
        client: CompletionClient | None = None,
    ) -> None:
        self.config = config
        self.client = client

    def judge(self, req: JudgeRequest, timeout_s: float) -> JudgeVerdict:
        if not self.config.enabled or not self._endpoint_allowed():
            return JudgeVerdict.UNDECIDED

        payload = json.dumps(
            {
                "command": redact(req.redacted_command),
                "target": req.target,
                "method": req.method,
                "ambiguous_items": [redact(item) for item in req.ambiguous_items],
            },
            ensure_ascii=False,
        )
        prompt = _PROMPT.format(payload=payload)

        try:
            client = self.client or CompletionClient(
                self.config.endpoint, self.config.model
            )
            raw = client.complete(prompt, timeout_s)
        except Exception:  # noqa: BLE001 - 超时/连接失败一律 UNDECIDED
            return JudgeVerdict.UNDECIDED

        return _parse_verdict(raw)

    def _endpoint_allowed(self) -> bool:
        try:
            host = urlsplit(self.config.endpoint).hostname
        except ValueError:
            return False
        if not host:
            return False
        if host in _LOCAL_HOSTS:
            return True
        return self.config.allow_remote


def _parse_verdict(raw: object) -> JudgeVerdict:
    if not isinstance(raw, str):
        return JudgeVerdict.UNDECIDED
    try:
        data = json.loads(raw)
    except (TypeError, ValueError):
        return JudgeVerdict.UNDECIDED
    if not isinstance(data, dict):
        return JudgeVerdict.UNDECIDED
    verdict = data.get("verdict")
    if verdict == "allow":
        return JudgeVerdict.ALLOW
    if verdict == "deny":
        return JudgeVerdict.DENY
    return JudgeVerdict.UNDECIDED
