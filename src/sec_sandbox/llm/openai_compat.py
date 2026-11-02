"""最小 OpenAI 兼容 HTTP 客户端（urllib，无第三方依赖）。"""

from __future__ import annotations

import json
import urllib.request


class CompletionClient:
    """调用 ``/v1/chat/completions`` 兼容端点。"""

    def __init__(
        self,
        endpoint: str,
        model: str,
        api_key: str | None = None,
    ) -> None:
        self.endpoint = endpoint
        self.model = model
        self.api_key = api_key

    def complete(self, prompt: str, timeout_s: float) -> str:
        payload = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0,
        }
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        request = urllib.request.Request(
            self.endpoint,
            data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=timeout_s) as response:
            body = response.read()
        data = json.loads(body.decode("utf-8"))
        return data["choices"][0]["message"]["content"]
