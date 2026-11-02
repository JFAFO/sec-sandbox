"""类 2 注入入口：放到 ``PYTHONPATH`` 首位，Python 启动时自动导入。

只做一件事：若存在 ``SECSAND_RUNTIME_POLICY``，在脚本代码执行前注册 audithook。
策略加载失败时必须 **fail-closed**：不能在没有 hook 的情况下继续执行类 2 代码。
"""

from __future__ import annotations

import os

_policy = os.environ.get("SECSAND_RUNTIME_POLICY")
if _policy:
    try:
        from sec_sandbox.python_audit.runtime import install

        install(_policy)
    except Exception:  # noqa: BLE001 - 无 hook 时不允许执行类 2 代码
        import sys

        sys.stderr.write(
            "[sec-sandbox] 内部错误：无法安全地准备执行环境，命令未执行。\n"
        )
        os._exit(127)
