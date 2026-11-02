"""bwrap 能力探测（跨发行版兼容）。

Ubuntu 22.04 自带 bubblewrap 0.6.1，不支持 ``--size`` 与 ``--tmp-overlay``；
WSL/新版本可能支持。构建挂载参数前先探测，避免在目标 VM 上生成
bwrap 无法识别的选项。

本模块只读 ``bwrap --help``，不改变系统状态。
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass

_DEFAULT_BWRAP = "bwrap"


@dataclass(frozen=True)
class BwrapCapabilities:
    """一次探测得到的 bwrap 能力快照。"""

    supports_size: bool = False


def probe_bwrap(bwrap: str = _DEFAULT_BWRAP, *, timeout: float = 5.0) -> BwrapCapabilities:
    """探测 ``bwrap`` 是否支持 ``--size``；无法执行时按不支持处理。"""
    try:
        result = subprocess.run(
            [bwrap, "--help"],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return BwrapCapabilities()

    help_text = f"{result.stdout or ''}\n{result.stderr or ''}"
    return BwrapCapabilities(supports_size="--size" in help_text)
