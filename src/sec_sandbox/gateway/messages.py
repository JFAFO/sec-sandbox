"""用户可见文案（《实现级架构设计》§6.3）。

**唯一来源**。禁止在此之外拼接面向用户的拦截提示；文案中不得出现
规则号、正则、阈值、命令原文或文件路径原文。
"""

from __future__ import annotations

from ..contracts import ReasonCode

DANGEROUS_COMMAND = (
    "[sec-sandbox] 已拦截：该命令被判定为高风险系统操作（类别：危险命令）。"
)
SENSITIVE_DATA = (
    "[sec-sandbox] 已拦截：该命令试图访问受保护的数据（类别：敏感数据访问）。"
)
PROTECTED_WRITE = (
    "[sec-sandbox] 已拦截：该命令试图修改受保护的位置（类别：受保护写入）。"
)
NETWORK_EXFILTRATION = (
    "[sec-sandbox] 已拦截：检测到向外部发送数据的行为（类别：数据外发）。"
)
NETWORK_TARGET = (
    "[sec-sandbox] 已拦截：网络目标不被允许（类别：网络目标限制）。"
)
NESTING_TOO_DEEP = (
    "[sec-sandbox] 已拦截：命令嵌套层级过深（类别：沙箱限制）。"
)
INPUT_TOO_LARGE = (
    "[sec-sandbox] 已拦截：输入超出安全上限（类别：输入限制）。"
)
INTERNAL_ERROR = (
    "[sec-sandbox] 内部错误：无法安全地准备执行环境，命令未执行。"
)
CLASS3_NOTICE = "[sec-sandbox] 权限已锁紧，该命令将在受限环境中执行。"

# 每个 Deny 原因只映射到 §6.3 的一条模板。
MESSAGES: dict[ReasonCode, str] = {
    ReasonCode.HIGH_RISK_COMMAND: DANGEROUS_COMMAND,
    ReasonCode.PY_FORBIDDEN_IMPORT: DANGEROUS_COMMAND,
    ReasonCode.PY_DYNAMIC_EVAL: DANGEROUS_COMMAND,
    ReasonCode.SENSITIVE_PATH: SENSITIVE_DATA,
    ReasonCode.DANGEROUS_REDIRECT: PROTECTED_WRITE,
    ReasonCode.NET_EXFILTRATION: NETWORK_EXFILTRATION,
    ReasonCode.NET_JUDGE_DENIED: NETWORK_EXFILTRATION,
    ReasonCode.NET_JUDGE_TIMEOUT: NETWORK_EXFILTRATION,
    ReasonCode.NET_JUDGE_UNDECIDED: NETWORK_EXFILTRATION,
    ReasonCode.NET_SSRF_TARGET: NETWORK_TARGET,
    ReasonCode.NET_DYNAMIC_TARGET: NETWORK_TARGET,
    ReasonCode.NET_UNSUPPORTED_COMMAND: NETWORK_TARGET,
    ReasonCode.INNER_NESTING_TOO_DEEP: NESTING_TOO_DEEP,
    ReasonCode.INPUT_TOO_LARGE: INPUT_TOO_LARGE,
    ReasonCode.PROFILE_INVALID: INTERNAL_ERROR,
    ReasonCode.REAL_BASH_MISSING: INTERNAL_ERROR,
    ReasonCode.SANDBOX_BUILD_ERROR: INTERNAL_ERROR,
    ReasonCode.INTERNAL_ERROR: INTERNAL_ERROR,
}


def message_for(reason: ReasonCode) -> str | None:
    """返回 Deny 原因对应的用户文案；放行/降级原因返回 ``None``。"""
    return MESSAGES.get(reason)
