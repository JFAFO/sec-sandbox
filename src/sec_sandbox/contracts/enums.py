"""公共枚举与内部原因码。

对应《实现级架构设计》§4.1、§6.1、§6.2。契约层零内部依赖，只使用标准库。

约定：
- 业务枚举继承 ``str, Enum``，成员值即 JSON/审计日志中的字符串；
- ``ReasonCode`` 是内部原因码，只进审计日志，**不得直接写入 stderr**（§6.3）；
- ``ExitCode`` 只覆盖固定语义码；``0-125`` 与 ``128+N`` 由执行器动态透传。
"""

from __future__ import annotations

from enum import Enum, IntEnum


class InvocationMode(str, Enum):
    """``safe-exec`` 的调用形态（§4.2）。"""

    INTERACTIVE = "interactive"        # 无参 + tty：直接放行交互 shell
    COMMAND_STRING = "command_string"  # bash -c "<text>"
    SCRIPT = "script"                  # bash <file>
    STDIN = "stdin"                    # bash -s / 无参 + 非 tty
    UNKNOWN = "unknown"                # 未知 flag：不猜测，原样交内层沙箱（§4.2）


class CommandClass(str, Enum):
    """三类路由（§4.1）。"""

    BASH_UTILITY = "bash_utility"    # 类 1
    PYTHON_SCRIPT = "python_script"  # 类 2
    SANDBOXED = "sandboxed"          # 类 3


class Decision(str, Enum):
    """执行线判定。"""

    ALLOW = "allow"
    DOWNGRADE = "downgrade"
    DENY = "deny"


class NetworkDecision(str, Enum):
    """网络线判定（§4.7）。"""

    PASS = "pass"
    DENY = "deny"
    SKIP = "skip"  # 无网络命令 / 类 3 无法解析


class CommandShape(str, Enum):
    """M2 对 bash 命令的形状分类（§4.4）。"""

    SIMPLE = "simple"
    COMPOUND = "compound"
    UNPARSEABLE = "unparseable"


class JudgeVerdict(str, Enum):
    """LLM 兜底裁决（§4.8）。无法判定按 Deny 处理。"""

    ALLOW = "allow"
    DENY = "deny"
    UNDECIDED = "undecided"


class ReasonCode(str, Enum):
    """内部原因码（§6.2）。取值即审计事件中的 ``reason`` 字段。"""

    # 放行
    SAFE_WHITELISTED = "SAFE_WHITELISTED"
    INTERACTIVE_SHELL = "INTERACTIVE_SHELL"
    PYTHON_STATIC_OK = "PYTHON_STATIC_OK"
    NET_SAFE_DOMAIN = "NET_SAFE_DOMAIN"
    NET_PURE_FETCH = "NET_PURE_FETCH"

    # 降级
    PARSE_FAILED = "PARSE_FAILED"
    COMPOUND_COMMAND = "COMPOUND_COMMAND"
    NOT_WHITELISTED = "NOT_WHITELISTED"
    PY_NEEDS_RUNTIME_AUDIT = "PY_NEEDS_RUNTIME_AUDIT"
    PY_DYNAMIC_CONSTRUCT = "PY_DYNAMIC_CONSTRUCT"
    ANALYZER_ERROR = "ANALYZER_ERROR"
    SCRIPT_DEFAULT_DOWNGRADE = "SCRIPT_DEFAULT_DOWNGRADE"

    # 执行线 Deny
    HIGH_RISK_COMMAND = "HIGH_RISK_COMMAND"
    SENSITIVE_PATH = "SENSITIVE_PATH"
    DANGEROUS_REDIRECT = "DANGEROUS_REDIRECT"
    PY_FORBIDDEN_IMPORT = "PY_FORBIDDEN_IMPORT"
    PY_DYNAMIC_EVAL = "PY_DYNAMIC_EVAL"
    INPUT_TOO_LARGE = "INPUT_TOO_LARGE"
    INNER_NESTING_TOO_DEEP = "INNER_NESTING_TOO_DEEP"

    # 网络线 Deny
    NET_SSRF_TARGET = "NET_SSRF_TARGET"
    NET_EXFILTRATION = "NET_EXFILTRATION"
    NET_DYNAMIC_TARGET = "NET_DYNAMIC_TARGET"
    NET_UNSUPPORTED_COMMAND = "NET_UNSUPPORTED_COMMAND"
    NET_JUDGE_DENIED = "NET_JUDGE_DENIED"
    NET_JUDGE_TIMEOUT = "NET_JUDGE_TIMEOUT"
    NET_JUDGE_UNDECIDED = "NET_JUDGE_UNDECIDED"

    # 内部
    PROFILE_INVALID = "PROFILE_INVALID"
    REAL_BASH_MISSING = "REAL_BASH_MISSING"
    SANDBOX_BUILD_ERROR = "SANDBOX_BUILD_ERROR"
    INTERNAL_ERROR = "INTERNAL_ERROR"


class ExitCode(IntEnum):
    """网关固定退出码（§6.1）。

    ``0-125`` 原样透传子进程退出码，``128+N`` 表示被信号 N 终止，二者均不枚举。
    """

    USAGE_ERROR = 64
    POLICY_DENY = 126
    INTERNAL_ERROR = 127
