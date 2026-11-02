"""敏感路径模式（唯一源）：附录 B.2 + C.3 并集。

bash 侧、python 侧与网络外发溯源共用同一份规则（附录 C.3 说明）。
所有模式交给 ``util.paths.match_sensitive_pattern`` 匹配。
"""

from __future__ import annotations

SENSITIVE_PATH_PATTERNS: tuple[str, ...] = (
    # SSH / 云凭据 / GPG / 密码库
    "~/.ssh/*",
    "~/.aws/*",
    "~/.kube/*",
    "~/.config/gcloud/*",
    "~/.gnupg/*",
    "~/.password-store/*",
    "**/id_rsa*",
    # 各类 token
    "~/.npmrc",
    "~/.pypirc",
    "~/.netrc",
    "~/.git-credentials",
    "~/.vault-token",
    # 环境变量 / 证书 / 私钥 / 通用凭据
    "**/.env",
    "**/.env.*",
    "**/*.pem",
    "**/*.key",
    "**/*.p12",
    "**/*.jks",
    "**/credentials*",
    "**/*.secret*",
    # 系统敏感
    "/etc/shadow",
    "/etc/gshadow",
    "/etc/sudoers*",
    # 历史痕迹
    "~/.bash_history",
    "~/.zsh_history",
)
