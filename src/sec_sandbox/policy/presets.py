"""内置 profile 预设：``strict`` / ``standard`` / ``loose``。

预设是唯一的默认值来源（§5.1）。预设加载时跳过 workspace 存在性检查，
由配置前端在启动时校验。
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

from .builtin.whitelist import DEFAULT_UTILITY_WHITELIST
from .models import Profile
from .schema import parse_profile

_PRESET_FACTORIES: dict[str, Callable[[], dict[str, Any]]] = {}


def preset_names() -> tuple[str, ...]:
    """返回全部预设名称。"""
    return tuple(_PRESET_FACTORIES)


def get_preset(name: str, *, workspace: str | Path | None = None) -> Profile:
    """构造指定预设；``workspace`` 可覆盖默认的 ``$HOME/project``。"""
    factory = _PRESET_FACTORIES.get(name)
    if factory is None:
        raise ValueError(f"未知预设：{name!r}（可选：{', '.join(preset_names())}）")

    data = factory()
    if workspace is not None:
        text = str(workspace)
        if not text.startswith("$HOME") and not Path(text).is_absolute():
            raise ValueError(f"workspace 必须是绝对路径或 $HOME 前缀：{text!r}")
        data["workspace"] = text

    result = parse_profile(data, check_workspace=False)
    if result.profile is None:
        detail = "；".join(f"{issue.path}: {issue.message}" for issue in result.errors)
        raise RuntimeError(f"内置预设 {name!r} 非法（实现缺陷）：{detail}")
    return result.profile


def _base() -> dict[str, Any]:
    """standard 预设的完整数据；其余预设在此基础上调整。"""
    return {
        "schema_version": 1,
        "profile_name": "standard",
        "workspace": "$HOME/project",
        "workspace_write_mode": "bind",
        "filesystem": {
            "read_blacklist": [
                {"path": "$HOME/.ssh", "action": "mask"},
                {"path": "$HOME/.aws", "action": "mask"},
                {"path": "/etc/shadow", "action": "devnull"},
            ],
            "write_whitelist": [
                "$HOME/.claude",
                "$HOME/.claude.json",
                "$HOME/.local/state/sec-sandbox",
            ],
            "tmp_size_bytes": 64 * 1024 * 1024,
        },
        "resources": {
            "memory_max": "512M",
            "pids_max": 64,
            "cpu_quota": "50%",
        },
        "bash": {
            "utility_whitelist": list(DEFAULT_UTILITY_WHITELIST),
            "trusted_path": ["/usr/local/bin", "/usr/bin", "/bin"],
            "allow_scripts": False,
            "max_script_bytes": 1024 * 1024,
        },
        "python": {
            "allowed_interpreters": ["/usr/bin/python3", "/usr/bin/python3.10"],
            "max_source_bytes": 1024 * 1024,
        },
        "network": {
            "enabled": True,
            "safe_domains": [
                "pypi.org",
                "registry.npmjs.org",
                "github.com",
                "api.anthropic.com",
            ],
            "llm_judge": {
                "enabled": False,
                "endpoint": "http://127.0.0.1:11434/v1/chat/completions",
                "model": "local-judge",
                "timeout_ms": 1500,
                "allow_remote": False,
            },
        },
        "inner": {
            "max_depth": 2,
            "masked_executables": [
                "/usr/bin/mount",
                "/usr/bin/umount",
                "/usr/bin/sudo",
                "/usr/bin/su",
                "/usr/sbin/modprobe",
                "/usr/sbin/insmod",
            ],
            "seccomp_denylist": [
                "ptrace",
                "mount",
                "umount2",
                "kexec_load",
                "init_module",
                "finit_module",
                "delete_module",
                "reboot",
                "swapon",
                "swapoff",
                "setns",
                "unshare",
                "bpf",
                "perf_event_open",
                "keyctl",
                "add_key",
                "request_key",
                "userfaultfd",
            ],
        },
        "audit": {
            "log_dir": "$HOME/.local/state/sec-sandbox",
            "log_command_text": False,
            "max_bytes": 10 * 1024 * 1024,
            "backups": 5,
        },
        "notices": {"class3_notice": True},
    }


def _standard() -> dict[str, Any]:
    return _base()


def _strict() -> dict[str, Any]:
    data = _base()
    data["profile_name"] = "strict"
    data["filesystem"]["read_blacklist"].extend(
        [
            {"path": "$HOME/.gnupg", "action": "mask"},
            {"path": "$HOME/.kube", "action": "mask"},
            {"path": "$HOME/.password-store", "action": "mask"},
            {"path": "$HOME/.config/gcloud", "action": "mask"},
        ]
    )
    data["resources"] = {
        "memory_max": "256M",
        "pids_max": 32,
        "cpu_quota": "25%",
    }
    data["bash"]["allow_scripts"] = False
    data["inner"]["max_depth"] = 1
    return data


def _loose() -> dict[str, Any]:
    data = _base()
    data["profile_name"] = "loose"
    data["resources"] = {
        "memory_max": "2G",
        "pids_max": 256,
        "cpu_quota": "200%",
    }
    data["bash"]["allow_scripts"] = True
    data["inner"]["max_depth"] = 3
    return data


_PRESET_FACTORIES.update(
    {
        "strict": _strict,
        "standard": _standard,
        "loose": _loose,
    }
)
