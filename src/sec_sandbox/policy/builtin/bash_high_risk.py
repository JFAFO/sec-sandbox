"""附录 B.1 / B.3 规则数据：高危命令与危险写入目标。"""

from __future__ import annotations

import re

# basename → 规则 ID（附录 B.1）
HIGH_RISK_COMMANDS: dict[str, str] = {
    "rm": "B1.RM",
    "wipefs": "B1.WIPEFS",
    "dd": "B1.DD",
    "shred": "B1.SHRED",
    "fdisk": "B1.FDISK",
    "parted": "B1.PARTED",
    "shutdown": "B1.SHUTDOWN",
    "reboot": "B1.REBOOT",
    "poweroff": "B1.POWEROFF",
    "halt": "B1.HALT",
    "mount": "B1.MOUNT",
    "umount": "B1.UMOUNT",
    "insmod": "B1.INSMOD",
    "rmmod": "B1.RMMOD",
    "modprobe": "B1.MODPROBE",
    "iptables": "B1.IPTABLES",
    "nft": "B1.NFT",
    "chown": "B1.CHOWN",
    "sudo": "B1.SUDO",
    "su": "B1.SU",
    "doas": "B1.DOAS",
    "kill": "B1.KILL",
    "pkill": "B1.PKILL",
    "killall": "B1.KILLALL",
    "crontab": "B3.CRONTAB",
}

# basename 前缀 → 规则 ID（mkfs.ext4、mkfs.xfs 等）
HIGH_RISK_PREFIXES: tuple[tuple[str, str], ...] = (("mkfs", "B1.MKFS"),)

# 只有递归模式才 Deny 的权限命令（普通 chmod 走降级）
RECURSIVE_PERMISSION_COMMANDS: dict[str, str] = {"chmod": "B1.CHMOD_RECURSIVE"}

# fork 炸弹：``:(){ :|:& };:`` 一类自递归函数
FORK_BOMB_PATTERN = re.compile(r":\s*\(\s*\)\s*\{[^}]*:\s*\|\s*:")

# 危险写入目标（附录 B.3）；同时用于重定向目标与写命令的目标参数
DANGEROUS_WRITE_PATTERNS: tuple[str, ...] = (
    "/etc/**",
    "/boot/**",
    "/sys/**",
    "/proc/**",
    "~/.ssh/**",
    "~/.aws/**",
    "~/.bashrc",
    "~/.zshrc",
    "~/.profile",
    "~/.bash_profile",
    "/etc/cron*",
    "~/.config/autostart",
    "~/.config/systemd/**",
    "**/.git/hooks/**",
)

# 这些命令的参数是写入目标，需检查 B.3
# 值为 True 时检查全部位置参数；为 False 时只检查最后一个参数
WRITE_COMMANDS: dict[str, bool] = {
    "cp": False,
    "mv": False,
    "mkdir": True,
    "touch": True,
    "tee": True,
}
