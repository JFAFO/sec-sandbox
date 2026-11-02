#!/usr/bin/env bash
# =============================================================================
# 面向大模型智能体的命令执行行为管控系统 —— 环境安装与自检脚本
#
# 适用系统：Ubuntu 22.04 LTS x86_64（主目标，完整虚拟机）
#           Ubuntu 24.04 等可作为开发机，但内核/cgroup 结论必须在目标 VM 复核
# 设计原则：
#   1. 幂等：可重复执行，不覆盖已有虚拟环境；
#   2. 只安装本系统真正依赖的包，不引入额外运行时依赖（运行时仅 bashlex）；
#   3. 安装后立即做黑盒自检，输出可直接粘贴进环境自检记录；
#   4. 不修改 shell 配置、不写死用户名与绝对路径（除用户显式指定）。
#
# 用法：
#   sudo ./setup.sh --mode vm          # 目标虚拟机（推荐）
#   sudo ./setup.sh --mode wsl         # WSL 开发机
#   ./setup.sh --check                 # 只检查，不安装
#   sudo ./setup.sh --mode vm --with-test-tools
# =============================================================================
set -euo pipefail

# ---------------------------------------------------------------- 默认参数 ---
MODE="auto"
CHECK_ONLY=0
CREATE_VENV=1
ENABLE_LINGER=1
WITH_TEST_TOOLS=0
WITH_SSHFS=0
WITH_SSH_SERVER=0
WITH_VM_TOOLS=0
PROJECT_DIR="${PROJECT_DIR:-$HOME/sec-sandbox}"
BASHLEX_VERSION="${BASHLEX_VERSION:-0.18}"

# ---------------------------------------------------------------- 输出函数 ---
if [ -t 1 ]; then
    C_BLUE=$'\033[1;34m'; C_GREEN=$'\033[1;32m'; C_YELLOW=$'\033[1;33m'
    C_RED=$'\033[1;31m'; C_RESET=$'\033[0m'
else
    C_BLUE=""; C_GREEN=""; C_YELLOW=""; C_RED=""; C_RESET=""
fi

log()  { printf '%s[setup]%s %s\n' "$C_BLUE" "$C_RESET" "$*"; }
ok()   { printf '%s[通过]%s %s\n' "$C_GREEN" "$C_RESET" "$*"; }
warn() { printf '%s[警告]%s %s\n' "$C_YELLOW" "$C_RESET" "$*" >&2; }
err()  { printf '%s[失败]%s %s\n' "$C_RED" "$C_RESET" "$*" >&2; }
die()  { err "$*"; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

usage() {
    cat <<'EOF'
用法: setup.sh [选项]

  --mode vm|wsl|bare|auto   目标形态（默认 auto 自动检测）
                              vm   完整 Ubuntu 虚拟机（主目标）
                              wsl  WSL 开发机（不能替代目标环境）
                              bare 裸机开发环境
  --check                   只做环境检查，不安装任何软件（无需 sudo）
  --project-dir PATH        项目目录（默认 ~/sec-sandbox）
  --no-venv                 不创建 Python 虚拟环境
  --no-linger               不尝试启用 systemd linger
  --with-test-tools         额外安装 strace/bpftrace/hyperfine/capsh/tcpdump/tmux/shellcheck
  --with-sshfs              额外安装 sshfs 与 openssh-client（开发机）
  --with-ssh-server         额外安装并启用 openssh-server（目标虚拟机）
  --with-vm-tools           额外安装 open-vm-tools（VMware 目标机）
  -h, --help                显示本帮助
EOF
}

# ---------------------------------------------------------------- 参数解析 ---
while [ $# -gt 0 ]; do
    case "$1" in
        --mode)            MODE="${2:-}"; shift 2 ;;
        --check)           CHECK_ONLY=1; shift ;;
        --project-dir)     PROJECT_DIR="${2:-}"; shift 2 ;;
        --no-venv)         CREATE_VENV=0; shift ;;
        --no-linger)       ENABLE_LINGER=0; shift ;;
        --with-test-tools) WITH_TEST_TOOLS=1; shift ;;
        --with-sshfs)      WITH_SSHFS=1; shift ;;
        --with-ssh-server) WITH_SSH_SERVER=1; shift ;;
        --with-vm-tools)   WITH_VM_TOOLS=1; shift ;;
        -h|--help)         usage; exit 0 ;;
        *)                 die "未知参数：$1（用 --help 查看用法）" ;;
    esac
done

case "$MODE" in
    auto|vm|wsl|bare) ;;
    *) die "--mode 只能是 auto/vm/wsl/bare，当前：$MODE" ;;
esac

# ---------------------------------------------------------------- 环境识别 ---
ARCH="$(uname -m)"
[ "$ARCH" = "x86_64" ] || die "仅支持 x86_64，当前架构：$ARCH（seccomp/内核行为不可比）"

[ -r /etc/os-release ] || die "无法读取 /etc/os-release，不支持的系统"
# shellcheck disable=SC1091
. /etc/os-release
case "${ID:-}" in
    ubuntu|debian) ;;
    *) die "仅支持 Ubuntu/Debian，当前：${PRETTY_NAME:-未知}" ;;
esac

IS_WSL=0
if grep -qi microsoft /proc/version 2>/dev/null; then
    IS_WSL=1
fi

VIRT=""
if have systemd-detect-virt; then
    VIRT="$(systemd-detect-virt 2>/dev/null || true)"
fi

if [ "$MODE" = "auto" ]; then
    if [ "$IS_WSL" -eq 1 ]; then
        MODE="wsl"
    elif [ -n "$VIRT" ] && [ "$VIRT" != "none" ]; then
        MODE="vm"
        # VMware 目标机默认补装 open-vm-tools
        if [ "$VIRT" = "vmware" ]; then
            WITH_VM_TOOLS=1
        fi
    else
        MODE="bare"
    fi
fi

log "系统：${PRETTY_NAME:-$ID} / 内核 $(uname -r) / $ARCH"
log "形态：$MODE（自动检测虚拟化：${VIRT:-未知}）"

if [ "$ID" = "ubuntu" ] && [ "${VERSION_ID:-}" != "22.04" ]; then
    warn "目标版本为 Ubuntu 22.04；当前为 ${VERSION_ID:-未知}。"
    warn "WSL/新版本仅作开发，bwrap/cgroup/seccomp 结论必须在 22.04 目标 VM 复核。"
fi

if [ -r /proc/sys/kernel/apparmor_restrict_unprivileged_userns ]; then
    if [ "$(cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns)" != "0" ]; then
        warn "AppArmor 正在限制非特权 user namespace（Ubuntu 24.04 常见）。"
        warn "bwrap 可能失败；目标环境请使用 Ubuntu 22.04，或由管理员关闭该限制。"
    fi
fi

# ---------------------------------------------------------------- 选择 Python
pick_python() {
    if have python3.10; then echo "python3.10"; return 0; fi
    if have python3; then echo "python3"; return 0; fi
    return 1
}

# ---------------------------------------------------------------- 检查函数 ---
CHECK_FAILED=0
check_all() {
    CHECK_FAILED=0
    log "==== 沙箱依赖自检 ===="

    # 1. bubblewrap
    if have bwrap; then
        ok "bubblewrap：$(bwrap --version 2>/dev/null || echo 已安装)"
        local flag help_text
        help_text="$(bwrap --help 2>&1 || true)"
        for flag in --seccomp --tmp-overlay --size --unshare-pid --die-with-parent; do
            if grep -q -- "$flag" <<<"$help_text"; then
                ok "bwrap 支持 $flag"
            else
                warn "bwrap 不支持 $flag（版本过旧？）"
            fi
        done
    else
        err "bubblewrap 未安装"
        CHECK_FAILED=1
    fi

    # 2. user namespace + mount namespace
    if unshare -Urm true 2>/dev/null; then
        ok "非特权 user namespace + mount namespace 可用"
    else
        err "unshare -Urm 失败：非特权 userns 被禁用或被策略拦截"
        CHECK_FAILED=1
    fi

    # 3. bwrap 冒烟测试与嵌套测试
    if have bwrap; then
        if bwrap --ro-bind / / --dev /dev --proc /proc --tmpfs /tmp true 2>/dev/null; then
            ok "bwrap 基本冒烟测试通过"
        else
            err "bwrap 基本冒烟测试失败（检查 userns/AppArmor）"
            CHECK_FAILED=1
        fi
        if bwrap --ro-bind / / --dev /dev --proc /proc --tmpfs /tmp \
                bwrap --ro-bind / / --dev /dev --proc /proc --tmpfs /tmp true 2>/dev/null; then
            ok "嵌套 bwrap 通过（类 3 依赖）"
        else
            err "嵌套 bwrap 失败（类 3 无法执行）"
            CHECK_FAILED=1
        fi

        # 外层 bwrap 会把真 bash 绑定到已有文件 /usr/bin/real-bash
        if [ -e /usr/bin/real-bash ]; then
            ok "真 bash 备份：/usr/bin/real-bash"
        else
            warn "缺少 /usr/bin/real-bash；安装模式会创建（外层 bwrap 必需）"
        fi
    fi

    # 4. cgroup v2 统一层级
    if [ -f /sys/fs/cgroup/cgroup.controllers ]; then
        ok "cgroup v2 统一层级可用（controllers: $(cat /sys/fs/cgroup/cgroup.controllers)）"
    else
        if [ "$IS_WSL" -eq 1 ]; then
            warn "WSL 为混合 cgroup（v1 + v2 unified），不能代表目标环境；请到 22.04 VM 复核"
        else
            err "未检测到 cgroup v2 统一层级（cgroup.controllers 不存在）"
            CHECK_FAILED=1
        fi
    fi

    # 5. systemd 用户委托
    if have systemd-run && systemd-run --scope --user -p MemoryMax=64M -p TasksMax=32 true >/dev/null 2>&1; then
        ok "systemd-run --user 委托可用"
    else
        err "systemd-run --user 失败；在目标机尝试 loginctl enable-linger \$USER"
        CHECK_FAILED=1
    fi

    # 6. seccomp 内核支持
    if [ -r /proc/sys/kernel/seccomp/actions_avail ]; then
        ok "seccomp filter 可用（actions: $(cat /proc/sys/kernel/seccomp/actions_avail)）"
    else
        err "内核未暴露 seccomp actions_avail，无法装载 cBPF 规则"
        CHECK_FAILED=1
    fi

    # 7. libseccomp（用于把 syscall 名称解析为编号）
    if ldconfig -p 2>/dev/null | grep 'libseccomp\.so' >/dev/null 2>&1; then
        ok "libseccomp 已安装"
    else
        err "libseccomp 未安装（sandbox/seccomp.py 需要）"
        CHECK_FAILED=1
    fi

    # 8. overlayfs（--tmp-overlay / overlay 可写区）
    if grep -qw overlay /proc/filesystems 2>/dev/null; then
        ok "overlayfs 可用"
    else
        warn "overlayfs 不可用：--tmp-overlay 方案将失效（工作区仍可用 --bind）"
    fi

    # 9. Python 版本与 bashlex
    local py
    if py="$(pick_python)"; then
        ok "Python：$("$py" --version 2>&1)"
        if [ "$("$py" -c 'import sys;print(f"{sys.version_info.major}.{sys.version_info.minor}")')" != "3.10" ]; then
            warn "目标环境要求 Python 3.10（当前为 $("$py" --version 2>&1)）；audithook 行为需在目标机复核"
        fi
    else
        err "未找到 python3"
        CHECK_FAILED=1
    fi

    if [ -x "$PROJECT_DIR/.venv/bin/python" ]; then
        if "$PROJECT_DIR/.venv/bin/python" -c 'import bashlex' 2>/dev/null; then
            ok "bashlex 可导入（venv：$PROJECT_DIR/.venv）"
        else
            err "venv 已存在但 bashlex 不可导入"
            CHECK_FAILED=1
        fi
    else
        warn "未找到 $PROJECT_DIR/.venv（尚未创建虚拟环境）"
    fi

    if [ "$CHECK_FAILED" -eq 0 ]; then
        log "==== 全部关键项通过 ===="
    else
        err "==== 存在未通过的关键项，请按提示处理 ===="
    fi
    return "$CHECK_FAILED"
}

# ---------------------------------------------------------------- 仅检查模式
if [ "$CHECK_ONLY" -eq 1 ]; then
    check_all || exit 1
    exit 0
fi

# ---------------------------------------------------------------- 安装依赖 ---
if [ "$(id -u)" -eq 0 ]; then
    SUDO=""
    TARGET_USER="${SUDO_USER:-$USER}"
else
    have sudo || die "需要 root 或 sudo 权限来安装系统依赖"
    SUDO="sudo"
    TARGET_USER="$USER"
fi

apt_install() {
    log "安装：$*"
    $SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y "$@"
}

apt_install_optional() {
    local pkg
    for pkg in "$@"; do
        if $SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y "$pkg" >/dev/null 2>&1; then
            ok "已安装可选包：$pkg"
        else
            warn "可选包安装失败（可忽略）：$pkg"
        fi
    done
}

log "更新 apt 索引"
$SUDO env DEBIAN_FRONTEND=noninteractive apt-get update

BASE_PKGS=(bubblewrap git curl ca-certificates jq libseccomp2 iproute2 procps libcap2-bin)
if apt-cache show python3.10 >/dev/null 2>&1; then
    BASE_PKGS+=(python3.10 python3.10-venv)
else
    warn "系统仓库没有 python3.10，使用默认 python3（目标环境仍建议 22.04 + 3.10）"
    BASE_PKGS+=(python3 python3-venv)
fi

apt_install "${BASE_PKGS[@]}"

# 真 bash 备份：外层 bwrap 需要把 real-bash 绑定到已存在的目标文件
REAL_BASH_TARGET="/usr/bin/real-bash"
if [ ! -e "$REAL_BASH_TARGET" ]; then
    # 不能命名为 BASH_SOURCE：它是 bash 的只读特殊变量，赋值会让 set -e 静默退出。
    BASH_REAL="$(readlink -f /usr/bin/bash 2>/dev/null || readlink -f /bin/bash)"
    $SUDO ln -s "$BASH_REAL" "$REAL_BASH_TARGET"
    ok "已创建真 bash 备份：$REAL_BASH_TARGET -> $BASH_REAL"
else
    ok "真 bash 备份已存在：$REAL_BASH_TARGET"
fi

case "$MODE" in
    vm)
        WITH_SSH_SERVER=1
        if [ "$VIRT" = "vmware" ]; then
            WITH_VM_TOOLS=1
        fi
        WITH_TEST_TOOLS=1
        ;;
    wsl|bare)
        WITH_SSHFS=1
        WITH_TEST_TOOLS=1
        ;;
esac

if [ "$WITH_SSHFS" -eq 1 ]; then
    apt_install_optional openssh-client sshfs
fi
if [ "$WITH_SSH_SERVER" -eq 1 ]; then
    apt_install_optional openssh-server
fi
if [ "$WITH_VM_TOOLS" -eq 1 ]; then
    apt_install_optional open-vm-tools
fi
if [ "$WITH_TEST_TOOLS" -eq 1 ]; then
    apt_install_optional strace bpftrace hyperfine tcpdump tmux shellcheck
fi

# 目标虚拟机启用 SSH
if [ "$WITH_SSH_SERVER" -eq 1 ]; then
    if have systemctl; then
        $SUDO systemctl enable --now ssh 2>/dev/null || warn "启用 ssh 服务失败，请手工检查"
    fi
fi

# systemd 用户委托：没有 linger，SSH 登录会话结束后 user manager 可能退出
if [ "$ENABLE_LINGER" -eq 1 ] && have loginctl; then
    if $SUDO loginctl enable-linger "$TARGET_USER" 2>/dev/null; then
        ok "已为 $TARGET_USER 启用 systemd linger"
    else
        warn "未能启用 linger；若 systemd-run --user 失败，请手工执行："
        warn "  sudo loginctl enable-linger $TARGET_USER"
    fi
fi

# ---------------------------------------------------------------- Python 环境
if [ "$CREATE_VENV" -eq 1 ]; then
    PY="$(pick_python)" || die "未找到 python3，无法创建虚拟环境"
    log "使用 $PY 创建虚拟环境：$PROJECT_DIR/.venv"
    mkdir -p "$PROJECT_DIR"
    if [ ! -x "$PROJECT_DIR/.venv/bin/python" ]; then
        "$PY" -m venv "$PROJECT_DIR/.venv"
    else
        log "虚拟环境已存在，复用"
    fi
    "$PROJECT_DIR/.venv/bin/python" -m pip install --upgrade pip >/dev/null
    log "安装运行时/测试依赖：bashlex==$BASHLEX_VERSION、pytest、hypothesis"
    "$PROJECT_DIR/.venv/bin/pip" install "bashlex==$BASHLEX_VERSION" pytest hypothesis >/dev/null
    if [ -f "$PROJECT_DIR/pyproject.toml" ]; then
        log "以可编辑模式安装项目本身"
        "$PROJECT_DIR/.venv/bin/pip" install -e "$PROJECT_DIR"
    else
        warn "未找到 $PROJECT_DIR/pyproject.toml，跳过项目安装"
        warn "仓库骨架就绪后，重新执行本脚本或：$PROJECT_DIR/.venv/bin/pip install -e $PROJECT_DIR"
    fi
else
    log "--no-venv：跳过 Python 虚拟环境"
fi

# ---------------------------------------------------------------- 安装后自检
check_all || true

cat <<EOF

------------------------------------------------------------
下一步：
  1. 目标虚拟机请使用 Ubuntu 22.04，并确认本脚本 --check 全部关键项通过；
  2. 将仓库放在 Linux 原生目录（如 $PROJECT_DIR），不要放在 /mnt/c 或 /mnt/d；
  3. 激活环境：source $PROJECT_DIR/.venv/bin/activate
  4. 启动沙箱（代码就绪后）：$PROJECT_DIR/.venv/bin/sandbox
  5. 任何“通过”结论都必须以完整虚拟机为准，WSL 结果只作开发参考。
------------------------------------------------------------
EOF
