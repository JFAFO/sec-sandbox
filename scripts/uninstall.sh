#!/usr/bin/env bash
# =============================================================================
# 面向大模型智能体的命令执行行为管控系统 —— 一键卸载脚本
#
# 与 setup.sh 的安装动作对称，默认清理：
#   1. /usr/bin/real-bash（真 bash 备份，需 sudo）
#   2. $HOME/.config/sandbox/profile.json（配置）
#   3. $HOME/.local/state/sec-sandbox/（审计日志与状态）
#   4. 项目内 .venv 与 Python 构建缓存
#   5. /tmp 下本用户的 secsand-demo-* 演示目录
#
# 明确不删：
#   - 项目源码（只删 .venv 与缓存；源码需要用户自行处理）；
#   - 系统 bash（/bin/bash、/usr/bin/bash）；
#   - git/curl/python3 等通用系统工具；
#   - SSH 服务（目标 VM 的基础能力）。
#
# 退出码：0 成功（含无需清理）；1 有删除失败；2 参数或环境错误。
#
# 用法：
#   ./uninstall.sh --dry-run          # 只列出将删除的内容
#   ./uninstall.sh                    # 交互确认后卸载
#   ./uninstall.sh --yes              # 非交互卸载
#   ./uninstall.sh --yes --purge      # 额外卸载 bubblewrap
#   ./uninstall.sh --yes --keep-state # 保留配置与审计日志
# =============================================================================
set -euo pipefail

# ---------------------------------------------------------------- 默认参数 ---
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_PROJECT_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"

PROJECT_DIR="${PROJECT_DIR:-$DEFAULT_PROJECT_DIR}"
TARGET_USER="${USER:-$(id -un)}"
HOME_OVERRIDE=""
REAL_BASH_TARGET="${REAL_BASH_TARGET:-/usr/bin/real-bash}"

DRY_RUN=0
ASSUME_YES=0
KEEP_STATE=0
PURGE=0
NO_SUDO=0
FORCE=0
DISABLE_LINGER=0

# ---------------------------------------------------------------- 输出函数 ---
if [ -t 1 ]; then
    C_BLUE=$'\033[1;34m'; C_GREEN=$'\033[1;32m'; C_YELLOW=$'\033[1;33m'
    C_RED=$'\033[1;31m'; C_RESET=$'\033[0m'
else
    C_BLUE=""; C_GREEN=""; C_YELLOW=""; C_RED=""; C_RESET=""
fi

log()  { printf '%s[卸载]%s %s\n' "$C_BLUE" "$C_RESET" "$*"; }
ok()   { printf '%s[删除]%s %s\n' "$C_GREEN" "$C_RESET" "$*"; }
skip() { printf '%s[跳过]%s %s\n' "$C_YELLOW" "$C_RESET" "$*"; }
warn() { printf '%s[警告]%s %s\n' "$C_YELLOW" "$C_RESET" "$*" >&2; }
err()  { printf '%s[失败]%s %s\n' "$C_RED" "$C_RESET" "$*" >&2; }
die()  { err "$*"; exit 2; }
have() { command -v "$1" >/dev/null 2>&1; }

usage() {
    cat <<'EOF'
用法: uninstall.sh [选项]

  --dry-run                 只列出将删除的内容，不实际删除
  -y, --yes                 跳过交互确认（非交互环境必须显式指定）
  --keep-state              保留 profile 与审计日志/状态目录
  --purge                   额外卸载专属系统包 bubblewrap
  --disable-linger          关闭当前用户的 systemd linger
  --no-sudo                 跳过需要 root 的步骤（如删除 /usr/bin/real-bash）
  --force                   删除 /usr/bin/real-bash 前不校验其目标是否为系统 bash
  --project-dir PATH        项目目录（默认：脚本所在仓库的上一级）
  --home PATH               指定目标用户家目录（默认：当前用户家目录）
  --real-bash PATH          真 bash 备份路径（默认：/usr/bin/real-bash）
  -h, --help                显示本帮助

说明：
  - 默认只清理本系统的部署产物，不会删除项目源码、系统 bash 或通用工具；
  - 脚本必须以普通用户运行；删除需要特权的文件时会在内部调用 sudo。
EOF
}

# ---------------------------------------------------------------- 参数解析 ---
while [ $# -gt 0 ]; do
    case "$1" in
        --dry-run)         DRY_RUN=1; shift ;;
        -y|--yes)          ASSUME_YES=1; shift ;;
        --keep-state)      KEEP_STATE=1; shift ;;
        --purge)           PURGE=1; shift ;;
        --disable-linger)  DISABLE_LINGER=1; shift ;;
        --no-sudo)         NO_SUDO=1; shift ;;
        --force)           FORCE=1; shift ;;
        --project-dir)     PROJECT_DIR="${2:-}"; shift 2 ;;
        --home)            HOME_OVERRIDE="${2:-}"; shift 2 ;;
        --real-bash)       REAL_BASH_TARGET="${2:-}"; shift 2 ;;
        -h|--help)         usage; exit 0 ;;
        *)                 die "未知参数：$1（用 --help 查看用法）" ;;
    esac
done

[ -n "$PROJECT_DIR" ] || die "--project-dir 不能为空"
[ -n "$REAL_BASH_TARGET" ] || die "--real-bash 不能为空"

if [ "$(id -u)" -eq 0 ]; then
    die "请以普通用户运行本脚本；需要特权的删除步骤会自动调用 sudo。"
fi

if [ -n "$HOME_OVERRIDE" ]; then
    TARGET_HOME="$HOME_OVERRIDE"
else
    TARGET_HOME="$(getent passwd "$TARGET_USER" | cut -d: -f6)"
fi
[ -n "$TARGET_HOME" ] || die "无法确定用户 $TARGET_USER 的家目录，请用 --home 指定"
[ -d "$TARGET_HOME" ] || die "家目录不存在：$TARGET_HOME"

PROFILE_FILE="$TARGET_HOME/.config/sandbox/profile.json"
PROFILE_DIR="$TARGET_HOME/.config/sandbox"
STATE_DIR="$TARGET_HOME/.local/state/sec-sandbox"

SUDO=""
if have sudo; then
    SUDO="sudo"
fi

FAILED=0
PLAN_KINDS=()
PLAN_PATHS=()
PLAN_NOTES=()

log "目标用户：$TARGET_USER   家目录：$TARGET_HOME"
log "项目目录：$PROJECT_DIR"
log "真 bash 备份：$REAL_BASH_TARGET"
echo

# ---------------------------------------------------------------- 计划收集 ---
plan_add() {
    local kind="$1" path="$2" note="${3:-}"
    if [ -e "$path" ] || [ -L "$path" ]; then
        PLAN_KINDS+=("$kind")
        PLAN_PATHS+=("$path")
        PLAN_NOTES+=("$note")
    fi
}

plan_real_bash() {
    local path="$1"
    if [ ! -e "$path" ] && [ ! -L "$path" ]; then
        return 0
    fi

    local resolved bash_real
    resolved="$(readlink -f -- "$path" 2>/dev/null || true)"
    bash_real="$(readlink -f -- /bin/bash 2>/dev/null || readlink -f -- /usr/bin/bash 2>/dev/null || true)"
    if [ "$resolved" != "$bash_real" ] && [ "$FORCE" -ne 1 ]; then
        warn "$path 不指向系统 bash（解析：${resolved:-无法解析}），已跳过；确认可删时加 --force"
        return 0
    fi

    if [ "$NO_SUDO" -eq 1 ]; then
        skip "$path（--no-sudo；可手工执行：sudo rm -f '$path'）"
        return 0
    fi
    if [ -z "$SUDO" ] && [ "$DRY_RUN" -ne 1 ]; then
        skip "$path（未找到 sudo；可手工执行：sudo rm -f '$path'）"
        return 0
    fi
    plan_add "特权" "$path" "真 bash 备份"
}

if [ "$KEEP_STATE" -eq 1 ]; then
    skip "保留配置：$PROFILE_FILE"
    skip "保留审计日志与状态：$STATE_DIR"
else
    plan_add "配置" "$PROFILE_FILE" "沙箱配置"
    plan_add "状态" "$STATE_DIR" "审计日志与状态"
fi

plan_add "环境" "$PROJECT_DIR/.venv" "Python 虚拟环境"
plan_real_bash "$REAL_BASH_TARGET"

if [ "$(id -u)" -ne 0 ] && [ "$DISABLE_LINGER" -eq 1 ] && [ -z "$SUDO" ]; then
    warn "未找到 sudo，无法关闭 linger"
    DISABLE_LINGER=0
fi
if [ "$PURGE" -eq 1 ] && ! have apt-get; then
    warn "未找到 apt-get，--purge 将跳过系统包卸载"
    PURGE=0
fi
if [ "$PURGE" -eq 1 ] && [ -z "$SUDO" ] && [ "$DRY_RUN" -ne 1 ]; then
    warn "未找到 sudo，--purge 将跳过系统包卸载"
    PURGE=0
fi

# 项目缓存与 /tmp 演示目录单独统计，避免逐条打印淹没输出。
CACHE_DIRS=()
if [ -d "$PROJECT_DIR" ]; then
    while IFS= read -r -d '' path; do
        CACHE_DIRS+=("$path")
    done < <(
        find "$PROJECT_DIR" -type d \
            \( -name '__pycache__' -o -name '.pytest_cache' -o -name '*.egg-info' \) \
            -prune -print0 2>/dev/null || true
    )
fi

DEMO_DIRS=()
while IFS= read -r -d '' path; do
    DEMO_DIRS+=("$path")
done < <(
    find /tmp -maxdepth 1 -type d -user "$TARGET_USER" \
        -name 'secsand-demo-*' -print0 2>/dev/null || true
)

# ---------------------------------------------------------------- 计划展示 ---
describe() {
    local path="$1"
    if [ -d "$path" ]; then
        du -sh -- "$path" 2>/dev/null | cut -f1 || true
    elif [ -e "$path" ] || [ -L "$path" ]; then
        printf '文件\n'
    fi
}

if [ "${#PLAN_PATHS[@]}" -eq 0 ] && [ "${#CACHE_DIRS[@]}" -eq 0 ] \
        && [ "${#DEMO_DIRS[@]}" -eq 0 ] && [ "$PURGE" -eq 0 ] \
        && [ "$DISABLE_LINGER" -eq 0 ]; then
    log "未发现需要清理的沙箱部署项。"
    exit 0
fi

log "将执行以下清理："
for index in "${!PLAN_PATHS[@]}"; do
    kind="${PLAN_KINDS[$index]}"
    path="${PLAN_PATHS[$index]}"
    note="${PLAN_NOTES[$index]}"
    printf '  [%s] %s（%s，%s）\n' "$kind" "$path" "$(describe "$path")" "$note"
done
if [ "${#CACHE_DIRS[@]}" -gt 0 ]; then
    printf '  [缓存] 项目内 Python 构建缓存：%d 个目录\n' "${#CACHE_DIRS[@]}"
fi
if [ "${#DEMO_DIRS[@]}" -gt 0 ]; then
    printf '  [临时] /tmp 下演示目录：%d 个\n' "${#DEMO_DIRS[@]}"
fi
if [ "$PURGE" -eq 1 ]; then
    printf '  [系统包] bubblewrap（apt-get remove --purge）\n'
fi
if [ "$DISABLE_LINGER" -eq 1 ]; then
    printf '  [linger] 关闭用户 %s 的 systemd linger\n' "$TARGET_USER"
fi
echo

if [ "$DRY_RUN" -eq 1 ]; then
    log "--dry-run：未做任何修改。"
    exit 0
fi

if [ "$ASSUME_YES" -ne 1 ]; then
    if [ ! -t 0 ]; then
        die "非交互环境请加 --yes 明确确认。"
    fi
    printf '确认执行卸载？输入 yes 继续：'
    read -r answer
    if [ "$answer" != "yes" ]; then
        log "已取消，未做任何修改。"
        exit 0
    fi
fi

# ---------------------------------------------------------------- 执行删除 ---
remove_user_path() {
    local path="$1"
    if [ ! -e "$path" ] && [ ! -L "$path" ]; then
        skip "不存在：$path"
        return 0
    fi
    if rm -rf -- "$path"; then
        ok "$path"
    else
        err "删除失败：$path"
        FAILED=1
    fi
}

remove_privileged_path() {
    local path="$1"
    if [ ! -e "$path" ] && [ ! -L "$path" ]; then
        skip "不存在：$path"
        return 0
    fi
    if sudo rm -f -- "$path"; then
        ok "$path"
    else
        err "删除失败（需要 sudo）：$path"
        FAILED=1
    fi
}

for index in "${!PLAN_PATHS[@]}"; do
    kind="${PLAN_KINDS[$index]}"
    path="${PLAN_PATHS[$index]}"
    if [ "$kind" = "特权" ]; then
        remove_privileged_path "$path"
    else
        remove_user_path "$path"
    fi
done

# 配置目录若已空则一并移除；用户自己的其他文件保持原样。
if [ "$KEEP_STATE" -ne 1 ] && [ -d "$PROFILE_DIR" ]; then
    if rmdir -- "$PROFILE_DIR" 2>/dev/null; then
        ok "$PROFILE_DIR（空目录）"
    else
        skip "$PROFILE_DIR 非空，保留用户其他配置"
    fi
fi

if [ "${#CACHE_DIRS[@]}" -gt 0 ]; then
    removed=0
    for path in "${CACHE_DIRS[@]}"; do
        if rm -rf -- "$path"; then
            removed=$((removed + 1))
        else
            err "删除失败：$path"
            FAILED=1
        fi
    done
    ok "项目缓存：$removed / ${#CACHE_DIRS[@]} 个目录"
fi

if [ "${#DEMO_DIRS[@]}" -gt 0 ]; then
    removed=0
    for path in "${DEMO_DIRS[@]}"; do
        if rm -rf -- "$path"; then
            removed=$((removed + 1))
        else
            err "删除失败：$path"
            FAILED=1
        fi
    done
    ok "演示临时目录：$removed / ${#DEMO_DIRS[@]} 个"
fi

if [ "$DISABLE_LINGER" -eq 1 ]; then
    if sudo loginctl disable-linger "$TARGET_USER" 2>/dev/null; then
        ok "已关闭 systemd linger：$TARGET_USER"
    else
        warn "关闭 linger 失败；可手工执行：sudo loginctl disable-linger $TARGET_USER"
    fi
fi

if [ "$PURGE" -eq 1 ]; then
    if dpkg -s bubblewrap >/dev/null 2>&1; then
        log "卸载系统包：bubblewrap"
        if sudo env DEBIAN_FRONTEND=noninteractive apt-get remove --purge -y bubblewrap; then
            ok "已卸载 bubblewrap"
        else
            warn "bubblewrap 卸载失败（可能被其他软件依赖）；请手工检查"
        fi
    else
        skip "bubblewrap 未安装"
    fi
fi

# ---------------------------------------------------------------- 结果汇总 ---
echo
if [ "$FAILED" -eq 0 ]; then
    log "卸载完成。"
else
    err "卸载完成，但存在删除失败的条目，请按上方提示手工处理。"
fi
cat <<EOF

保留内容：
  - 项目源码：$PROJECT_DIR
  - 系统 bash：/bin/bash
  - 通用系统工具：git、curl、python3、libseccomp2 等
  - SSH 服务（目标 VM 的基础能力）

如需重新安装：
  sudo $PROJECT_DIR/scripts/setup.sh --mode vm
EOF

exit "$FAILED"
