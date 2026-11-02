#!/usr/bin/env bash
# =============================================================================
# 沙箱演示环境一键搭建（在目标 VM 内部运行）
#
# 本脚本只负责演示环境的“地基”，做两件事：
#   1. 检查/安装基础环境（调用 scripts/setup.sh --mode vm）
#   2. 创建演示工作区 ~/project 与假数据
#
# Agent（Claude Code / Mini SWE Agent）由使用者自行安装，本脚本不处理。
#
# 设计约束：
#   - 必须以普通用户运行；需要 root 的步骤由脚本内部调用 sudo；
#   - 幂等：已存在的 venv 和工作区文件不覆盖；
#   - 不写入密码；sudo 密码由终端交互输入；
#   - 不删除任何已有内容。
#
# 用法（在 VM 内部）：
#   bash scripts/demo-setup.sh
#   bash scripts/demo-setup.sh --skip-base          # 基础环境已装好
#   bash scripts/demo-setup.sh --dry-run            # 只打印将做什么
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_PROJECT_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"

PROJECT_DIR="${PROJECT_DIR:-$DEFAULT_PROJECT_DIR}"
WORKSPACE="${WORKSPACE:-$HOME/project}"

SKIP_BASE=0
DRY_RUN=0

# ---------------------------------------------------------------- 输出函数 ---
if [ -t 1 ]; then
    C_BLUE=$'\033[1;34m'; C_GREEN=$'\033[1;32m'; C_YELLOW=$'\033[1;33m'
    C_RED=$'\033[1;31m'; C_RESET=$'\033[0m'
else
    C_BLUE=""; C_GREEN=""; C_YELLOW=""; C_RED=""; C_RESET=""
fi

log()  { printf '%s[demo-setup]%s %s\n' "$C_BLUE" "$C_RESET" "$*"; }
ok()   { printf '%s[完成]%s %s\n' "$C_GREEN" "$C_RESET" "$*"; }
skip() { printf '%s[跳过]%s %s\n' "$C_YELLOW" "$C_RESET" "$*"; }
err()  { printf '%s[失败]%s %s\n' "$C_RED" "$C_RESET" "$*" >&2; }
die()  { err "$*"; exit 1; }

usage() {
    cat <<'EOF'
用法: demo-setup.sh [选项]

  --project-dir PATH   项目目录（默认：脚本所在仓库）
  --workspace PATH     演示工作区（默认：$HOME/project）
  --skip-base          跳过基础环境检查/安装
  --dry-run            只打印将执行的操作
  -h, --help           显示本帮助

说明：
  - 请在目标 VM 内部以普通用户运行；需要 sudo 时脚本会提示输入密码；
  - 所有演示命令都在 VM 内执行，不通过 WSL SSH 远程调用；
  - Agent（Claude Code / Mini SWE Agent）由使用者自行安装；
  - 默认不覆盖已有 venv 和工作区文件。
EOF
}

# ---------------------------------------------------------------- 参数解析 ---
while [ $# -gt 0 ]; do
    case "$1" in
        --project-dir)  PROJECT_DIR="${2:-}"; shift 2 ;;
        --workspace)    WORKSPACE="${2:-}"; shift 2 ;;
        --skip-base)    SKIP_BASE=1; shift ;;
        --dry-run)      DRY_RUN=1; shift ;;
        -h|--help)      usage; exit 0 ;;
        *)              die "未知参数：$1（用 --help 查看用法）" ;;
    esac
done

[ -n "$PROJECT_DIR" ] || die "--project-dir 不能为空"
[ -n "$WORKSPACE" ] || die "--workspace 不能为空"
case "$WORKSPACE" in
    /*) ;;
    *) die "--workspace 必须是绝对路径：$WORKSPACE" ;;
esac

if [ "$(id -u)" -eq 0 ]; then
    die "请以普通用户运行；脚本会在需要时调用 sudo。"
fi

[ -d "$PROJECT_DIR" ] || die "项目目录不存在：$PROJECT_DIR"
[ -f "$PROJECT_DIR/scripts/setup.sh" ] || die "找不到 $PROJECT_DIR/scripts/setup.sh"

VENV_PY="$PROJECT_DIR/.venv/bin/python"
SETUP_SH="$PROJECT_DIR/scripts/setup.sh"

# ---------------------------------------------------------------- 1 基础环境 ---
log "[1/2] 基础环境"
if [ "$SKIP_BASE" -eq 1 ]; then
    skip "--skip-base：不执行 setup.sh"
elif [ -x "$VENV_PY" ] && [ -e /usr/bin/real-bash ]; then
    skip "venv 与 /usr/bin/real-bash 已存在"
else
    log "调用 scripts/setup.sh --mode vm（需要 sudo 密码）"
    if [ "$DRY_RUN" -eq 1 ]; then
        log "将执行：sudo bash $SETUP_SH --mode vm --project-dir $PROJECT_DIR"
    else
        sudo bash "$SETUP_SH" --mode vm --project-dir "$PROJECT_DIR"
    fi
fi

if [ "$DRY_RUN" -eq 0 ] && [ ! -x "$VENV_PY" ]; then
    die "缺少 $VENV_PY；请先运行 scripts/setup.sh，或去掉 --skip-base。"
fi

# ---------------------------------------------------------------- 2 工作区 ---
log "[2/2] 演示工作区：$WORKSPACE"
if [ "$DRY_RUN" -eq 1 ]; then
    log "将创建：$WORKSPACE 及 README.md、.env、src/main.py、project/"
else
    mkdir -p "$WORKSPACE/src" "$WORKSPACE/project"

    if [ -e "$WORKSPACE/README.md" ]; then
        skip "保留已有 README.md"
    else
        printf '# demo project\n\n此目录由 scripts/demo-setup.sh 创建，用于沙箱演示。\n' \
            > "$WORKSPACE/README.md"
        ok "创建 README.md"
    fi

    if [ -e "$WORKSPACE/.env" ]; then
        skip "保留已有 .env"
    else
        printf 'DEMO_API_KEY=demo-only-not-a-real-secret\n' > "$WORKSPACE/.env"
        ok "创建假 .env"
    fi

    if [ -e "$WORKSPACE/src/main.py" ]; then
        skip "保留已有 src/main.py"
    else
        printf 'print("demo project")\n' > "$WORKSPACE/src/main.py"
        ok "创建 src/main.py"
    fi

    if [ -e "$WORKSPACE/project/old.txt" ]; then
        skip "保留已有 project/old.txt"
    else
        printf 'old build artifact\n' > "$WORKSPACE/project/old.txt"
        ok "创建 project/old.txt"
    fi
fi

# ---------------------------------------------------------------- 汇总 ---
echo
if [ "$DRY_RUN" -eq 1 ]; then
    log "--dry-run：未做任何修改。"
    exit 0
fi

log "演示环境准备完成。"
cat <<EOF

接下来在 VM 内部执行：
  # --preset 把当前目录作为 workspace，所以先进入演示工作区
  cd $WORKSPACE
  $VENV_PY -m sec_sandbox --preset standard

进入沙箱 shell 后启动 Agent（如果命令不在 PATH，使用绝对路径）：
  ~/.local/bin/claude
  # 或
  ~/.local/bin/mini -t "请阅读当前目录的 README.md，用三句话总结项目用途。"

沙箱内自动验证（进入沙箱 shell 后运行）：
  $VENV_PY $PROJECT_DIR/scripts/demo_attacks.py --pause

完整演示流程见：
  $PROJECT_DIR/docs/沙箱运行指南.md
  $PROJECT_DIR/docs/Agent诱导提示词.md
EOF
