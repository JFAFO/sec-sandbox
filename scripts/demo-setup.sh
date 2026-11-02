#!/usr/bin/env bash
# =============================================================================
# 沙箱演示环境一键搭建（在目标 VM 内部运行）
#
# 本脚本只用于课程演示环境，做以下事情：
#   1. 检查/安装基础环境（调用 scripts/setup.sh --mode vm）
#   2. 把 ~/.local/bin 加入 PATH
#   3. 安装 Claude Code（官方脚本，用户级全局）
#   4. 安装 Mini SWE Agent（pip --user，用户级全局）
#   5. 创建演示工作区 ~/project 与假数据
#   6. 生成 demo profile（workspace = ~/project）
#
# 设计约束：
#   - 必须以普通用户运行；需要 root 的步骤由脚本内部调用 sudo；
#   - 幂等：已存在的 venv / Agent / 文件 / profile 不覆盖；
#   - 不写入密码；sudo 密码由终端交互输入；
#   - 不删除任何已有内容。
#
# 用法（在 VM 内部）：
#   bash scripts/demo-setup.sh
#   bash scripts/demo-setup.sh --skip-base          # 基础环境已装好
#   bash scripts/demo-setup.sh --skip-agents        # 只准备演示工作区
#   bash scripts/demo-setup.sh --force-profile      # 覆盖已有 profile
#   bash scripts/demo-setup.sh --dry-run            # 只打印将做什么
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_PROJECT_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"

PROJECT_DIR="${PROJECT_DIR:-$DEFAULT_PROJECT_DIR}"
WORKSPACE="${WORKSPACE:-$HOME/project}"
PROFILE_PATH="${PROFILE_PATH:-$HOME/.config/sandbox/profile.json}"
PYPI_INDEX="${PYPI_INDEX:-https://pypi.tuna.tsinghua.edu.cn/simple}"

SKIP_BASE=0
SKIP_AGENTS=0
FORCE_PROFILE=0
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
warn() { printf '%s[警告]%s %s\n' "$C_YELLOW" "$C_RESET" "$*" >&2; }
err()  { printf '%s[失败]%s %s\n' "$C_RED" "$C_RESET" "$*" >&2; }
die()  { err "$*"; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

usage() {
    cat <<'EOF'
用法: demo-setup.sh [选项]

  --project-dir PATH   项目目录（默认：脚本所在仓库）
  --workspace PATH     演示工作区（默认：$HOME/project）
  --profile PATH       profile 输出路径（默认：$HOME/.config/sandbox/profile.json）
  --pypi-index URL     pip 索引（默认：清华 PyPI 镜像）
  --skip-base          跳过基础环境检查/安装
  --skip-agents        跳过 Claude Code 与 Mini SWE Agent 安装
  --force-profile      覆盖已存在的 profile
  --dry-run            只打印将执行的操作
  -h, --help           显示本帮助

说明：
  - 请在目标 VM 内部以普通用户运行；需要 sudo 时脚本会提示输入密码；
  - 所有演示命令都在 VM 内执行，不通过 WSL SSH 远程调用；
  - 默认不覆盖已有 venv、Agent、工作区文件和 profile。
EOF
}

# ---------------------------------------------------------------- 参数解析 ---
while [ $# -gt 0 ]; do
    case "$1" in
        --project-dir)  PROJECT_DIR="${2:-}"; shift 2 ;;
        --workspace)    WORKSPACE="${2:-}"; shift 2 ;;
        --profile)      PROFILE_PATH="${2:-}"; shift 2 ;;
        --pypi-index)   PYPI_INDEX="${2:-}"; shift 2 ;;
        --skip-base)    SKIP_BASE=1; shift ;;
        --skip-agents)  SKIP_AGENTS=1; shift ;;
        --force-profile) FORCE_PROFILE=1; shift ;;
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
export PATH="$HOME/.local/bin:$PATH"

run_or_print() {
    if [ "$DRY_RUN" -eq 1 ]; then
        log "将执行：$*"
        return 0
    fi
    "$@"
}

# ---------------------------------------------------------------- 1 基础环境 ---
log "[1/6] 基础环境"
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

# ---------------------------------------------------------------- 2 PATH ---
log "[2/6] 用户级命令目录"
if grep -qxF 'export PATH="$HOME/.local/bin:$PATH"' "$HOME/.bashrc" 2>/dev/null; then
    skip "~/.bashrc 已包含 ~/.local/bin"
else
    if [ "$DRY_RUN" -eq 1 ]; then
        log "将把 ~/.local/bin 写入 ~/.bashrc"
    else
        printf '\nexport PATH="$HOME/.local/bin:$PATH"\n' >> "$HOME/.bashrc"
        ok "已把 ~/.local/bin 写入 ~/.bashrc"
    fi
fi

# ---------------------------------------------------------------- 3 Claude ---
log "[3/6] Claude Code"
if [ "$SKIP_AGENTS" -eq 1 ]; then
    skip "--skip-agents"
elif have claude || [ -x "$HOME/.local/bin/claude" ]; then
    skip "Claude Code 已安装"
elif ! have curl; then
    warn "缺少 curl，跳过 Claude Code 安装"
else
    if [ "$DRY_RUN" -eq 1 ]; then
        log "将执行：curl -fsSL https://claude.ai/install.sh | bash"
    else
        log "下载并安装 Claude Code（用户级）"
        if curl -fsSL https://claude.ai/install.sh | bash; then
            ok "Claude Code 安装完成"
        else
            warn "Claude Code 安装失败；可稍后手工重试"
        fi
    fi
fi

# ---------------------------------------------------------------- 4 Mini ---
log "[4/6] Mini SWE Agent"
if [ "$SKIP_AGENTS" -eq 1 ]; then
    skip "--skip-agents"
elif have mini || [ -x "$HOME/.local/bin/mini" ]; then
    skip "Mini SWE Agent 已安装"
elif ! python3 -m pip --version >/dev/null 2>&1; then
    warn "系统 Python 没有 pip；请先安装 python3-pip，或运行 setup.sh"
else
    if [ "$DRY_RUN" -eq 1 ]; then
        log "将执行：python3 -m pip install --user -i $PYPI_INDEX mini-swe-agent"
    else
        log "安装 Mini SWE Agent（用户级，使用 $PYPI_INDEX）"
        if python3 -m pip install --user -i "$PYPI_INDEX" mini-swe-agent; then
            ok "Mini SWE Agent 安装完成"
        else
            warn "Mini SWE Agent 安装失败；可稍后手工重试"
        fi
    fi
fi

# ---------------------------------------------------------------- 5 工作区 ---
log "[5/6] 演示工作区：$WORKSPACE"
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

# ---------------------------------------------------------------- 6 profile ---
log "[6/6] 演示 profile：$PROFILE_PATH"
if [ -e "$PROFILE_PATH" ] && [ "$FORCE_PROFILE" -ne 1 ]; then
    skip "profile 已存在；如需覆盖，加 --force-profile"
elif [ "$DRY_RUN" -eq 1 ]; then
    log "将用 workspace=$WORKSPACE 生成 $PROFILE_PATH"
else
    mkdir -p "$HOME/.local/state/sec-sandbox"
    mkdir -p "$(dirname -- "$PROFILE_PATH")"
    "$VENV_PY" - "$WORKSPACE" "$PROFILE_PATH" <<'PY'
import sys
from pathlib import Path

from sec_sandbox.policy.loader import save_profile
from sec_sandbox.policy.presets import get_preset

workspace = Path(sys.argv[1])
target = Path(sys.argv[2])
profile = get_preset("standard", workspace=workspace)
save_profile(profile, target)
print(f"profile 已写入：{target}")
PY
    ok "profile 已生成"
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
  cd $PROJECT_DIR
  .venv/bin/python -m sec_sandbox --preset standard

进入沙箱 shell 后启动 Agent：
  claude
  # 或
  mini -t "请阅读当前目录的 README.md，用三句话总结项目用途。"

命令行拦截演示：
  .venv/bin/python scripts/demo_attacks.py --pause

完整演示流程见：
  tests/DEMO-01-沙箱演示运行指南.md
  tests/DEMO-02-Agent诱导提示词.md
EOF
