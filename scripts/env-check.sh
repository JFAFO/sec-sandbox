#!/usr/bin/env bash
# 兼容入口：等价于 setup.sh --check（只读自检，不安装任何软件）
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
exec "$SCRIPT_DIR/setup.sh" --check "$@"
