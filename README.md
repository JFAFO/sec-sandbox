# sec-sandbox

面向大模型智能体的命令执行行为管控系统：一个 CLI 安全执行网关（命令沙箱）。

真实 Agent（Claude Code）在 `bwrap` 内运行，其派生命令统一经 `safe-exec` 网关分类与审计；
触发安全机制时不执行，并在 stderr 回显可读的拦截提示（非 0 退出码）。

## 环境要求

- Linux（Ubuntu 22.04 为目标环境；WSL 仅作开发）
- Python 3.10+（目标基线 3.10）
- 运行依赖：`bashlex==0.18`
- 系统依赖：`bubblewrap`、`libseccomp2`（安装与自检见 `scripts/setup.sh`）

## 开发

仓库必须位于 Linux 原生文件系统（如 `~/sec-sandbox`），不要放在 `/mnt/c`、`/mnt/d` 等挂载盘。

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[test]'
.venv/bin/pytest
```

## 环境自检

```bash
./scripts/setup.sh --check
```

## 目录

- `src/sec_sandbox/`：源码（`contracts`、`policy`、`bash_audit`、`python_audit`、`netpolicy`、`gateway`、`sandbox`、`frontend`）
- `tests/`：单元、集成、内核与端到端测试
- `scripts/`：安装、自检与 VM 辅助脚本
- `etc/`：profile schema 与预设

## 安全边界

本项目只拦截经 `safe-exec` 网关的命令；MCP 工具任意行为、Agent 本体上传上下文等不在防护范围内。
