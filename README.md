# sec-sandbox

面向大模型智能体的命令执行行为管控系统：一个 CLI 安全执行网关（命令沙箱）。真实 Agent（如 Claude Code）在外层 bwrap 沙箱中运行，其派生命令统一经 `safe-exec` 网关做分类、审计与拦截；命中安全规则时不执行，并在 stderr 回显可读的拦截提示（非 0 退出码）。

A command-execution control system for LLM agents: a CLI security gateway (command sandbox). Real agents (such as Claude Code) run inside an outer bwrap sandbox, and their spawned commands are classified, audited, and blocked by the `safe-exec` gateway; when a security rule fires, the command is not executed, and a readable message is printed to stderr with a non-zero exit code.

## 作用 / What It Does

项目在 Agent 执行动作的入口处建立安全闸门，重点防止敏感数据被读取、篡改或外发。它采用“命令层 + 内核层”的双层防护：命令层做白名单分类与规则审计，内核层用 mount namespace、cgroup v2 与 seccomp 做硬隔离，规则无法确定时一律降级到最严格的执行路径。

The project places a security gate at the point where an agent takes action, focusing on preventing sensitive data from being read, modified, or exfiltrated. It combines a command layer and a kernel layer: the command layer performs whitelist classification and rule-based auditing, while the kernel layer enforces hard isolation with mount namespaces, cgroup v2, and seccomp. When a rule cannot decide, execution falls back to the strictest path.

- **命令分类。** 白名单内的纯 bash 命令交给 AST 审计，纯 Python 命令交给 `sys.addaudithook`，其余命令（混合、解析失败、未知）一律进入内层 bwrap 硬隔离。
- **Command classification.** Whitelisted pure-bash commands go through AST auditing, pure-Python commands go through `sys.addaudithook`, and everything else (mixed, unparsable, or unknown) is forced into the inner bwrap sandbox.
- **资源与系统调用限制。** cgroup v2 限制内存、进程数和 CPU；seccomp 过滤危险 syscall；`no_new_privs` 阻止提权。
- **Resource and syscall limits.** cgroup v2 limits memory, task count, and CPU; seccomp filters dangerous syscalls; `no_new_privs` prevents privilege escalation.
- **网络外发审查。** 不禁止正常联网，但拦截字面量内网/回环目标、敏感数据外发和无法确定的目标；网络线判定不通过时独立拒绝。
- **Network egress review.** Normal network access is allowed, but literal private/loopback targets, sensitive-data uploads, and undecidable destinations are blocked; a failed network check results in an independent denial.
- **可配置、可审计。** 提供 Textual 全屏 TUI 生成 `profile.json`，所有放行/拒绝决策写入 JSONL 审计日志。
- **Configurable and auditable.** A full-screen Textual TUI generates `profile.json`, and every allow/deny decision is written to a JSONL audit log.

## 文件结构 / File Structure

```text
项目/
├── bin/                     # 入口脚本 / entry scripts
├── src/sec_sandbox/         # 源码 / source code
├── tests/                   # 单元、集成、内核、端到端测试 / unit, integration, kernel, e2e tests
├── scripts/                 # 安装、自检、演示、基准与卸载脚本 / setup, self-check, demo, benchmark, uninstall
├── docs/                    # 使用说明与演示文档 / usage and demo documents
├── etc/                     # profile schema 与预设 / profile schema and presets
├── tools/                   # 开发者工具 / developer tools
├── design/                  # 设计文档（不纳入 Git）/ design documents (not committed)
└── logs/                    # 只追加问题日志（不纳入 Git）/ append-only logs (not committed)
```

| 路径 / Path | 作用 / Purpose |
| --- | --- |
| `src/sec_sandbox/contracts/` | 公共类型、枚举与 Protocol。Shared types, enums, and protocols. |
| `src/sec_sandbox/policy/` | profile 的 Schema、加载与预设。Profile schema, loading, and presets. |
| `src/sec_sandbox/bash_audit/` | 基于 `bashlex` 的 bash AST 解析、分类与规则审计。Bash AST parsing, classification, and rule auditing with `bashlex`. |
| `src/sec_sandbox/python_audit/` | Python AST 静态扫描与 `sys.addaudithook` 运行时拦截。Python AST static scanning and runtime interception via `sys.addaudithook`. |
| `src/sec_sandbox/netpolicy/` | 网络目标、数据来源与外发风险分析。Network target, data-source, and egress-risk analysis. |
| `src/sec_sandbox/gateway/` | `safe-exec` 的参数解析、分类、Broker、执行器、审计与提示。`safe-exec` argument parsing, classification, broker, executor, audit, and messages. |
| `src/sec_sandbox/sandbox/` | 外层/内层 bwrap、cgroup、seccomp、挂载视图与自检。Outer/inner bwrap, cgroup, seccomp, mount view, and self-check. |
| `src/sec_sandbox/frontend/` | Textual 配置前端与预设。Textual configuration frontend and presets. |
| `src/sec_sandbox/llm/` | 规则无法定论时的可选 LLM 判定。Optional LLM judge when rules cannot decide. |
| `src/sec_sandbox/util/` | 路径、日志与脱敏工具。Path, logging, and redaction utilities. |
| `tests/` | 单元、集成、内核与端到端测试，含恶意/正常命令用例集。Unit, integration, kernel, and end-to-end tests, including malicious/normal command cases. |
| `scripts/` | `setup.sh`、`uninstall.sh`、`demo_attacks.py`、`bench_gateway.py` 等运维与演示脚本。Operational and demo scripts such as `setup.sh`, `uninstall.sh`, `demo_attacks.py`, and `bench_gateway.py`. |
| `docs/` | TUI 使用说明、现场演示指南与 Agent 诱导提示词。TUI manual, live demo guide, and agent prompts. |
| `etc/` | profile schema 与标准预设。Profile schema and standard presets. |

## 快速开始 / Quick Start

目标运行环境是 Ubuntu 22.04；WSL 仅用于开发与非内核测试。编辑和 Git 提交可以在 Windows 挂载盘进行，但运行 bwrap、内核测试和真实 Agent 演示必须先把代码复制到 Linux 原生目录。

The target runtime is Ubuntu 22.04; WSL is only for development and non-kernel tests. Editing and Git commits may happen on a Windows-mounted drive, but running bwrap, kernel tests, and real-agent demos requires copying the code to a Linux-native directory first.

```bash
# 创建环境 / create the environment
python3 -m venv .venv
.venv/bin/pip install -e '.[test]'

# 环境自检 / environment self-check
./scripts/setup.sh --check

# 沙箱自检，不启动 / sandbox self-check without launching
bin/sandbox --check
```

启动沙箱时，`--preset` 会把**当前目录**作为 workspace：

When launching the sandbox, `--preset` uses the **current directory** as the workspace:

```bash
cd /path/to/workspace
/path/to/project/bin/sandbox --preset standard
```

已有 profile 时也可以直接启动；网关位于外层 bwrap 的 `/usr/bin/bash` 路径：

An existing profile can also be used directly; the gateway is bound to `/usr/bin/bash` inside the outer bwrap:

```bash
bin/sandbox --profile ~/.config/sandbox/profile.json
SECSAND_PROFILE=~/.config/sandbox/profile.json bin/safe-exec -c 'ls'
```

`setup.sh` 安装模式会创建 `/usr/bin/real-bash`（真 bash 的普通副本，不是符号链接；bwrap 0.6.1 要求 `--ro-bind` 目标是普通文件），这是外层 bwrap 的部署前提。

The install mode of `setup.sh` creates `/usr/bin/real-bash` as a regular copy of the real bash (not a symlink, because bwrap 0.6.1 requires a regular file as the `--ro-bind` target); this is a deployment prerequisite for the outer bwrap.

## 测试 / Tests

模块单元测试可以在 WSL 执行；集成测试、内核黑盒测试、真实 Agent 联调与性能基准应在 Ubuntu 22.04 VM 的本机终端执行。

Module unit tests can run in WSL; integration tests, kernel black-box tests, real-agent integration, and performance benchmarks should run in a local terminal on the Ubuntu 22.04 VM.

```bash
.venv/bin/pytest -m "not kernel"   # 开发机 / development machine
.venv/bin/pytest -m kernel         # Ubuntu 22.04 VM（内核黑盒 / kernel black-box）
.venv/bin/pytest tests/e2e         # 恶意/正常用例集与指标 / malicious and normal cases with metrics
```

## 文档 / Documentation

- [`docs/沙箱使用说明.md`](docs/沙箱使用说明.md)：TUI 字段、预设与全部可操作组合。TUI fields, presets, and all supported combinations.
- [`docs/沙箱运行指南.md`](docs/沙箱运行指南.md)：现场演示流程与自动验证脚本。Live demo workflow and automatic verification script.
- [`docs/Agent诱导提示词.md`](docs/Agent诱导提示词.md)：真实 Agent 联调使用的提示词。Prompts used for real-agent integration.

## 卸载 / Uninstall

默认不删除项目源码、系统 bash 与通用系统工具；需要特权时脚本内部调用 `sudo`，因此请以普通用户运行，不要整体使用 `sudo`。

Project sources, the system bash, and common system tools are not removed by default. The script invokes `sudo` internally when needed, so run it as a normal user rather than prefixing the whole command with `sudo`.

```bash
# 预览将删除的内容 / preview what will be removed
./scripts/uninstall.sh --dry-run

# 交互确认后卸载部署产物 / remove deployment artifacts after confirmation
./scripts/uninstall.sh

# 额外卸载系统包 bubblewrap，并保留配置与审计日志
# also remove the bubblewrap package while keeping configuration and audit logs
./scripts/uninstall.sh --yes --purge --keep-state
```

## 安全边界 / Security Boundary

本项目只拦截经过 `safe-exec` 网关的命令；Agent 的文件工具直接访问挂载视图，只受外层 bwrap 的读写范围约束。MCP 工具的任意行为、Agent 本体上传上下文、经“人”或侧信道的外发，以及 DNS 解析后指向内网等残余风险，不在完整防护范围内。

This project only intercepts commands that pass through the `safe-exec` gateway; an agent's file tools access the mount view directly and are constrained only by the outer bwrap's read/write scope. Arbitrary MCP tool behavior, agent context uploads, exfiltration through humans or side channels, and DNS rebinding to internal networks are outside the full protection scope.
