"""T2-02 命令形状分类用例表（§4.4）。"""

from __future__ import annotations

import pytest

from sec_sandbox.bash_audit.classifier import classify
from sec_sandbox.bash_audit.parser import parse
from sec_sandbox.contracts import CommandShape


@pytest.mark.parametrize(
    "text",
    [
        "ls",
        "ls -la /tmp",
        "ls; pwd",
        "ls && pwd",
        "cd /tmp",
        "ls *.py",
        "echo hi > out",
        "cat file 2>/dev/null",
    ],
)
def test_simple_commands(text):
    assert classify(parse(text)) is CommandShape.SIMPLE


@pytest.mark.parametrize(
    "text",
    [
        # 管道 / 子 shell / 命令替换 / 进程替换
        "ls | grep x",
        "(ls)",
        "echo $(date)",
        "cat <(ls)",
        # 动态重定向 / heredoc
        "echo hi > *.log",
        "cat << EOF\nx\nEOF",
        # 函数 / 循环 / 条件
        "f() { ls; }",
        "for x in a; do ls; done",
        "if true; then ls; fi",
        # 会派生新命令的 utility
        "find . -exec rm {} \\;",
        "xargs rm",
        "bash -c 'ls'",
        "env FOO=bar ls",
        "awk 'BEGIN { system(\"ls\") }'",
        "sed -i 's/a/b/' f",
        # 赋值 / 后台 / 动态词
        "FOO=bar ls",
        "sleep 1 &",
        "cat $HOME/x",
        "cd $HOME",
    ],
)
def test_compound_commands(text):
    assert classify(parse(text)) is CommandShape.COMPOUND


def test_unparseable():
    assert classify(parse("echo 'unclosed")) is CommandShape.UNPARSEABLE


def test_empty_command_is_simple():
    assert classify(parse("")) is CommandShape.SIMPLE
