"""T2-01 bashlex 封装与 AST 工具测试。"""

from __future__ import annotations

from pathlib import Path

import pytest
from hypothesis import given, settings, strategies as st

from sec_sandbox.bash_audit.analyzer import BashAnalyzer
from sec_sandbox.bash_audit.astutil import (
    command_argv,
    is_static_word,
    iter_words,
    walk,
    word_text,
)
from sec_sandbox.bash_audit.classifier import classify
from sec_sandbox.bash_audit.parser import parse
from sec_sandbox.contracts import AuditContext, CommandShape, Decision


def test_parse_simple_command():
    parsed = parse("ls -la")
    assert parsed.ok
    assert parsed.error is None
    assert len(parsed.nodes) == 1
    assert parsed.nodes[0].kind == "command"


@pytest.mark.parametrize("text", ["", "   ", "\n\t"])
def test_empty_text_is_valid_empty_command(text):
    parsed = parse(text)
    assert parsed.ok
    assert parsed.nodes == ()


@pytest.mark.parametrize(
    "text",
    [
        "echo 'unclosed",
        'if true; then',
        "$(",
        "echo \\",
        "for x in; do",
    ],
)
def test_malformed_input_never_raises(text):
    parsed = parse(text)
    assert not parsed.ok
    assert parsed.nodes == ()
    assert parsed.error


def test_walk_reaches_nested_nodes():
    parsed = parse("ls | grep x && echo $(date)")
    assert parsed.ok

    kinds = {node.kind for node in walk(parsed.nodes[0])}

    assert {"list", "pipeline", "command", "word", "commandsubstitution"} <= kinds


def test_iter_words_in_source_order():
    parsed = parse("cat $HOME/.ssh/id_rsa")
    nodes = parsed.nodes
    assert parsed.ok

    texts = [word_text(word) for word in iter_words(nodes[0])]

    assert texts == ["cat", None]


def test_word_text_literal():
    parsed = parse("echo hello")
    words = list(iter_words(parsed.nodes[0]))
    assert word_text(words[0]) == "echo"
    assert word_text(words[1]) == "hello"


@pytest.mark.parametrize(
    "text",
    [
        "echo $HOME",
        'echo "$HOME"',
        "echo $(date)",
        "echo ~/x",
        "echo `date`",
    ],
)
def test_word_text_returns_none_for_expansions(text):
    parsed = parse(text)
    assert parsed.ok
    words = list(iter_words(parsed.nodes[0]))
    assert word_text(words[1]) is None


def test_single_quoted_text_is_literal():
    parsed = parse("echo '$HOME'")
    words = list(iter_words(parsed.nodes[0]))
    assert word_text(words[1]) == "$HOME"
    assert is_static_word(words[1])


def test_is_static_word_rejects_glob():
    parsed = parse("echo *.py")
    words = list(iter_words(parsed.nodes[0]))
    assert word_text(words[1]) == "*.py"
    assert not is_static_word(words[1])


def test_command_argv_simple():
    parsed = parse("ls -la /tmp")
    assert command_argv(parsed.nodes[0]) == ("ls", "-la", "/tmp")


def test_command_argv_ignores_assignment():
    parsed = parse("FOO=bar ls")
    assert command_argv(parsed.nodes[0]) == ("ls",)


def test_command_argv_none_for_dynamic_word():
    parsed = parse("cat $HOME/.ssh/id_rsa")
    assert command_argv(parsed.nodes[0]) is None


def test_command_argv_none_for_non_command_node():
    parsed = parse("ls | grep x")
    assert command_argv(parsed.nodes[0]) is None


@given(st.text(max_size=80))
@settings(max_examples=200, deadline=None, derandomize=True)
def test_parse_never_raises(text):
    parsed = parse(text)
    assert parsed.error is None or not parsed.ok
    if parsed.ok:
        assert classify(parsed) is not CommandShape.UNPARSEABLE


@given(st.text(max_size=60))
@settings(max_examples=100, deadline=None, derandomize=True)
def test_analyzer_never_raises(text):
    ctx = AuditContext(cwd=Path("/tmp"), home=Path("/tmp"), workspace=Path("/tmp"))
    result = BashAnalyzer().analyze(parse(text), ctx)
    assert result.verdict.decision in set(Decision)
