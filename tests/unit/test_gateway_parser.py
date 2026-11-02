"""T1-04 safe-exec 参数解析测试（§4.2 全表）。"""

from __future__ import annotations

import io
from pathlib import Path

import pytest

from sec_sandbox.contracts import CommandRequest, InvocationMode
from sec_sandbox.gateway.parser import (
    InputTooLargeError,
    ParseError,
    parse_invocation,
)


def parse(
    argv,
    *,
    tty: bool = False,
    stdin: bytes = b"",
    max_bytes: int = 1024,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
) -> CommandRequest:
    return parse_invocation(
        argv,
        stdin_is_tty=tty,
        max_input_bytes=max_bytes,
        cwd=cwd,
        env={} if env is None else env,
        stdin=io.BytesIO(stdin),
    )


def test_interactive_tty():
    request = parse([], tty=True)
    assert request.mode is InvocationMode.INTERACTIVE
    assert request.command_text is None
    assert request.script_path is None


def test_stdin_when_not_tty():
    request = parse([], stdin=b"echo hi\n")
    assert request.mode is InvocationMode.STDIN
    assert request.command_text == "echo hi\n"


def test_command_string():
    request = parse(["-c", "ls -l"])
    assert request.mode is InvocationMode.COMMAND_STRING
    assert request.command_text == "ls -l"


def test_command_string_missing_text():
    with pytest.raises(ParseError):
        parse(["-c"])


@pytest.mark.parametrize(
    "flag", ["-i", "-l", "-il", "-li", "--interactive", "--login"]
)
def test_interactive_flags(flag):
    assert parse([flag], tty=True).mode is InvocationMode.INTERACTIVE


def test_interactive_flag_with_command_string():
    request = parse(["-i", "-c", "ls"])
    assert request.mode is InvocationMode.COMMAND_STRING
    assert request.command_text == "ls"


@pytest.mark.parametrize("flag", ["-l", "-i", "--login", "--interactive"])
def test_command_string_after_option_flag(flag):
    # Claude Code 在快照不可用时会生成 ``bash -c -l <command>``。
    request = parse(["-c", flag, "pwd"])

    assert request.mode is InvocationMode.COMMAND_STRING
    assert request.command_text == "pwd"


@pytest.mark.parametrize("flag", ["-lc", "-cl", "-ilc", "-lic"])
def test_combined_command_flags(flag):
    request = parse([flag, "pwd"])

    assert request.mode is InvocationMode.COMMAND_STRING
    assert request.command_text == "pwd"


def test_combined_command_flag_reads_stdin():
    request = parse(["-lc"], stdin=b"pwd\n")

    assert request.mode is InvocationMode.STDIN
    assert request.command_text == "pwd\n"


def test_combined_command_flag_without_text():
    with pytest.raises(ParseError):
        parse(["-lc"], tty=True)


def test_unknown_combined_flag_still_unknown():
    assert parse(["-xc", "ls"]).mode is InvocationMode.UNKNOWN


def test_stdin_flag():
    request = parse(["-s"], stdin=b"pwd\n")
    assert request.mode is InvocationMode.STDIN
    assert request.command_text == "pwd\n"


def test_stdin_flag_ignores_positional_args():
    request = parse(["-s", "name", "arg"], stdin=b"pwd\n")
    assert request.mode is InvocationMode.STDIN
    assert request.command_text == "pwd\n"


def test_script_file(tmp_path):
    script = tmp_path / "run.sh"
    script.write_text("echo hi\n", encoding="utf-8")

    request = parse([str(script), "arg1"])

    assert request.mode is InvocationMode.SCRIPT
    assert request.command_text == "echo hi\n"
    assert request.script_path == script.resolve()


def test_script_relative_to_cwd(tmp_path):
    script = tmp_path / "run.sh"
    script.write_text("pwd\n", encoding="utf-8")

    request = parse(["run.sh"], cwd=tmp_path)

    assert request.mode is InvocationMode.SCRIPT
    assert request.script_path == script.resolve()


def test_script_missing(tmp_path):
    with pytest.raises(ParseError):
        parse([str(tmp_path / "nope.sh")])


def test_script_too_large(tmp_path):
    script = tmp_path / "big.sh"
    script.write_bytes(b"x" * 11)

    with pytest.raises(InputTooLargeError):
        parse([str(script)], max_bytes=10)


def test_stdin_too_large():
    with pytest.raises(InputTooLargeError):
        parse(["-s"], stdin=b"x" * 11, max_bytes=10)


@pytest.mark.parametrize("flag", ["-x", "--norc", "-O2", "-e"])
def test_unknown_flag(flag):
    assert parse([flag]).mode is InvocationMode.UNKNOWN


def test_unknown_flag_before_command_string():
    request = parse(["-x", "-c", "ls"])
    assert request.mode is InvocationMode.UNKNOWN
    assert request.command_text is None


def test_double_dash_before_script(tmp_path):
    script = tmp_path / "run.sh"
    script.write_text("pwd\n", encoding="utf-8")

    request = parse(["--", str(script)])

    assert request.mode is InvocationMode.SCRIPT
    assert request.script_path == script.resolve()


def test_depth_from_env():
    assert parse(["-c", "ls"], env={"SECSAND_DEPTH": "2"}).depth == 2


@pytest.mark.parametrize("raw", ["bad", "-1"])
def test_invalid_depth(raw):
    with pytest.raises(ParseError):
        parse(["-c", "ls"], env={"SECSAND_DEPTH": raw})


def test_request_preserves_inputs(tmp_path):
    request = parse(["-c", "ls"], cwd=tmp_path, env={"A": "1"})
    assert request.argv == ("-c", "ls")
    assert request.cwd == tmp_path
    assert request.env == {"A": "1"}


def test_parsing_does_not_execute_script(tmp_path):
    marker = tmp_path / "marker"
    script = tmp_path / "run.sh"
    script.write_text(f"touch {marker}\n", encoding="utf-8")

    parse([str(script)])

    assert not marker.exists()
