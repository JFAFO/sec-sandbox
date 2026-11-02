"""T5-06 沙箱自检测试。"""

from __future__ import annotations

from dataclasses import dataclass

from sec_sandbox.sandbox.selfcheck import CheckResult, format_report, run_selfcheck


@dataclass
class FakeProcess:
    returncode: int = 0


def test_all_checks_pass():
    results = run_selfcheck(
        which=lambda name: f"/usr/bin/{name}",
        run=lambda argv, **kwargs: FakeProcess(0),
        filesystems="nodev\toverlay\n",
        libseccomp=True,
    )

    assert len(results) == 7
    assert all(result.ok for result in results)
    report = format_report(results)
    assert "[通过] bubblewrap" in report
    assert "全部关键项通过" in report


def test_missing_bwrap_fails():
    results = run_selfcheck(
        which=lambda name: None,
        run=lambda argv, **kwargs: FakeProcess(1),
        filesystems="",
        libseccomp=False,
    )
    by_name = {result.name: result for result in results}

    assert not by_name["bubblewrap"].ok
    assert not by_name["嵌套 bwrap"].ok
    assert "存在关键失败" in format_report(results)


def test_nested_failure_reported():
    def run(argv, **kwargs):
        return FakeProcess(0 if "--scope" in argv else 1)

    results = run_selfcheck(
        which=lambda name: f"/usr/bin/{name}",
        run=run,
        filesystems="nodev\toverlay\n",
        libseccomp=True,
    )
    by_name = {result.name: result for result in results}

    assert not by_name["嵌套 bwrap"].ok
    assert by_name["cgroup 委托"].ok


def test_cgroup_missing_systemd_run():
    results = run_selfcheck(
        which=lambda name: None if name == "systemd-run" else f"/usr/bin/{name}",
        run=lambda argv, **kwargs: FakeProcess(0),
        filesystems="nodev\toverlay\n",
        libseccomp=True,
    )
    by_name = {result.name: result for result in results}

    assert not by_name["cgroup 委托"].ok


def test_overlayfs_is_non_critical():
    results = run_selfcheck(
        which=lambda name: f"/usr/bin/{name}",
        run=lambda argv, **kwargs: FakeProcess(0),
        filesystems="nodev\ttmpfs\n",
        libseccomp=True,
    )
    by_name = {result.name: result for result in results}

    assert not by_name["overlayfs"].ok
    assert not by_name["overlayfs"].critical
    assert "全部关键项通过" in format_report(results)


def test_run_exception_is_captured():
    def run(argv, **kwargs):
        raise TimeoutError("timeout")

    results = run_selfcheck(
        which=lambda name: f"/usr/bin/{name}",
        run=run,
        filesystems="nodev\toverlay\n",
        libseccomp=True,
    )
    by_name = {result.name: result for result in results}

    assert not by_name["嵌套 bwrap"].ok
    assert not by_name["cgroup 委托"].ok
    assert not by_name["非特权 user namespace"].ok


def test_format_report_contains_no_rule_details():
    report = format_report([CheckResult("bubblewrap", True, "/usr/bin/bwrap")])

    assert "bwrap" in report
    assert "rule" not in report.lower()
