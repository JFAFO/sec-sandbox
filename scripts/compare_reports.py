#!/usr/bin/env python3
"""对比 WSL 与 VM 的基准/用例报告（T7-05）。

用法：compare_reports.py wsl.json vm.json
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 2:
        print("用法：compare_reports.py <wsl.json> <vm.json>", file=sys.stderr)
        return 2

    reports = [json.loads(Path(path).read_text(encoding="utf-8")) for path in args]
    keys = sorted(set().union(*(report.keys() for report in reports)))
    print(f"{'指标':<20}{'WSL':<20}{'VM':<20}")
    for key in keys:
        left, right = (json.dumps(report.get(key, "-"), ensure_ascii=False) for report in reports)
        print(f"{key:<20}{left:<20}{right:<20}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
