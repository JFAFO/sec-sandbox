#!/usr/bin/env python3
"""网关延迟基准（T7-04）。

在目标机本地循环测量，禁止"一条命令一次 SSH"，避免网络往返噪声。
输出 JSON，包含 p50/p95 与测量环境。
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import statistics
import subprocess
import sys
import time
from pathlib import Path


def measure(argv: list[str], repeats: int, env: dict[str, str]) -> list[float]:
    durations: list[float] = []
    for _ in range(repeats):
        started = time.perf_counter()
        subprocess.run(argv, env=env, capture_output=True, check=False)
        durations.append((time.perf_counter() - started) * 1000)
    return durations


def percentile(values: list[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, int(round(fraction * len(ordered))) - 1))
    return round(ordered[index], 2)


def summarize(values: list[float]) -> dict[str, float]:
    return {
        "p50_ms": percentile(values, 0.50),
        "p95_ms": percentile(values, 0.95),
        "min_ms": round(min(values), 2) if values else 0.0,
        "max_ms": round(max(values), 2) if values else 0.0,
        "mean_ms": round(statistics.mean(values), 2) if values else 0.0,
    }


def cpu_model() -> str:
    try:
        for line in Path("/proc/cpuinfo").read_text(encoding="utf-8").splitlines():
            if line.startswith("model name"):
                return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return platform.processor() or "unknown"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="网关冷启动与放行/拦截延迟基准")
    parser.add_argument("--profile", default=str(Path.home() / ".config/sandbox/profile.json"))
    parser.add_argument("--repeats", type=int, default=30)
    parser.add_argument("--label", default="wsl-development")
    args = parser.parse_args(argv)

    profile = Path(args.profile)
    if not profile.is_file():
        print(f"profile 不存在：{profile}", file=sys.stderr)
        return 2

    env = {**os.environ, "SECSAND_PROFILE": str(profile)}
    gateway = [sys.executable, "-m", "sec_sandbox.gateway.cli"]

    report = {
        "environment": args.label,
        "kernel": platform.release(),
        "python": platform.python_version(),
        "cpu": cpu_model(),
        "repeats": args.repeats,
        "import_only": summarize(
            measure([sys.executable, "-c", "import sec_sandbox.gateway.cli"], args.repeats, env)
        ),
        "allow": summarize(measure([*gateway, "-c", "pwd"], args.repeats, env)),
        "deny": summarize(measure([*gateway, "-c", "cat ~/.ssh/id_rsa"], args.repeats, env)),
    }
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
