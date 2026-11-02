"""运行时路径探测（§4.6、§8）。

所有路径一律运行时探测，禁止在代码中写死用户名或发行版路径。
"""

from __future__ import annotations

import shutil
import sys
from dataclasses import dataclass
from pathlib import Path

from ..policy.models import Profile


@dataclass(frozen=True)
class RuntimePaths:
    """一次启动所需的路径快照。"""

    home: Path
    workspace: Path
    audit_dir: Path
    real_bash: Path | None
    python: Path | None
    bash_paths: tuple[Path, ...]


def probe_paths(profile: Profile) -> RuntimePaths:
    """探测用户 home、工作区、真 bash、Python 与 bash 的规范路径。"""
    bash_candidates: list[Path] = []
    for candidate in (shutil.which("bash"), "/bin/bash", "/usr/bin/bash"):
        if candidate is None:
            continue
        resolved = Path(candidate).resolve()
        if resolved.exists() and resolved not in bash_candidates:
            bash_candidates.append(resolved)

    real_bash = bash_candidates[0] if bash_candidates else None
    python = Path(sys.executable).resolve() if sys.executable else None

    return RuntimePaths(
        home=Path.home(),
        workspace=profile.workspace,
        audit_dir=profile.audit.log_dir,
        real_bash=real_bash,
        python=python,
        bash_paths=tuple(bash_candidates),
    )
