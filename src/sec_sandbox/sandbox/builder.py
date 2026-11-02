"""``SandboxBuilder`` 组合实现（§4.6）。"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from ..contracts import InnerLaunchRequest, LaunchPlan
from ..policy.models import Profile, ResourceLimits
from .cgroup import build_cgroup
from .inner import build_inner
from .mounts import DEFAULT_READ_BLACKLIST
from .outer import build_outer
from .paths import RuntimePaths


class SandboxBuilderImpl:
    """把 T5-01～T5-05 的构建函数组装成网关可注入的对象。"""

    def __init__(
        self,
        *,
        safe_exec: Path,
        profile_path: Path,
        paths: RuntimePaths | None = None,
        seccomp_fd: int | None = None,
        defaults: Sequence[tuple[str, str]] = DEFAULT_READ_BLACKLIST,
    ) -> None:
        self.safe_exec = safe_exec
        self.profile_path = profile_path
        self.paths = paths
        self.seccomp_fd = seccomp_fd
        self.defaults = tuple(defaults)

    def build_outer(self, profile: Profile, profile_path: Path) -> LaunchPlan:
        return build_outer(
            profile,
            profile_path,
            safe_exec=self.safe_exec,
            paths=self.paths,
            seccomp_fd=self.seccomp_fd,
            defaults=self.defaults,
        )

    def build_inner(self, profile: Profile, req: InnerLaunchRequest) -> LaunchPlan:
        return build_inner(
            profile,
            req,
            profile_path=self.profile_path,
            paths=self.paths,
            seccomp_fd=self.seccomp_fd,
            defaults=self.defaults,
        )

    def build_cgroup(self, plan: LaunchPlan, limits: ResourceLimits) -> LaunchPlan:
        return build_cgroup(plan, limits)
