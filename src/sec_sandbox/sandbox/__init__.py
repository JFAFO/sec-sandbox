"""M4 OS 沙箱层：路径探测、挂载参数、bwrap 构建、cgroup 与 seccomp。"""


class SandboxBuildError(Exception):
    """沙箱构建失败（real-bash 缺失、网关入口缺失、profile 不可读等）。"""

