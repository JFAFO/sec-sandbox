"""Textual 全屏配置表单（§4.9）。

六类配置项：workspace、内存、pids、CPU 配额、网络开关、脚本开关。
"""

from __future__ import annotations

from dataclasses import replace

from textual.app import App, ComposeResult
from textual.containers import Vertical
from textual.widgets import Button, Checkbox, Footer, Header, Input, Label, Static

from ..policy.models import Profile
from ..util.paths import canonicalize
from .presets import get_preset


class ProfileForm(App[Profile | None]):
    """返回用户确认的 Profile；取消时返回 ``None``。"""

    CSS = """
    Vertical { padding: 1 2; }
    Input { margin-bottom: 1; }
    Button { margin-right: 1; }
    """

    def __init__(self, profile: Profile) -> None:
        super().__init__()
        self._profile = profile

    def compose(self) -> ComposeResult:
        yield Header()
        with Vertical():
            yield Label("工作区（绝对路径或 $HOME 前缀）")
            yield Input(value=str(self._profile.workspace), id="workspace")
            yield Label("内存上限（如 512M）")
            yield Input(value=self._profile.resources.memory_max, id="memory_max")
            yield Label("最大进程数")
            yield Input(value=str(self._profile.resources.pids_max), id="pids_max")
            yield Label("CPU 配额（如 50%）")
            yield Input(value=self._profile.resources.cpu_quota, id="cpu_quota")
            yield Checkbox("允许网络", value=self._profile.network.enabled, id="network_enabled")
            yield Checkbox("允许脚本", value=self._profile.bash.allow_scripts, id="allow_scripts")
            yield Static("预设：", id="preset-label")
            yield Button("严格", id="preset-strict")
            yield Button("标准", id="preset-standard")
            yield Button("宽松", id="preset-loose")
            yield Button("保存并启动", id="save", variant="primary")
            yield Button("取消", id="cancel")
            yield Static("", id="error")
        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        button_id = event.button.id or ""
        if button_id == "cancel":
            self.exit(None)
            return
        if button_id.startswith("preset-"):
            name = button_id.removeprefix("preset-")
            try:
                self.exit(
                    get_preset(name, workspace=canonicalize(str(self._profile.workspace)))
                )
            except Exception as exc:  # noqa: BLE001 - 表单错误回显
                self.query_one("#error", Static).update(str(exc))
            return
        if button_id == "save":
            try:
                self.exit(self._build_profile())
            except Exception as exc:  # noqa: BLE001
                self.query_one("#error", Static).update(str(exc))

    def _build_profile(self) -> Profile:
        workspace = canonicalize(self.query_one("#workspace", Input).value)
        pids = int(self.query_one("#pids_max", Input).value)
        if pids <= 0:
            raise ValueError("最大进程数必须为正整数")
        resources = replace(self._profile.resources, pids_max=pids)
        resources = replace(
            resources,
            memory_max=self.query_one("#memory_max", Input).value,
            cpu_quota=self.query_one("#cpu_quota", Input).value,
        )
        return replace(
            self._profile,
            workspace=workspace,
            resources=resources,
            network=replace(
                self._profile.network,
                enabled=self.query_one("#network_enabled", Checkbox).value,
            ),
            bash=replace(
                self._profile.bash,
                allow_scripts=self.query_one("#allow_scripts", Checkbox).value,
            ),
        )

    def run_form(self) -> Profile | None:
        """同步运行动画循环并返回结果。"""
        return self.run()
