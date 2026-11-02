"""Textual 全屏配置表单（§4.9）。

六类配置项：workspace、内存、pids、CPU 配额、网络开关、脚本开关。
"""

from __future__ import annotations

from dataclasses import replace
from typing import ClassVar

from textual.app import App, ComposeResult
from textual.containers import Grid, Horizontal, Vertical, VerticalScroll
from textual.widgets import Button, Checkbox, Input, Label, Static

from ..policy.models import Profile
from ..util.paths import canonicalize
from .presets import get_preset


class ProfileForm(App[Profile | None]):
    """返回用户确认的 Profile；取消时返回 ``None``。"""

    BINDINGS: ClassVar[list[tuple[str, str, str]]] = [
        ("ctrl+s", "save", "保存并启动"),
        ("escape", "cancel", "取消"),
    ]

    CSS = """
    Screen {
        background: #111111;
        color: #e5e5e5;
    }

    #page {
        width: 100%;
        height: 100%;
        padding: 2 6;
    }

    #panel {
        width: 100%;
        height: auto;
    }

    #title {
        color: #d97757;
        text-style: bold;
        height: 1;
    }

    #subtitle {
        color: #8a8a8a;
        height: 1;
        margin-bottom: 1;
    }

    #rule {
        height: 1;
        border-bottom: solid #333333;
        margin-bottom: 1;
    }

    .section {
        color: #8a8a8a;
        height: 1;
        margin-top: 1;
        margin-bottom: 1;
    }

    #form {
        grid-size: 2;
        grid-columns: 18 1fr;
        grid-rows: auto;
        grid-gutter: 0 2;
        height: auto;
    }

    .field-label {
        color: #b0b0b0;
        content-align: left middle;
        height: 3;
    }

    Input {
        height: 3;
        background: #1b1b1b;
        border: tall #333333;
        color: #e5e5e5;
    }

    Input:focus {
        border: tall #d97757;
    }

    .checks {
        height: 3;
    }

    Checkbox {
        background: transparent;
        color: #b0b0b0;
        margin-right: 2;
        height: 3;
    }

    #presets {
        height: 3;
        margin-bottom: 1;
    }

    Button {
        height: 3;
        min-width: 10;
        margin-right: 1;
        background: #1b1b1b;
        color: #e5e5e5;
        border: tall #333333;
    }

    Button:hover {
        border: tall #d97757;
    }

    #save {
        min-width: 16;
        background: #d97757;
        color: #111111;
        text-style: bold;
        border: none;
    }

    #save:hover {
        background: #e08b6f;
    }

    #actions {
        height: 3;
        margin-top: 1;
    }

    #error {
        color: #ff6b6b;
        height: auto;
        margin-top: 1;
    }

    #hint {
        color: #6f6f6f;
        height: 1;
        margin-top: 1;
    }
    """

    def __init__(self, profile: Profile) -> None:
        super().__init__()
        self._profile = profile

    def compose(self) -> ComposeResult:
        with VerticalScroll(id="page"):  # noqa: SIM117 - 保持 page/panel 两层
            with Vertical(id="panel"):
                yield Static("✻ sec-sandbox", id="title")
                yield Static("配置工作区与运行限制，然后进入沙箱", id="subtitle")
                yield Static("", id="rule")
                with Grid(id="form"):
                    yield Label("工作区", classes="field-label")
                    yield Input(value=str(self._profile.workspace), id="workspace")
                    yield Label("内存上限", classes="field-label")
                    yield Input(value=self._profile.resources.memory_max, id="memory_max")
                    yield Label("最大进程数", classes="field-label")
                    yield Input(value=str(self._profile.resources.pids_max), id="pids_max")
                    yield Label("CPU 配额", classes="field-label")
                    yield Input(value=self._profile.resources.cpu_quota, id="cpu_quota")
                    yield Label("权限", classes="field-label")
                    with Horizontal(classes="checks"):
                        yield Checkbox(
                            "允许网络",
                            value=self._profile.network.enabled,
                            id="network_enabled",
                        )
                        yield Checkbox(
                            "允许脚本",
                            value=self._profile.bash.allow_scripts,
                            id="allow_scripts",
                        )
                yield Static("预设", classes="section")
                with Horizontal(id="presets"):
                    yield Button("严格", id="preset-strict")
                    yield Button("标准", id="preset-standard")
                    yield Button("宽松", id="preset-loose")
                with Horizontal(id="actions"):
                    yield Button("保存并启动", id="save", variant="primary")
                    yield Button("取消", id="cancel")
                yield Static("", id="error")
                yield Static("Ctrl+S 保存并启动    Esc 取消", id="hint")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        button_id = event.button.id or ""
        if button_id == "cancel":
            self.action_cancel()
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
            self.action_save()

    def action_save(self) -> None:
        try:
            self.exit(self._build_profile())
        except Exception as exc:  # noqa: BLE001
            self.query_one("#error", Static).update(str(exc))

    def action_cancel(self) -> None:
        self.exit(None)

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
