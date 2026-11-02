"""前端使用的预设入口（复用 policy.presets 的唯一源）。"""

from __future__ import annotations

from ..policy.presets import get_preset, preset_names

__all__ = ["get_preset", "preset_names"]
