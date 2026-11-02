"""``python -m sec_sandbox`` → 前端入口。"""

from __future__ import annotations

from .frontend.app import main

if __name__ == "__main__":
    raise SystemExit(main())
