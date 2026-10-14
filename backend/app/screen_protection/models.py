from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(slots=True)
class WindowProtection:
    name: str
    secure: bool | None
    focused: bool
    flags: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ScreenProtectionObservation:
    """What the inspector saw for the target package, without any verdict."""

    status: str
    message: str
    windows: list[WindowProtection] = field(default_factory=list)
    focused_window_secure: bool | None = None
    task_id: int | None = None
    foreground_dark_ratio: float | None = None
    recents_dark_ratio: float | None = None
    task_snapshot: dict[str, Any] = field(default_factory=dict)
    steps: list[dict[str, Any]] = field(default_factory=list)
    restored_foreground: bool | None = None
    synthetic: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "message": self.message,
            "windows": [item.to_dict() for item in self.windows],
            "focused_window_secure": self.focused_window_secure,
            "task_id": self.task_id,
            "foreground_dark_ratio": self.foreground_dark_ratio,
            "recents_dark_ratio": self.recents_dark_ratio,
            "task_snapshot": self.task_snapshot,
            "steps": self.steps,
            "restored_foreground": self.restored_foreground,
            "synthetic": self.synthetic,
        }
