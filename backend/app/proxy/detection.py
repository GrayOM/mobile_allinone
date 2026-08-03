from __future__ import annotations

import re
from typing import Any


TOKEN_PATTERN = re.compile(
    r"(?i)(?:access[_-]?token|refresh[_-]?token|api[_-]?key|session(?:id)?)"
    r"[\s\"']*[:=][\s\"']*([A-Za-z0-9._~+/=-]{8,})"
)
EMAIL_PATTERN = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)
PHONE_PATTERN = re.compile(r"(?<!\d)(?:\+?82[- ]?)?0?1[016789][ -]?\d{3,4}[ -]?\d{4}(?!\d)")


def detect_sensitive(
    headers: dict[str, Any], body: str, *, side: str
) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    lowered = {str(key).lower(): str(value) for key, value in headers.items()}
    for name in ("authorization", "cookie", "set-cookie", "x-api-key"):
        if name in lowered:
            candidates.append(
                {
                    "type": name,
                    "side": side,
                    "location": f"header:{name}",
                    "masked": _mask(lowered[name]),
                }
            )
    for kind, pattern in (
        ("token", TOKEN_PATTERN),
        ("email", EMAIL_PATTERN),
        ("phone", PHONE_PATTERN),
    ):
        for match in list(pattern.finditer(body))[:10]:
            value = match.group(1) if match.lastindex else match.group(0)
            candidates.append(
                {
                    "type": kind,
                    "side": side,
                    "location": f"body:{match.start()}",
                    "masked": _mask(value),
                }
            )
    return candidates


def _mask(value: str) -> str:
    if len(value) < 9:
        return "*" * len(value)
    return f"{value[:4]}…{value[-4:]}"

