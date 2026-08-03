from __future__ import annotations

import json
import re
from typing import Any


MASK_PATTERNS = [
    (
        re.compile(
            r"(?i)(authorization|cookie|set-cookie|x-api-key)([\"']?\s*[:=]\s*[\"']?)([^,\"'\s}]+)"
        ),
        r"\1\2[MASKED_HEADER]",
    ),
    (
        re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\b"),
        "[MASKED_JWT]",
    ),
    (
        re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I),
        "[MASKED_EMAIL]",
    ),
    (
        re.compile(r"(?<!\d)(?:\+?82[- ]?)?0?1[016789][ -]?\d{3,4}[ -]?\d{4}(?!\d)"),
        "[MASKED_PHONE]",
    ),
    (
        re.compile(r"https?://([A-Za-z0-9.-]+)(?::\d+)?", re.I),
        "https://[MASKED_DOMAIN]",
    ),
    (
        re.compile(
            r"(?i)(api[_-]?key|secret|access[_-]?token|refresh[_-]?token)"
            r"([\"']?\s*[:=]\s*[\"']?)([A-Za-z0-9._~+/=-]{8,})"
        ),
        r"\1\2[MASKED_SECRET]",
    ),
]


def mask_context(context: dict[str, Any]) -> tuple[str, list[str]]:
    text = json.dumps(context, ensure_ascii=False, default=str)
    applied: list[str] = []
    for index, (pattern, replacement) in enumerate(MASK_PATTERNS):
        text, count = pattern.subn(replacement, text)
        if count:
            applied.append(f"rule_{index}:{count}")
    return text, applied

