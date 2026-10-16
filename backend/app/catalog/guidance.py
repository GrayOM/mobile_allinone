"""Document-derived guidance for the domestic assessment profiles.

The two customer-provided DOCX advisories hold, for every item, the threat
summary, the diagnostic criteria or diagnostic examples, the remediation
guidance and platform-specific remediation examples. Each workstation extracts
them locally with ``scripts/extract_korean_guidance.py`` into
``data/korean_standard_guidance.json`` (gitignored: the repository is public
and must not carry the advisory text). When the file is absent every lookup
returns ``None`` and the workbench falls back to the catalog summaries.

The JSON is data, never executable policy: the workbench still decides which
evidence confirms a finding through ``korean_standards`` definitions.
"""

from __future__ import annotations

import json
import os
from functools import lru_cache
from pathlib import Path
from typing import Any

from backend.app.catalog.korean_standards import (
    CRITICAL_INFRASTRUCTURE,
    DOMESTIC_ALL,
    ELECTRONIC_FINANCIAL,
)

GUIDANCE_PATH = Path(
    os.getenv("MSW_KOREAN_GUIDANCE_PATH")
    or Path(__file__).resolve().parent / "data" / "korean_standard_guidance.json"
)

GUIDANCE_SECTIONS = (
    "description",
    "threats",
    "diagnostic_criteria",
    "diagnostic_examples",
    "remediation",
    "check_scripts",
)


@lru_cache(maxsize=1)
def _load() -> dict[str, Any]:
    try:
        payload = json.loads(GUIDANCE_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"source": {}, "extracted_at": None, "controls": []}
    if not isinstance(payload, dict) or not isinstance(payload.get("controls"), list):
        return {"source": {}, "extracted_at": None, "controls": []}
    return payload


def guidance_source() -> dict[str, Any]:
    payload = _load()
    return {
        "available": bool(payload.get("controls")),
        "path_configured": GUIDANCE_PATH.is_file(),
        "documents": dict(payload.get("source") or {}),
        "extracted_at": payload.get("extracted_at"),
        "control_count": len(payload.get("controls") or []),
    }


@lru_cache(maxsize=1)
def _index() -> dict[tuple[str, str], dict[str, Any]]:
    index: dict[tuple[str, str], dict[str, Any]] = {}
    for item in _load().get("controls") or []:
        if not isinstance(item, dict):
            continue
        profile = str(item.get("profile") or "")
        control_id = str(item.get("control_id") or "")
        if profile and control_id:
            index[(profile, control_id)] = item
    return index


def guidance_for(profile: str, control_id: str) -> dict[str, Any] | None:
    """Return the document guidance for one control or ``None``."""
    source_profile = profile
    if profile == DOMESTIC_ALL:
        if control_id.startswith("CII-MA-"):
            source_profile = CRITICAL_INFRASTRUCTURE
        elif control_id.startswith("EFI-MA-"):
            source_profile = ELECTRONIC_FINANCIAL
    item = _index().get((source_profile, control_id))
    if item is None:
        return None
    examples = item.get("remediation_examples")
    return {
        "profile": profile,
        "source_profile": source_profile,
        "control_id": control_id,
        "title": item.get("title", ""),
        "description": list(item.get("description") or []),
        "threats": list(item.get("threats") or []),
        "diagnostic_criteria": list(item.get("diagnostic_criteria") or []),
        "diagnostic_examples": list(item.get("diagnostic_examples") or []),
        "remediation": list(item.get("remediation") or []),
        "remediation_examples": {
            str(key): list(value)
            for key, value in (examples.items() if isinstance(examples, dict) else [])
        },
        "check_scripts": list(item.get("check_scripts") or []),
    }


def guidance_summary(profile: str, control_id: str) -> dict[str, Any] | None:
    """Compact summary suitable for list rows (counts only, no bodies)."""
    item = guidance_for(profile, control_id)
    if item is None:
        return None
    return {
        "available": True,
        "threat_count": len(item["threats"]),
        "criteria_count": len(item["diagnostic_criteria"]) + len(item["diagnostic_examples"]),
        "remediation_count": len(item["remediation"]),
        "example_platforms": sorted(item["remediation_examples"]),
    }


def guidance_titles(profile: str) -> list[tuple[str, str]]:
    if profile == DOMESTIC_ALL:
        return [
            (control_id, str(item.get("title") or ""))
            for (item_profile, control_id), item in sorted(_index().items())
            if item_profile in {CRITICAL_INFRASTRUCTURE, ELECTRONIC_FINANCIAL}
        ]
    return [
        (control_id, str(item.get("title") or ""))
        for (item_profile, control_id), item in sorted(_index().items())
        if item_profile == profile
    ]
