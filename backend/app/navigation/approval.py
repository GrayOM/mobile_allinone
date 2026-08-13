from __future__ import annotations

import hashlib
import json
from typing import Any


class NavigationApprovalError(ValueError):
    """Raised when a stored navigation proposal cannot be safely approved."""


def navigation_candidate_id(candidate: dict[str, Any]) -> str:
    material = {
        "state_fingerprint": str(candidate.get("state_fingerprint") or ""),
        "element_id": str(candidate.get("element_id") or ""),
        "action_type": str(candidate.get("action_type") or ""),
        "label": str(candidate.get("label") or ""),
        "risk": str(candidate.get("risk") or ""),
    }
    encoded = json.dumps(
        material, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()[:24]


def normalized_navigation_candidate(candidate: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(candidate)
    normalized["id"] = navigation_candidate_id(normalized)
    return normalized


def approval_eligible(candidate: dict[str, Any]) -> bool:
    return (
        candidate.get("action_type") == "tap"
        and candidate.get("risk") == "medium"
        and candidate.get("requires_approval") is True
        and bool(candidate.get("element_id"))
        and bool(candidate.get("state_fingerprint"))
    )


def pending_navigation_candidates(options: dict[str, Any]) -> list[dict[str, Any]]:
    navigation = options.get("navigation")
    raw = (
        navigation.get("pending_approval")
        if isinstance(navigation, dict)
        else options.get("pending_navigation_actions")
    )
    if not isinstance(raw, list):
        return []
    return [
        normalized_navigation_candidate(item)
        for item in raw
        if isinstance(item, dict)
    ]


def resolve_navigation_candidate(
    options: dict[str, Any], candidate_id: str
) -> dict[str, Any]:
    candidate = next(
        (
            item
            for item in pending_navigation_candidates(options)
            if item["id"] == candidate_id
        ),
        None,
    )
    if candidate is None:
        raise NavigationApprovalError(
            "현재 Run의 승인 대기 UI 원장에서 후보를 찾을 수 없습니다."
        )
    if not approval_eligible(candidate):
        raise NavigationApprovalError(
            "고위험·차단·입력 동작은 자동 실행하지 않으며 수동 재검증이 필요합니다."
        )
    return candidate
