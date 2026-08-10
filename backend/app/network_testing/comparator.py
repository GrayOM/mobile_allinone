from __future__ import annotations

import json
from typing import Any

from .models import ResponseComparison


SENSITIVE_TERMS = (
    "token",
    "secret",
    "password",
    "cookie",
    "session",
    "email",
    "phone",
    "address",
    "account",
    "card",
)


def _headers(value: dict[str, Any]) -> dict[str, str]:
    return {str(key).casefold(): str(item) for key, item in value.items()}


def _shape(value: Any, prefix: str = "$") -> dict[str, str]:
    if value is None:
        return {prefix: "null"}
    if isinstance(value, bool):
        return {prefix: "boolean"}
    if isinstance(value, (int, float)):
        return {prefix: "number"}
    if isinstance(value, str):
        return {prefix: "string"}
    if isinstance(value, list):
        result = {prefix: "array"}
        if value:
            result.update(_shape(value[0], f"{prefix}[]"))
        return result
    if isinstance(value, dict):
        result = {prefix: "object"}
        for key in sorted(value):
            result.update(_shape(value[key], f"{prefix}.{key}"))
        return result
    return {prefix: type(value).__name__}


def _json_shape(body: str) -> dict[str, str]:
    if not body:
        return {}
    try:
        return _shape(json.loads(body))
    except (json.JSONDecodeError, TypeError):
        return {}


def compare_responses(
    *,
    original_status: int | None,
    original_headers: dict[str, Any],
    original_body: str,
    candidate_status: int | None,
    candidate_headers: dict[str, Any],
    candidate_body: str,
) -> ResponseComparison:
    original_shape = _json_shape(original_body)
    candidate_shape = _json_shape(candidate_body)
    original_keys = set(original_shape)
    candidate_keys = set(candidate_shape)
    shared = original_keys & candidate_keys
    type_changes = [
        {
            "path": path,
            "original": original_shape[path],
            "candidate": candidate_shape[path],
        }
        for path in sorted(shared)
        if original_shape[path] != candidate_shape[path]
    ]
    added = sorted(candidate_keys - original_keys)
    removed = sorted(original_keys - candidate_keys)
    sensitive_added = [
        path
        for path in added
        if any(term in path.casefold() for term in SENSITIVE_TERMS)
    ]
    original_header_map = _headers(original_headers)
    candidate_header_map = _headers(candidate_headers)
    original_length = len(original_body.encode("utf-8"))
    candidate_length = len(candidate_body.encode("utf-8"))
    ratio = (
        round(candidate_length / original_length, 4)
        if original_length
        else None
    )
    status_changed = original_status != candidate_status
    redirect_changed = original_header_map.get("location") != candidate_header_map.get(
        "location"
    )
    authentication_changed = (original_status == 401) != (candidate_status == 401)
    authorization_changed = (original_status == 403) != (candidate_status == 403)
    differences = sum(
        [
            status_changed,
            bool(added or removed or type_changes),
            bool(sensitive_added),
            redirect_changed,
            authentication_changed,
            authorization_changed,
            original_length != candidate_length,
        ]
    )
    return ResponseComparison(
        status_changed=status_changed,
        original_status=original_status,
        candidate_status=candidate_status,
        body_length_delta=candidate_length - original_length,
        body_length_ratio=ratio,
        json_structure_changed=bool(added or removed or type_changes),
        added_keys=added,
        removed_keys=removed,
        value_type_changes=type_changes,
        sensitive_fields_added=sensitive_added,
        redirect_changed=redirect_changed,
        authentication_changed=authentication_changed,
        authorization_changed=authorization_changed,
        summary=f"응답 비교 신호 {differences}건을 식별했습니다.",
    )
