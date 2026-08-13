from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from typing import Any


class ComponentCandidateError(ValueError):
    pass


_SCHEME_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]{0,63}$")
_COMPONENT_PATTERN = re.compile(r"^[A-Za-z0-9_.$]{1,220}$")
_EXECUTABLE_COMPONENT_PATTERN = re.compile(r"^[A-Za-z0-9_.]{1,220}$")
_HOST_LABEL_PATTERN = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
)
_PATH_PATTERN = re.compile(r"^(?:/[A-Za-z0-9._~%/@:+-]*)?$")
_BLOCKED_SCHEMES = {"content", "data", "file", "intent", "javascript"}


def _candidate_id(payload: dict[str, Any]) -> str:
    serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()[:24]


def _clean_component_name(value: Any) -> str | None:
    name = str(value or "").strip()
    if not _COMPONENT_PATTERN.fullmatch(name):
        return None
    return name


def _deep_link_uri(item: dict[str, Any]) -> str | None:
    scheme = str(item.get("scheme") or "").strip().casefold()
    if not _SCHEME_PATTERN.fullmatch(scheme) or scheme in _BLOCKED_SCHEMES:
        return None
    host = str(item.get("host") or "").strip().casefold()
    if host:
        try:
            ipaddress.ip_address(host)
        except ValueError:
            try:
                host = host.encode("idna").decode("ascii")
            except UnicodeError:
                return None
            if len(host) > 253 or any(
                not _HOST_LABEL_PATTERN.fullmatch(label) for label in host.split(".")
            ):
                return None
    path = str(item.get("path") or "").strip()
    if len(path) > 500 or not _PATH_PATTERN.fullmatch(path):
        return None
    if path and not path.startswith("/"):
        path = "/" + path
    return f"{scheme}://{host}{path}"


def build_component_candidates(
    *,
    platform: str,
    package_name: str | None,
    analysis_result: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    analysis = analysis_result if isinstance(analysis_result, dict) else {}
    package = str(package_name or "").strip()
    candidates: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    for raw in analysis.get("components") or []:
        if not isinstance(raw, dict) or raw.get("exported") is not True or raw.get("permission"):
            continue
        component_name = _clean_component_name(raw.get("name"))
        component_type = str(raw.get("type") or "component").strip().casefold()
        if not component_name:
            continue
        key = ("exported_component", f"{component_type}:{component_name}")
        if key in seen:
            continue
        seen.add(key)
        executable = (
            platform == "android"
            and component_type in {"activity", "activity-alias"}
            and bool(_EXECUTABLE_COMPONENT_PATTERN.fullmatch(component_name))
        )
        identity = {
            "kind": "exported_component",
            "package_name": package,
            "component_type": component_type,
            "component_name": component_name,
        }
        candidates.append(
            {
                "id": _candidate_id(identity),
                **identity,
                "label": f"외부 노출 {component_type} · {component_name}",
                "target": f"{package}/{component_name}" if package else component_name,
                "location": component_name,
                "risk": "medium",
                "execution_status": "approval_required" if executable else "manual_required",
                "rationale": (
                    "승인된 테스트 단말에서 외부 진입 가능 여부를 화면·로그와 함께 확인합니다."
                    if executable
                    else "상태 변경 또는 임의 데이터 접근 가능성이 있어 자동 호출하지 않습니다."
                ),
            }
        )

    for raw in analysis.get("deep_links") or []:
        if not isinstance(raw, dict):
            continue
        uri = _deep_link_uri(raw)
        if not uri:
            continue
        component_name = _clean_component_name(raw.get("component"))
        key = ("deep_link", f"{component_name or ''}:{uri}")
        if key in seen:
            continue
        seen.add(key)
        executable = platform == "android" and bool(package)
        identity = {
            "kind": "deep_link",
            "package_name": package,
            "component_name": component_name,
            "uri": uri,
        }
        candidates.append(
            {
                "id": _candidate_id(identity),
                **identity,
                "component_type": "activity",
                "label": f"딥링크 · {uri}",
                "target": uri,
                "location": component_name or uri,
                "risk": "medium",
                "execution_status": "approval_required" if executable else "manual_required",
                "rationale": (
                    "Manifest에 선언된 URI를 대상 패키지로 한정해 외부 진입 가능 여부를 확인합니다."
                    if executable
                    else "현재 플랫폼에서는 자동 호출을 지원하지 않아 수동 재검증이 필요합니다."
                ),
            }
        )
    return candidates


def resolve_component_candidate(
    candidate_id: str,
    *,
    platform: str,
    package_name: str | None,
    analysis_result: dict[str, Any] | None,
) -> dict[str, Any]:
    candidate = next(
        (
            item
            for item in build_component_candidates(
                platform=platform,
                package_name=package_name,
                analysis_result=analysis_result,
            )
            if item["id"] == candidate_id
        ),
        None,
    )
    if candidate is None:
        raise ComponentCandidateError(
            "현재 활성 정적 분석 결과에 속한 검증 후보를 찾을 수 없습니다."
        )
    return candidate
