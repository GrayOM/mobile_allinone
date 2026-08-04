from __future__ import annotations

import json

from backend.app.core.targets import normalize_platform
from backend.app.database.models import AppArtifact, FridaScript


_CATEGORY_SIGNALS = {
    "root detection": "root_jailbreak_detection",
    "jailbreak detection": "root_jailbreak_detection",
    "ssl pinning": "certificate_pinning",
    "anti-debug": "debugger_detection",
}


def is_safe_automatic_script(script: FridaScript) -> bool:
    return script.source == "builtin" and script.risk == "low"


def script_applies_to_app(script: FridaScript, app: AppArtifact) -> tuple[bool, str]:
    try:
        if normalize_platform(script.platform) != normalize_platform(app.platform):
            return False, "스크립트와 앱 플랫폼이 다릅니다."
    except ValueError as exc:
        return False, str(exc)

    framework = (script.target_framework or "generic").strip().lower()
    platform = normalize_platform(app.platform)
    searchable = json.dumps(app.analysis_result or {}, ensure_ascii=False).lower()
    if framework not in {"", "generic"}:
        framework_matches = (
            (framework == "android java" and platform == "android")
            or (framework == "ios native" and platform == "ios")
            or framework in searchable
        )
        if not framework_matches:
            return False, f"대상 프레임워크 {script.target_framework} 신호를 확인할 수 없습니다."

    conditions = [item.strip().lower() for item in (script.conditions or []) if item.strip()]
    if not conditions:
        return True, "별도 적용 조건이 없습니다."
    signals = (app.analysis_result or {}).get("signals") or {}
    category_signal = _CATEGORY_SIGNALS.get((script.category or "").strip().lower())
    if category_signal and signals.get(category_signal):
        return True, f"정적 분석 신호 {category_signal}와 일치합니다."
    if any(condition in searchable for condition in conditions):
        return True, "스크립트 적용 조건이 정적 분석 결과와 일치합니다."
    return False, "스크립트 적용 조건을 대상 앱에서 확인할 수 없습니다."
