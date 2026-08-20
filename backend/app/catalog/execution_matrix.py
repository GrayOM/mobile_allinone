from __future__ import annotations

from collections import Counter
from typing import Any, Iterable

from backend.app.catalog.korean_standards import StandardControlDefinition


DEVICE_EVALUATORS = {
    "root_execution",
    "local_storage",
    "memory_exposure",
    "runtime_logs",
    "forced_screen",
    "deep_link",
    "ui_review",
    "dynamic_review",
}
NETWORK_EVALUATORS = {"network_plaintext", "network_review"}
TEST_ACCOUNT_TOKENS = {
    "authentication",
    "authorization",
    "transaction",
    "session",
    "password",
    "credential",
    "ownership",
    "csrf",
}


def _contains_token(categories: Iterable[str], tokens: set[str]) -> bool:
    return any(token in category for category in categories for token in tokens)


def remediation_for_control(control: StandardControlDefinition) -> str:
    categories = set(control.finding_categories)
    if categories.intersection({"root_detection", "jailbreak_detection"}):
        return (
            "루팅·탈옥 및 후킹 상태를 복수 신호로 검증하고, 탐지 시 인증정보와 중요 기능을 "
            "노출하지 않은 채 서버 정책과 연계해 제한한다. 클라이언트 탐지만을 유일한 보안 경계로 사용하지 않는다."
        )
    if "local_storage" in categories:
        return (
            "개인·인증·금융정보를 평문 파일이나 DB에 저장하지 않고 플랫폼 보안 저장소와 "
            "키 보호 기능을 사용한다. 로그아웃·만료 시 잔존 데이터를 안전하게 제거한다."
        )
    if categories.intersection({"runtime_log_exposure", "sensitive_data_exposure"}):
        return (
            "운영 빌드의 민감정보 로그와 과도한 오류 출력을 제거하고, 필요한 기록은 마스킹·접근통제·보존기간을 적용한다."
        )
    if any(
        "injection" in item or item in {"xxe", "xss", "ssti", "ssrf"}
        for item in categories
    ):
        return (
            "외부 입력을 서버의 데이터와 명령으로 분리하고 허용목록 검증, 안전한 파서, 매개변수화 API를 적용한다. "
            "클라이언트 검증과 별개로 서버에서 다시 검증한다."
        )
    if _contains_token(
        categories,
        {"authentication", "authorization", "transaction", "session", "password", "credential"},
    ):
        return (
            "모든 중요 요청에서 서버가 사용자·단말·세션·거래 객체의 소유권과 인증 단계를 다시 검증하고, "
            "재사용·우회·오류 횟수·만료 정책을 일관되게 적용한다."
        )
    if any(
        "tls" in item or "certificate" in item or "network" in item
        for item in categories
    ):
        return (
            "신뢰된 인증서와 안전한 TLS 설정을 강제하고 민감정보는 암호화된 구간으로만 전송한다. "
            "인증서 오류와 평문 fallback은 실패로 처리한다."
        )
    if categories.intersection(
        {"obfuscation", "hardcoded_secret", "integrity", "debugger_detection"}
    ):
        return (
            "운영 빌드에서 비밀정보를 제거하고 난독화·무결성·디버깅 제한을 적용하되, "
            "핵심 권한 검증과 비밀 관리는 서버 및 플랫폼 보안 저장소에 둔다."
        )
    if categories.intersection({"deep_link", "navigation", "exposed_component"}):
        return (
            "외부 진입점의 대상·파라미터·호출자를 검증하고 민감 화면과 기능은 서버 인증·인가를 통과한 경우에만 실행한다."
        )
    return (
        "문서의 취약 조건을 서버와 앱 양쪽에서 거부하도록 입력·상태·권한 검증을 적용하고, "
        "수정 후 동일 재현 절차와 원본 증적으로 재점검한다."
    )


def execution_plan(control: StandardControlDefinition) -> dict[str, Any]:
    categories = tuple(control.finding_categories)
    device_required = control.evaluator in DEVICE_EVALUATORS
    server_required = control.evaluator in NETWORK_EVALUATORS or (
        control.automation == "manual" and not device_required
    )
    test_account_required = _contains_token(categories, TEST_ACCOUNT_TOKENS)
    state_changing = control.risk in {"high", "blocked"} and (
        server_required or test_account_required
    )

    if control.automation == "static" or control.evaluator == "static_review":
        lane = "ready_now"
        capability = "static_review_ready"
        next_action = "APK·IPA 정적 분석 결과와 코드 위치를 검토해 후보를 판정합니다."
        available_now = ["native_static", "oss_static_correlation", "ai_static_triage"]
    elif device_required:
        lane = "device_required"
        capability = "prepared_waiting_for_device"
        next_action = "실제 단말 연결 전에는 Mock 연습과 외부 증적 가져오기까지만 수행합니다."
        available_now = ["mock_rehearsal", "manual_evidence_import", "ai_test_plan"]
    elif server_required:
        lane = "server_scope_required"
        capability = "test_case_ready"
        next_action = "승인된 테스트 서버·계정 범위가 준비되면 수동 재현하고 증적을 연결합니다."
        available_now = ["test_case_definition", "manual_evidence_import", "ai_test_plan"]
    else:
        lane = "manual_review"
        capability = "manual_evidence_ready"
        next_action = "문서 기준에 따라 수동 검토하고 취약한 경우에만 원본 증적을 첨부합니다."
        available_now = ["manual_evidence_import", "ai_test_plan"]

    return {
        "lane": lane,
        "capability": capability,
        "available_now": available_now,
        "device_required": device_required,
        "server_scope_required": server_required,
        "test_account_required": test_account_required,
        "state_changing": state_changing,
        "automatic_execution": control.automation in {"static", "dynamic", "hybrid"}
        and not state_changing,
        "next_action": next_action,
        "remediation": remediation_for_control(control),
    }


def execution_matrix(controls: Iterable[StandardControlDefinition]) -> dict[str, Any]:
    rows = [
        {
            "control_id": control.control_id,
            "profile": control.profile,
            "group": control.group,
            "title": control.title,
            "automation": control.automation,
            "evaluator": control.evaluator,
            "risk": control.risk,
            "evidence_requirements": [
                list(item) for item in control.evidence_requirements
            ],
            **execution_plan(control),
        }
        for control in controls
    ]
    lanes = Counter(item["lane"] for item in rows)
    return {
        "total": len(rows),
        "lane_counts": dict(lanes),
        "device_deferred": sum(1 for item in rows if item["device_required"]),
        "ready_without_device": sum(
            1 for item in rows if not item["device_required"]
        ),
        "controls": rows,
    }
