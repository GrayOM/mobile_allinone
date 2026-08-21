from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterable

from backend.app.database.models import ControlTest, Evidence


TERMINAL_RESULTS = {"confirmed", "not_vulnerable", "not_applicable"}
EXCLUDED_EVIDENCE_TYPES = {
    "approval_record",
    "control_scope_enforcement",
    "approved_ui_action_scope",
    "approved_network_replay_scope",
    "assessment_attestation",
    "assessment_ledger",
    "assessment_ledger_amendment",
    "vulnerability_assessment",
    "evidence_policy",
}
RISK_POINTS = {
    "critical": 36,
    "high": 30,
    "medium": 22,
    "low": 14,
    "info": 6,
}


def ai_eligible_evidence(rows: Iterable[Evidence]) -> list[Evidence]:
    return [
        item for item in rows if item.evidence_type not in EXCLUDED_EVIDENCE_TYPES
    ]


def _attachment_belongs_to_control(
    evidence: Evidence,
    control: ControlTest,
) -> bool:
    if evidence.evidence_type != "manual_assessment_attachment":
        return True
    return (
        isinstance(evidence.inline_data, dict)
        and evidence.inline_data.get("control_test_id") == control.id
    )


def _priority_band(score: int) -> str:
    if score >= 76:
        return "urgent"
    if score >= 56:
        return "high"
    if score >= 36:
        return "medium"
    return "low"


def build_assessment_evidence_priority(
    *,
    run_id: str,
    profile: str,
    controls: Iterable[ControlTest],
    evidence: Iterable[Evidence],
    ai_findings: Iterable[dict[str, Any]],
    provider: str,
    model: str,
    status: str,
    message: str,
    synthetic: bool,
) -> dict[str, Any]:
    evidence_rows = ai_eligible_evidence(evidence)
    evidence_by_id = {item.id: item for item in evidence_rows}
    findings_by_control: dict[str, list[dict[str, Any]]] = {}
    for finding in ai_findings:
        if not isinstance(finding, dict):
            continue
        for control_id in finding.get("control_ids") or []:
            if isinstance(control_id, str):
                findings_by_control.setdefault(control_id, []).append(finding)

    recommendations: list[dict[str, Any]] = []
    terminal_count = 0
    for control in controls:
        if control.result in TERMINAL_RESULTS:
            terminal_count += 1
            continue
        requirements = [list(group) for group in control.evidence_requirements]
        relevant_rows = [
            item
            for item in evidence_rows
            if _attachment_belongs_to_control(item, control)
            and any(item.evidence_type in group for group in requirements)
        ]
        relevant_rows.sort(key=lambda item: (item.sequence, item.id), reverse=True)
        mapped_findings = findings_by_control.get(control.mastg_id, [])
        proposed_ids = list(
            dict.fromkeys(
                evidence_id
                for finding in mapped_findings
                for evidence_id in finding.get("evidence_ids") or []
                if isinstance(evidence_id, str) and evidence_id in evidence_by_id
            )
        )
        proposed_rows = [
            evidence_by_id[item]
            for item in proposed_ids
            if _attachment_belongs_to_control(evidence_by_id[item], control)
        ]

        selected: list[Evidence] = []
        missing: list[list[str]] = []
        for group in requirements:
            candidate = next(
                (item for item in proposed_rows if item.evidence_type in group),
                None,
            )
            if candidate is None:
                candidate = next(
                    (item for item in relevant_rows if item.evidence_type in group),
                    None,
                )
            if candidate is None:
                missing.append(group)
            elif candidate.id not in {item.id for item in selected}:
                selected.append(candidate)

        coverage = (
            (len(requirements) - len(missing)) / len(requirements)
            if requirements
            else 0.0
        )
        confidence = max(
            (
                float(item.get("confidence") or 0.0)
                for item in mapped_findings
                if isinstance(item.get("confidence"), (int, float))
            ),
            default=0.0,
        )
        score = min(
            100,
            RISK_POINTS.get(control.risk, 18)
            + round(coverage * 38)
            + round(confidence * 20)
            + (6 if control.finding_ids else 0),
        )
        rationale = next(
            (
                str(item.get("rationale"))
                for item in sorted(
                    mapped_findings,
                    key=lambda value: float(value.get("confidence") or 0.0),
                    reverse=True,
                )
                if item.get("rationale")
            ),
            (
                "같은 Run에서 필수 유형과 일치하는 원본 증적을 로컬 정책으로 선별했습니다."
                if selected
                else "현재 Run에는 이 항목의 필수 증적 유형이 없어 수집 또는 수동 검토가 필요합니다."
            ),
        )
        recommendations.append(
            {
                "control_test_id": control.id,
                "control_id": control.mastg_id,
                "title": control.title,
                "risk": control.risk,
                "current_result": control.result,
                "priority_score": score,
                "priority_band": _priority_band(score),
                "ai_confidence": confidence,
                "ai_mapped": bool(mapped_findings),
                "selection_source": (
                    "ai_with_local_policy" if mapped_findings else "local_policy"
                ),
                "suggested_evidence_ids": [item.id for item in selected],
                "suggested_evidence_types": [
                    item.evidence_type for item in selected
                ],
                "missing_requirements": missing,
                "requirements_satisfied": bool(requirements) and not missing,
                "rationale": rationale,
                "decision_boundary": (
                    "추천은 증적 검토 순서만 제시하며 판정·증적 연결·DOCX 수록을 자동 수행하지 않습니다."
                ),
            }
        )

    recommendations.sort(
        key=lambda item: (
            -int(item["priority_score"]),
            str(item["control_id"]),
        )
    )
    return {
        "version": 1,
        "run_id": run_id,
        "assessment_profile": profile,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "generated_by": (
            "ai_with_local_policy" if status == "available" else "local_policy_fallback"
        ),
        "provider": provider,
        "model": model,
        "status": status,
        "message": message,
        "decision_policy": "recommendation_only_no_automatic_verdict",
        "synthetic": synthetic,
        "terminal_controls_excluded": terminal_count,
        "unresolved_controls": len(recommendations),
        "ai_mapped_controls": sum(item["ai_mapped"] for item in recommendations),
        "ready_with_required_evidence": sum(
            item["requirements_satisfied"] for item in recommendations
        ),
        "recommendations": recommendations,
    }
