from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.catalog import controls_for_profile, execution_plan
from backend.app.database.models import AppArtifact, ControlTest, Project, RawFinding


ASSESSMENT_PLAN_VERSION = 1
TERMINAL_RESULTS = {"confirmed", "not_vulnerable", "not_applicable"}

_RAW_CATEGORY_ALIASES: dict[str, set[str]] = {
    "build_configuration": {"debugger_detection"},
    "data_protection": {"local_storage", "sensitive_data_exposure"},
    "exposed_component": {"navigation", "deep_link", "authorization"},
    "webview": {"xss", "navigation"},
    "certificate_pinning": {"certificate_validation"},
    "root_detection": {"root_detection"},
}

_SIGNAL_CATEGORY_ALIASES: dict[str, set[str]] = {
    "root_jailbreak_detection": {"root_detection", "jailbreak_detection"},
    "root_detection": {"root_detection"},
    "jailbreak_detection": {"jailbreak_detection"},
    "certificate_pinning": {"certificate_validation"},
    "debugger_detection": {"debugger_detection"},
    "frida_hook_detection": {"debugger_detection", "integrity"},
    "integrity_signature": {"integrity"},
    "webview": {"xss", "navigation"},
    "javascript_interface": {"xss", "navigation"},
}

_SECRET_CANDIDATE_KINDS = {
    "api_key",
    "credential",
    "high_entropy",
    "password",
    "private_key",
    "secret",
    "token",
}


def _expanded_categories(category: str) -> set[str]:
    return {category, *_RAW_CATEGORY_ALIASES.get(category, set())}


def _static_candidates(
    artifact: AppArtifact,
    raw_rows: list[RawFinding],
) -> list[dict[str, Any]]:
    values: list[dict[str, Any]] = []
    for item in raw_rows:
        values.append(
            {
                "source": item.source_tool,
                "category": item.category,
                "mapped_categories": sorted(_expanded_categories(item.category)),
                "title": item.title,
                "severity": item.severity,
                "location": item.location,
            }
        )

    analysis = artifact.analysis_result if isinstance(artifact.analysis_result, dict) else {}
    signals = analysis.get("signals") if isinstance(analysis.get("signals"), dict) else {}
    for signal, rows in signals.items():
        if not isinstance(rows, list) or not rows:
            continue
        mapped = _SIGNAL_CATEGORY_ALIASES.get(str(signal), {str(signal)})
        values.append(
            {
                "source": "native_static_signal",
                "category": str(signal),
                "mapped_categories": sorted(mapped),
                "title": f"{signal} 정적 통제 신호 {len(rows)}건",
                "severity": "info",
                "location": "static analysis signals",
            }
        )

    candidates = analysis.get("candidates")
    if isinstance(candidates, list):
        for item in candidates[:100]:
            if not isinstance(item, dict):
                continue
            kind = str(item.get("kind") or "string")
            mapped = {"sensitive_data_exposure"}
            if kind in _SECRET_CANDIDATE_KINDS:
                mapped.add("hardcoded_secret")
            values.append(
                {
                    "source": "native_static_candidate",
                    "category": kind,
                    "mapped_categories": sorted(mapped),
                    "title": f"{kind} 문자열 후보",
                    "severity": str(item.get("severity") or "info"),
                    "location": str(item.get("location") or "archive"),
                }
            )
    return values


def _ai_control_ids(artifact: AppArtifact) -> set[str]:
    analysis = artifact.analysis_result if isinstance(artifact.analysis_result, dict) else {}
    triage = analysis.get("ai_static_triage")
    if not isinstance(triage, dict) or triage.get("artifact_sha256") != artifact.sha256:
        return set()
    values: set[str] = set()
    for finding in triage.get("findings") or []:
        if not isinstance(finding, dict):
            continue
        values.update(
            item
            for item in finding.get("control_ids") or []
            if isinstance(item, str)
        )
    return values


def _blockers(execution: dict[str, Any], evaluator: str) -> list[str]:
    if execution["lane"] == "device_required":
        values = ["authorized_physical_device"]
        if evaluator in {"root_execution", "local_storage", "memory_exposure"}:
            values.append("privileged_device_access")
        if evaluator in {"root_execution", "memory_exposure", "dynamic_review"}:
            values.append("frida_runtime_ready")
        return values
    if execution["lane"] == "server_scope_required":
        values = ["approved_test_server_scope"]
        if execution["test_account_required"]:
            values.append("test_account_reference")
        return values
    if execution["lane"] == "manual_review":
        return ["authorized_reviewer"]
    return []


def _queue_status(
    *,
    lane: str,
    analysis_completed: bool,
    candidate_count: int,
    evaluator: str,
) -> str:
    if lane == "device_required":
        return "waiting_device"
    if lane == "server_scope_required":
        return "waiting_server_scope"
    if lane == "manual_review":
        return "waiting_manual_review"
    if not analysis_completed:
        return "static_analysis_failed"
    if candidate_count:
        return "candidate_detected"
    if evaluator == "static_review":
        return "review_ready"
    return "screened_no_candidate"


def refresh_app_assessment_plan(
    db: Session,
    *,
    project: Project,
    artifact: AppArtifact,
) -> dict[str, Any]:
    profile = project.assessment_profile
    definitions = controls_for_profile(profile)
    baseline_rows = db.scalars(
        select(ControlTest).where(
            ControlTest.app_id == artifact.id,
            ControlTest.run_id.is_(None),
            ControlTest.standard == profile,
        )
    ).all()
    baseline = {item.mastg_id: item for item in baseline_rows}
    raw_rows = db.scalars(
        select(RawFinding)
        .where(RawFinding.app_id == artifact.id)
        .order_by(RawFinding.created_at, RawFinding.id)
        .limit(1000)
    ).all()
    static_candidates = _static_candidates(artifact, raw_rows)
    ai_control_ids = _ai_control_ids(artifact)
    analysis_completed = artifact.analysis_status == "completed"

    controls: list[dict[str, Any]] = []
    for definition in definitions:
        execution = execution_plan(definition)
        target_categories = set(definition.finding_categories)
        matches = [
            item
            for item in static_candidates
            if target_categories.intersection(item["mapped_categories"])
        ]
        ai_mapped = definition.control_id in ai_control_ids
        candidate_count = len(matches) + int(ai_mapped)
        queue_status = _queue_status(
            lane=execution["lane"],
            analysis_completed=analysis_completed,
            candidate_count=candidate_count,
            evaluator=definition.evaluator,
        )
        row = baseline.get(definition.control_id)
        if row and row.result not in TERMINAL_RESULTS:
            if execution["lane"] == "ready_now":
                row.status = "completed" if analysis_completed else "failed"
                row.result = "needs_review" if candidate_count else "not_tested"
                if candidate_count:
                    row.summary = (
                        f"정적 선별에서 관련 후보 {candidate_count}건을 연결했습니다. "
                        "재현 증적 전에는 취약점을 확정하지 않습니다."
                    )
                elif analysis_completed:
                    row.summary = (
                        "정적 선별을 완료했지만 관련 후보를 찾지 못했습니다. "
                        "이는 양호 판정이 아니며 문서 기준의 전문가 검토가 남아 있습니다."
                    )
                else:
                    row.summary = "정적 분석이 완료되지 않아 현재 항목을 선별할 수 없습니다."
            else:
                row.status = "manual_required"
                row.result = "not_tested"
                row.summary = execution["next_action"]

        controls.append(
            {
                "control_id": definition.control_id,
                "group": definition.group,
                "title": definition.title,
                "risk": definition.risk,
                "lane": execution["lane"],
                "queue_status": queue_status,
                "screening_completed": execution["lane"] == "ready_now"
                and analysis_completed,
                "candidate_count": candidate_count,
                "ai_mapped": ai_mapped,
                "static_candidates": matches[:10],
                "blockers": _blockers(execution, definition.evaluator),
                "available_now": execution["available_now"],
                "next_action": execution["next_action"],
                "test_account_required": execution["test_account_required"],
                "state_changing": execution["state_changing"],
            }
        )

    lane_counts = Counter(item["lane"] for item in controls)
    queue_counts = Counter(item["queue_status"] for item in controls)
    ready_rows = [item for item in controls if item["lane"] == "ready_now"]
    plan = {
        "version": ASSESSMENT_PLAN_VERSION,
        "app_id": artifact.id,
        "artifact_sha256": artifact.sha256,
        "assessment_profile": profile,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "generated_by": "local_deterministic_policy",
        "decision_policy": "no_runtime_evidence_no_confirmation",
        "total": len(controls),
        "lane_counts": dict(lane_counts),
        "queue_counts": dict(queue_counts),
        "ready_now_total": len(ready_rows),
        "ready_now_screened": sum(item["screening_completed"] for item in ready_rows),
        "candidate_controls": sum(bool(item["candidate_count"]) for item in controls),
        "controls": controls,
    }
    analysis = dict(artifact.analysis_result or {})
    analysis["assessment_plan"] = plan
    artifact.analysis_result = analysis
    db.flush()
    return plan


def stored_plan_is_current(artifact: AppArtifact, profile: str) -> bool:
    analysis = artifact.analysis_result if isinstance(artifact.analysis_result, dict) else {}
    plan = analysis.get("assessment_plan")
    return bool(
        isinstance(plan, dict)
        and plan.get("version") == ASSESSMENT_PLAN_VERSION
        and plan.get("app_id") == artifact.id
        and plan.get("artifact_sha256") == artifact.sha256
        and plan.get("assessment_profile") == profile
    )
