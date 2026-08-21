from __future__ import annotations

import hashlib
from collections import Counter
from typing import Any, Iterable
from urllib.parse import urlsplit

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.catalog import control_by_id
from backend.app.database.models import (
    AppArtifact,
    ControlTest,
    DiagnosticRun,
    Evidence,
    Finding,
    FindingSource,
    ProxyFlow,
)


TERMINAL_ASSESSMENT_RESULTS = {"confirmed", "not_vulnerable", "not_applicable"}


def _requirements_satisfied(
    requirements: Iterable[Iterable[str]],
    evidence: Iterable[Evidence],
) -> bool:
    available = {item.evidence_type for item in evidence}
    return all(available.intersection(group) for group in requirements)


def _evidence_for_requirements(
    requirements: Iterable[Iterable[str]],
    evidence: Iterable[Evidence],
) -> list[Evidence]:
    relevant = {kind for group in requirements for kind in group}
    return [item for item in evidence if item.evidence_type in relevant]


def _finding_evidence_ids(db: Session, finding: Finding) -> list[str]:
    values = [item.id for item in finding.evidence]
    for source in db.scalars(
        select(FindingSource).where(FindingSource.finding_id == finding.id)
    ).all():
        values.extend(source.evidence_ids)
    return list(dict.fromkeys(values))


def _matching_confirmed_findings(
    db: Session,
    run: DiagnosticRun,
    categories: list[str],
) -> list[tuple[Finding, list[str]]]:
    if not categories:
        return []
    findings = db.scalars(
        select(Finding).where(
            Finding.run_id == run.id,
            Finding.verdict == "confirmed",
            Finding.category.in_(categories),
        )
    ).all()
    return [(item, _finding_evidence_ids(db, item)) for item in findings]


def _privileged_app_execution(
    evidence: list[Evidence],
) -> tuple[bool, list[str]]:
    device_rows = [item for item in evidence if item.evidence_type == "device_state"]
    privileged_rows = [
        item
        for item in device_rows
        if (
            isinstance(item.inline_data, dict)
            and isinstance(item.inline_data.get("device"), dict)
            and item.inline_data["device"].get("privileged") is True
        )
    ]
    process_rows = [
        item
        for item in evidence
        if item.evidence_type in {"command_log", "device_log"}
        and "프로세스" in item.title
    ]
    running_rows = [
        item
        for item in process_rows
        if (
            isinstance(item.inline_data, dict)
            and item.inline_data.get("status") == "available"
            and (
                bool((item.inline_data.get("data") or {}).get("running"))
                or bool((item.inline_data.get("data") or {}).get("pids"))
            )
        )
    ]
    preferred_process_titles = (
        "앱 프로세스 실행 확인",
        "Frida Spawn 후 프로세스 실행 확인",
        "Frida Attach 후 프로세스 유지 확인",
    )
    representative_process = next(
        (
            item
            for title in preferred_process_titles
            for item in running_rows
            if item.title == title
        ),
        running_rows[-1] if running_rows else None,
    )
    screenshots = [item for item in evidence if item.evidence_type == "screenshot"]
    preferred_titles = (
        "승인된 보안통제 우회 적용 후",
        "우회 적용 후",
        "승인된 Frida 우회 적용 후 앱 실행",
        "앱 실행 직후",
    )
    representative_screen = next(
        (
            item
            for title in preferred_titles
            for item in reversed(screenshots)
            if item.title == title
        ),
        screenshots[0] if screenshots else None,
    )
    bypass_rows = [
        item
        for item in evidence
        if item.evidence_type == "frida_script"
        and isinstance(item.inline_data, dict)
        and item.inline_data.get("risk") == "high"
        and item.inline_data.get("category")
        in {"Root Detection Bypass", "Jailbreak Detection Bypass"}
        and isinstance(item.inline_data.get("result"), dict)
        and item.inline_data["result"].get("status") == "available"
    ]
    linked = [
        *privileged_rows[-1:],
        *([representative_process] if representative_process else []),
        *([representative_screen] if representative_screen else []),
        *bypass_rows[-1:],
    ]
    return bool(privileged_rows and running_rows and representative_screen), [
        item.id for item in linked
    ]


def _plaintext_transport(
    db: Session,
    run: DiagnosticRun,
    evidence: list[Evidence],
) -> tuple[bool, list[str]]:
    plaintext = [
        item
        for item in db.scalars(
            select(ProxyFlow).where(ProxyFlow.run_id == run.id)
        ).all()
        if urlsplit(item.url).scheme.casefold() == "http"
    ]
    linked = [
        item.id
        for item in evidence
        if item.evidence_type in {"network_capture", "manual_proxy_import"}
    ]
    return bool(plaintext and linked), linked


def upsert_standard_finding(
    db: Session,
    *,
    run: DiagnosticRun,
    app: AppArtifact,
    control: ControlTest,
    evidence_ids: list[str],
    rationale: str,
) -> Finding:
    source_rule = f"{control.standard}:{control.mastg_id}"
    existing = db.scalar(
        select(Finding)
        .join(FindingSource, FindingSource.finding_id == Finding.id)
        .where(
            Finding.run_id == run.id,
            FindingSource.source_rule_id == source_rule,
        )
        .limit(1)
    )
    definition = control_by_id(control.standard, control.mastg_id)
    category = (
        control.finding_categories[0]
        if control.finding_categories
        else "assessment_control"
    )
    if existing:
        existing.verdict = "confirmed"
        existing.rationale = rationale
        existing.reproduction = list(control.criteria)
        source = db.scalar(
            select(FindingSource).where(
                FindingSource.finding_id == existing.id,
                FindingSource.source_rule_id == source_rule,
            )
        )
        if source:
            source.evidence_ids = list(dict.fromkeys(evidence_ids))
        return existing
    finding = Finding(
        project_id=run.project_id,
        run_id=run.id,
        title=control.title,
        category=category,
        platform=app.platform,
        severity=definition.severity if definition else "medium",
        location=control.mastg_id,
        verdict="confirmed",
        confidence=1.0,
        rationale=rationale,
        reproduction=list(control.criteria),
        false_positive_risk=(
            "선택한 국내 기준의 진단 조건과 Run 원본 증적을 다시 검토하면 판정을 재현할 수 있습니다."
        ),
        additional_checks=[],
        source=f"standard:{control.standard}",
        synthetic=run.synthetic,
    )
    db.add(finding)
    db.flush()
    fingerprint = hashlib.sha256(
        f"{run.id}:{control.standard}:{control.mastg_id}".encode("utf-8")
    ).hexdigest()
    db.add(
        FindingSource(
            finding_id=finding.id,
            raw_finding_id=None,
            source_tool=f"standard:{control.standard}",
            source_rule_id=source_rule,
            fingerprint=fingerprint,
            evidence_ids=list(dict.fromkeys(evidence_ids)),
        )
    )
    return finding


def evaluate_standard_controls(
    db: Session,
    run: DiagnosticRun,
    app: AppArtifact,
) -> dict[str, Any]:
    profile = str(run.options.get("assessment_profile") or app.project.assessment_profile)
    controls = db.scalars(
        select(ControlTest)
        .where(
            ControlTest.run_id == run.id,
            ControlTest.standard == profile,
        )
        .order_by(ControlTest.mastg_id)
    ).all()
    evidence = db.scalars(
        select(Evidence)
        .where(Evidence.run_id == run.id)
        .order_by(Evidence.sequence)
    ).all()
    evidence_by_id = {item.id: item for item in evidence}
    run_finding_ids = set(
        db.scalars(select(Finding.id).where(Finding.run_id == run.id)).all()
    )
    ai_recommendations: dict[str, list[dict[str, Any]]] = {}
    for item in run.options.get("ai_assessment_recommendations") or []:
        finding_id = item.get("finding_id") if isinstance(item, dict) else None
        if not isinstance(finding_id, str) or finding_id not in run_finding_ids:
            continue
        control_ids = item.get("control_ids")
        if not isinstance(control_ids, list):
            continue
        for control_id in control_ids:
            if isinstance(control_id, str):
                ai_recommendations.setdefault(control_id, []).append(item)

    for control in controls:
        definition = control_by_id(profile, control.mastg_id)
        if definition is None:
            control.status = "failed"
            control.result = "unknown"
            control.summary = "현재 카탈로그에서 항목 정의를 찾지 못했습니다."
            continue

        if control.result in TERMINAL_ASSESSMENT_RESULTS:
            linked = [
                evidence_by_id[item]
                for item in control.evidence_ids
                if item in evidence_by_id
            ]
            if control.result != "confirmed" or _requirements_satisfied(
                control.evidence_requirements, linked
            ):
                continue
            control.result = "needs_review"
            control.status = "completed"
            control.summary = "기존 확정 판정의 필수 증적이 현재 Run에 없어 재검토가 필요합니다."

        relevant = _evidence_for_requirements(
            control.evidence_requirements,
            evidence,
        )
        matched_findings = _matching_confirmed_findings(
            db,
            run,
            control.finding_categories,
        )
        confirmed_finding = None
        confirmed_ids: list[str] = []
        for finding, ids in matched_findings:
            linked_rows = [evidence_by_id[item] for item in ids if item in evidence_by_id]
            if _requirements_satisfied(control.evidence_requirements, linked_rows):
                confirmed_finding = finding
                confirmed_ids = ids
                break

        deterministic_confirmed = False
        deterministic_ids: list[str] = []
        if definition.evaluator == "root_execution":
            deterministic_confirmed, deterministic_ids = _privileged_app_execution(evidence)
        elif definition.evaluator == "network_plaintext":
            deterministic_confirmed, deterministic_ids = _plaintext_transport(
                db, run, evidence
            )

        if confirmed_finding:
            control.status = "completed"
            control.result = "confirmed"
            control.summary = "동일 Run의 confirmed Finding과 필수 증적을 모두 확인했습니다."
            control.evidence_ids = list(dict.fromkeys(confirmed_ids))
            control.finding_ids = [confirmed_finding.id]
        elif deterministic_confirmed:
            control.status = "completed"
            control.result = "confirmed"
            control.summary = (
                "문서의 취약 판정 조건이 구조화된 단말·프로세스·화면 증적으로 재현됐습니다."
                if definition.evaluator == "root_execution"
                else "암호화되지 않은 HTTP 흐름을 원본 프록시 증적으로 확인했습니다."
            )
            control.evidence_ids = list(dict.fromkeys(deterministic_ids))
            finding = upsert_standard_finding(
                db,
                run=run,
                app=app,
                control=control,
                evidence_ids=control.evidence_ids,
                rationale=control.summary,
            )
            control.finding_ids = [finding.id]
        elif ai_recommendations.get(control.mastg_id):
            recommendations = ai_recommendations[control.mastg_id]
            control.status = "completed"
            control.result = "needs_review"
            control.summary = (
                "AI가 현재 Run 증적과 국내 기준의 관련성을 추천했습니다. "
                "AI 추론만으로는 취약점을 확정하지 않으며 문서의 판정 조건을 추가 재현해야 합니다."
            )
            control.evidence_ids = list(
                dict.fromkeys(
                    evidence_id
                    for item in recommendations
                    for evidence_id in item.get("evidence_ids") or []
                    if evidence_id in evidence_by_id
                )
            )
            control.finding_ids = list(
                dict.fromkeys(
                    str(item["finding_id"])
                    for item in recommendations
                    if item.get("finding_id") in run_finding_ids
                )
            )
        elif relevant:
            control.status = "completed"
            control.result = "needs_review"
            control.summary = (
                "관련 증적은 수집했지만 문서의 취약 판정 조건이 재현됐다고 확정할 수 없습니다."
            )
            control.evidence_ids = [item.id for item in relevant]
        elif definition.automation == "static":
            static_rows = [item for item in evidence if item.evidence_type == "static_analysis"]
            control.status = "completed" if static_rows else "not_configured"
            control.result = "needs_review" if static_rows else "unknown"
            control.summary = (
                "정적 분석 증적을 연결했습니다. 동적 재현 또는 전문가 검토 전에는 확정하지 않습니다."
                if static_rows
                else "정적 분석 증적을 수집하지 못했습니다."
            )
            control.evidence_ids = [item.id for item in static_rows]
        else:
            control.status = "manual_required"
            control.result = "not_tested"
            control.summary = (
                "진단 기준을 실행한 원본 증적이 없습니다. 승인된 수동 검증이 필요합니다."
            )

    db.flush()
    counts = Counter(item.result for item in controls)
    unresolved = sum(
        count
        for result, count in counts.items()
        if result not in TERMINAL_ASSESSMENT_RESULTS
    )
    return {
        "profile": profile,
        "total": len(controls),
        "counts": dict(counts),
        "confirmed": counts.get("confirmed", 0),
        "unresolved": unresolved,
        "controls": [
            {
                "control_id": item.mastg_id,
                "title": item.title,
                "status": item.status,
                "result": item.result,
                "evidence_ids": item.evidence_ids,
                "finding_ids": item.finding_ids,
                "summary": item.summary,
            }
            for item in controls
        ],
    }
