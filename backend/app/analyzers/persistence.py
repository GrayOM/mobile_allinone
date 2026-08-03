from __future__ import annotations

from datetime import datetime

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from backend.app.database.models import (
    AppArtifact,
    ControlTest,
    Finding,
    FindingSource,
    Project,
    RawFinding,
    ToolRun,
)

from .correlation import correlate_findings
from .static import StaticAnalysisResult


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def _severity_rank(value: str) -> int:
    return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(value, 0)


def replace_analysis_records(
    db: Session,
    *,
    project: Project,
    artifact: AppArtifact,
    result: StaticAnalysisResult,
) -> list[Finding]:
    old_raw_ids = list(
        db.scalars(select(RawFinding.id).where(RawFinding.app_id == artifact.id))
    )
    old_finding_ids: set[str] = set()
    if old_raw_ids:
        old_finding_ids.update(
            db.scalars(
                select(FindingSource.finding_id).where(
                    FindingSource.raw_finding_id.in_(old_raw_ids)
                )
            )
        )
        db.execute(
            delete(FindingSource).where(FindingSource.raw_finding_id.in_(old_raw_ids))
        )
    db.execute(delete(RawFinding).where(RawFinding.app_id == artifact.id))
    db.execute(delete(ToolRun).where(ToolRun.app_id == artifact.id))
    db.execute(
        delete(ControlTest).where(
            ControlTest.app_id == artifact.id,
            ControlTest.run_id.is_(None),
        )
    )
    for finding_id in old_finding_ids:
        finding = db.get(Finding, finding_id)
        if finding and finding.run_id is None and not finding.sources:
            db.delete(finding)
    db.flush()

    tool_rows: dict[str, ToolRun] = {}
    for item in result.tool_runs:
        row = ToolRun(
            app_id=artifact.id,
            run_id=None,
            tool_name=str(item.get("tool") or "unknown"),
            tool_version=item.get("version"),
            status=str(item.get("status") or "failed"),
            command=[str(value) for value in item.get("command") or []],
            raw_output_path=item.get("raw_output_path"),
            raw_sha256=item.get("raw_sha256"),
            error=item.get("error"),
            metadata_json={
                **(item.get("metadata") or {}),
                "finding_count": int(item.get("finding_count") or 0),
            },
            started_at=_parse_time(item.get("started_at")) or datetime.now().astimezone(),
            finished_at=_parse_time(item.get("finished_at")),
        )
        db.add(row)
        db.flush()
        tool_rows[row.tool_name] = row

    raw_by_fingerprint: dict[str, RawFinding] = {}
    for item in result.findings:
        row = RawFinding(
            app_id=artifact.id,
            tool_run_id=(
                tool_rows[item.source_tool].id
                if item.source_tool in tool_rows
                else None
            ),
            source_tool=item.source_tool,
            rule_id=item.rule_id,
            fingerprint=item.fingerprint,
            title=item.title,
            category=item.category,
            severity=item.severity,
            location=item.location,
            confidence=item.confidence,
            references=item.references,
            raw_payload=item.raw,
        )
        db.add(row)
        db.flush()
        raw_by_fingerprint[item.fingerprint] = row

    findings: list[Finding] = []
    for group in correlate_findings(result.findings):
        primary = group.primary
        strongest = max(group.members, key=lambda item: _severity_rank(item.severity))
        source_names = sorted({item.source_tool for item in group.members})
        finding = Finding(
            project_id=project.id,
            run_id=None,
            title=primary.title,
            category=primary.category,
            platform=result.platform,
            severity=strongest.severity,
            location=primary.location,
            verdict=primary.verdict,
            confidence=max(item.confidence for item in group.members),
            rationale=primary.rationale,
            reproduction=[],
            false_positive_risk=(
                "자동 분석 도구의 정적 신호입니다. 서로 다른 출처가 일치할수록 "
                "신뢰도가 높지만 런타임 재현이 필요합니다."
            ),
            additional_checks=[
                "관련 코드 위치를 확인하세요.",
                "MASTG 테스트 상태와 동적 증적을 연결하세요.",
            ],
            source="static:" + "+".join(source_names),
        )
        db.add(finding)
        db.flush()
        for member in group.members:
            raw = raw_by_fingerprint[member.fingerprint]
            db.add(
                FindingSource(
                    finding_id=finding.id,
                    raw_finding_id=raw.id,
                    source_tool=member.source_tool,
                    source_rule_id=member.rule_id,
                    fingerprint=member.fingerprint,
                    evidence_ids=[],
                )
            )
        findings.append(finding)

    for item in result.controls:
        db.add(
            ControlTest(
                project_id=project.id,
                app_id=artifact.id,
                run_id=None,
                mastg_id=item["mastg_id"],
                masvs_id=item["masvs_id"],
                platform=item["platform"],
                title=item["title"],
                automation=item["automation"],
                status=item["status"],
                result=item["result"],
                summary=item["summary"],
                replacement_ids=item.get("replacement_ids", []),
                source_url=item.get("source_url", ""),
                evidence_ids=[],
            )
        )
    db.flush()
    return findings
