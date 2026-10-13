"""Project assessment scope: fixed catalog + exception inspections + exclusions.

The domestic profile chosen at project creation stays immutable. This module
adds two project-scoped, audited adjustments on top of it:

* custom (``CUS-MA-*``) inspection methods for checks that the selected
  advisory does not cover. They behave like catalog items: the same evaluator
  vocabulary, the same evidence requirement groups, ``needs_review`` until the
  required run evidence exists.
* exclusions of catalog items that are outside the agreed engagement scope.
  An excluded item is kept in every ledger as ``excluded`` /
  ``not_applicable`` with the recorded reason so the gap stays visible.

Only app baselines (``run_id IS NULL``) are synchronised. Run ledgers are
historical records and are never rewritten by a scope change.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Iterable

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend.app.catalog.korean_standards import (
    AUTOMATION_KINDS,
    CUSTOM_CONTROL_PREFIX,
    EVIDENCE_REQUIREMENTS_BY_EVALUATOR,
    EVALUATOR_KEYS,
    PLATFORM_SCOPES,
    PROFILE_SOURCES,
    RISK_LEVELS,
    SEVERITY_LEVELS,
    StandardControlDefinition,
    control_by_id,
    controls_for_profile,
    custom_control_definition,
    evaluate_definition_baseline,
    is_custom_control_id,
)
from backend.app.core.targets import normalize_platform
from backend.app.database.models import (
    AppArtifact,
    ControlTest,
    Project,
    ProjectAssessmentControl,
)

CUSTOM_KIND = "custom"
CUSTOM_DELETED_KIND = "custom_deleted"
EXCLUSION_KIND = "exclusion"
EXCLUDED_STATUS = "excluded"
EXCLUDED_RESULT = "not_applicable"

EVALUATOR_LABELS: dict[str, str] = {
    "static_review": "정적 분석 검토",
    "root_execution": "루팅·탈옥 단말 실행",
    "local_storage": "단말 저장소 스냅샷·변화",
    "memory_exposure": "메모리 노출 확인",
    "runtime_logs": "단말 로그·런타임 메시지",
    "forced_screen": "화면 강제 실행",
    "deep_link": "딥링크 호출",
    "network_plaintext": "평문 전송 캡처",
    "network_review": "네트워크 흐름 검토",
    "tls_configuration": "서버 TLS 구성 점검",
    "ui_review": "화면·UI 트리 검토",
    "dynamic_review": "동적 런타임 검토",
    "manual": "수동 원본 첨부",
}


class ScopeError(ValueError):
    """Raised for invalid scope requests; routers translate it to HTTP 4xx."""

    def __init__(self, message: str, status_code: int = 422):
        super().__init__(message)
        self.status_code = status_code


@dataclass(frozen=True, slots=True)
class ProjectScope:
    profile: str
    definitions: tuple[StandardControlDefinition, ...]
    custom: dict[str, ProjectAssessmentControl]
    exclusions: dict[str, ProjectAssessmentControl]

    def definition(self, control_id: str) -> StandardControlDefinition | None:
        return next(
            (item for item in self.definitions if item.control_id == control_id),
            None,
        )


def scope_options() -> dict[str, Any]:
    return {
        "custom_prefix": CUSTOM_CONTROL_PREFIX,
        "automation": list(AUTOMATION_KINDS),
        "risk": list(RISK_LEVELS),
        "severity": list(SEVERITY_LEVELS),
        "platform_scope": list(PLATFORM_SCOPES),
        "evaluators": [
            {
                "key": key,
                "label": EVALUATOR_LABELS.get(key, key),
                "evidence_requirements": [list(group) for group in groups],
            }
            for key, groups in EVIDENCE_REQUIREMENTS_BY_EVALUATOR.items()
        ],
    }


def _definition_from_row(row: ProjectAssessmentControl) -> StandardControlDefinition:
    return custom_control_definition(
        row.profile,
        control_id=row.control_id,
        group=row.group,
        title=row.title,
        criteria=row.criteria or [],
        automation=row.automation,
        evaluator=row.evaluator,
        risk=row.risk,
        finding_categories=row.finding_categories or [],
        severity=row.severity,
    )


def _definition_hash(definition: StandardControlDefinition, row: ProjectAssessmentControl) -> str:
    payload = {
        **definition.to_dict(),
        "platform_scope": row.platform_scope,
        "procedure": list(row.procedure or []),
        "reference": row.reference,
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")
    ).hexdigest()


def _scope_rows(db: Session, project: Project) -> list[ProjectAssessmentControl]:
    return list(
        db.scalars(
            select(ProjectAssessmentControl)
            .where(
                ProjectAssessmentControl.project_id == project.id,
                ProjectAssessmentControl.profile == project.assessment_profile,
            )
            .order_by(ProjectAssessmentControl.control_id)
        ).all()
    )


def load_project_scope(db: Session, project: Project) -> ProjectScope:
    rows = _scope_rows(db, project)
    custom = {row.control_id: row for row in rows if row.kind == CUSTOM_KIND}
    exclusions = {
        row.control_id: row
        for row in rows
        if row.kind == EXCLUSION_KIND and row.enabled
    }
    definitions = [*controls_for_profile(project.assessment_profile)]
    for row in custom.values():
        if row.enabled:
            definitions.append(_definition_from_row(row))
    return ProjectScope(
        profile=project.assessment_profile,
        definitions=tuple(definitions),
        custom=custom,
        exclusions=exclusions,
    )


def resolve_definition(
    db: Session,
    *,
    project_id: str,
    standard: str,
    control_id: str,
) -> StandardControlDefinition | None:
    """Catalog lookup that also knows project-defined exception controls.

    Disabled custom controls still resolve so historical Run ledgers keep their
    definition after the control is turned off for new runs.
    """
    if standard not in PROFILE_SOURCES:
        return None
    if not is_custom_control_id(control_id):
        return control_by_id(standard, control_id)
    row = db.scalar(
        select(ProjectAssessmentControl).where(
            ProjectAssessmentControl.project_id == project_id,
            ProjectAssessmentControl.kind == CUSTOM_KIND,
            ProjectAssessmentControl.profile == standard,
            ProjectAssessmentControl.control_id == control_id,
        )
    )
    return _definition_from_row(row) if row else None


def custom_row_for(
    db: Session, *, project_id: str, control_id: str
) -> ProjectAssessmentControl | None:
    if not is_custom_control_id(control_id):
        return None
    return db.scalar(
        select(ProjectAssessmentControl).where(
            ProjectAssessmentControl.project_id == project_id,
            ProjectAssessmentControl.kind == CUSTOM_KIND,
            ProjectAssessmentControl.control_id == control_id,
        )
    )


def _platform_matches(scope: str, platform: str) -> bool:
    if scope in {"", "any"}:
        return True
    try:
        return normalize_platform(platform) == scope
    except ValueError:
        return False


def project_definitions_for_platform(
    db: Session,
    project: Project,
    platform: str | None,
    *,
    scope: ProjectScope | None = None,
) -> list[StandardControlDefinition]:
    scope = scope or load_project_scope(db, project)
    if platform is None:
        return list(scope.definitions)
    return [
        item
        for item in scope.definitions
        if not is_custom_control_id(item.control_id)
        or _platform_matches(scope.custom[item.control_id].platform_scope, platform)
    ]


def _exclusion_summary(row: ProjectAssessmentControl) -> str:
    return f"프로젝트 범위 제외 · {row.recorded_by}: {row.reason}"


def _definition_fields(definition: StandardControlDefinition) -> dict[str, Any]:
    return {
        "title": definition.title,
        "masvs_id": definition.group,
        "automation": definition.automation,
        "criteria": list(definition.criteria),
        "evidence_requirements": [list(group) for group in definition.evidence_requirements],
        "finding_categories": list(definition.finding_categories),
        "risk": definition.risk,
    }


def definition_drifted(control: ControlTest, definition: StandardControlDefinition) -> bool:
    """True when a ledger row no longer carries the current catalog policy."""
    current = _definition_fields(definition)
    return any(getattr(control, key) != value for key, value in current.items())


def align_definition_fields(control: ControlTest, definition: StandardControlDefinition) -> None:
    for key, value in _definition_fields(definition).items():
        setattr(control, key, value)


def _apply_baseline_values(
    control: ControlTest,
    definition: StandardControlDefinition,
    platform: str,
) -> None:
    values = evaluate_definition_baseline(definition, platform)
    control.title = values["title"]
    control.masvs_id = values["group"]
    control.automation = values["automation"]
    control.status = values["status"]
    control.result = values["result"]
    control.summary = values["summary"]
    control.criteria = values["criteria"]
    control.evidence_requirements = values["evidence_requirements"]
    control.finding_categories = values["finding_categories"]
    control.risk = values["risk"]


def sync_app_baseline(db: Session, *, project: Project, artifact: AppArtifact) -> dict[str, int]:
    """Bring one app's baseline ledger in line with the project scope."""
    scope = load_project_scope(db, project)
    rows = db.scalars(
        select(ControlTest).where(
            ControlTest.app_id == artifact.id,
            ControlTest.run_id.is_(None),
            ControlTest.standard == project.assessment_profile,
        )
    ).all()
    existing = {row.mastg_id: row for row in rows}
    wanted = {
        item.control_id: item
        for item in project_definitions_for_platform(
            db, project, artifact.platform, scope=scope
        )
    }
    added = removed = excluded = restored = realigned = 0

    for control_id, row in existing.items():
        if control_id not in wanted and is_custom_control_id(control_id):
            db.delete(row)
            removed += 1

    for control_id, definition in wanted.items():
        row = existing.get(control_id)
        if row is None:
            row = ControlTest(
                project_id=project.id,
                app_id=artifact.id,
                run_id=None,
                mastg_id=control_id,
                masvs_id=definition.group,
                platform=artifact.platform,
                title=definition.title,
                automation=definition.automation,
                status="manual_required",
                result="not_tested",
                summary="",
                replacement_ids=[],
                source_url="",
                evidence_ids=[],
                synthetic=artifact.synthetic,
                standard=project.assessment_profile,
                criteria=[],
                evidence_requirements=[],
                finding_categories=[],
                finding_ids=[],
                risk=definition.risk,
            )
            _apply_baseline_values(row, definition, artifact.platform)
            db.add(row)
            added += 1
        elif definition_drifted(row, definition):
            # The catalog policy changed (for example EFI-MA-41~44 moved to the
            # TLS evaluator). Baseline rows hold no verdicts, so reset them.
            _apply_baseline_values(row, definition, artifact.platform)
            realigned += 1
        exclusion = scope.exclusions.get(control_id)
        if exclusion is not None:
            if row.status != EXCLUDED_STATUS or row.summary != _exclusion_summary(exclusion):
                row.status = EXCLUDED_STATUS
                row.result = EXCLUDED_RESULT
                row.summary = _exclusion_summary(exclusion)
                excluded += 1
        elif row.status == EXCLUDED_STATUS:
            _apply_baseline_values(row, definition, artifact.platform)
            restored += 1
    db.flush()
    return {
        "added": added,
        "removed": removed,
        "excluded": excluded,
        "restored": restored,
        "realigned": realigned,
    }


def sync_project_baselines(db: Session, project: Project) -> dict[str, int]:
    totals = {"apps": 0, "added": 0, "removed": 0, "excluded": 0, "restored": 0, "realigned": 0}
    apps = db.scalars(
        select(AppArtifact).where(AppArtifact.project_id == project.id)
    ).all()
    for artifact in apps:
        changes = sync_app_baseline(db, project=project, artifact=artifact)
        totals["apps"] += 1
        for key, value in changes.items():
            totals[key] += value
    return totals


def _clean_lines(values: Iterable[Any], *, limit: int, item_limit: int) -> list[str]:
    lines: list[str] = []
    for value in values or []:
        text = " ".join(str(value).split())
        if text:
            lines.append(text[:item_limit])
    if len(lines) > limit:
        raise ScopeError(f"항목은 최대 {limit}개까지 입력할 수 있습니다.")
    return lines


def _insert_unique(db: Session, row: ProjectAssessmentControl, message: str) -> None:
    try:
        with db.begin_nested():
            db.add(row)
            db.flush()
    except IntegrityError as exc:
        raise ScopeError(message, 409) from exc


def _next_custom_id(db: Session, project: Project) -> str:
    # Deleted IDs stay reserved as tombstones so an ID never points at two
    # different definitions (AI mappings and plans reference IDs).
    existing = db.scalars(
        select(ProjectAssessmentControl.control_id).where(
            ProjectAssessmentControl.project_id == project.id,
            ProjectAssessmentControl.kind.in_((CUSTOM_KIND, CUSTOM_DELETED_KIND)),
        )
    ).all()
    numbers = [
        int(item.rsplit("-", 1)[-1])
        for item in existing
        if item.rsplit("-", 1)[-1].isdigit()
    ]
    return f"{CUSTOM_CONTROL_PREFIX}-{(max(numbers) + 1) if numbers else 1:02d}"


def create_custom_control(
    db: Session,
    project: Project,
    *,
    title: str,
    group: str,
    criteria: Iterable[str],
    procedure: Iterable[str],
    automation: str,
    evaluator: str,
    risk: str,
    severity: str,
    platform_scope: str,
    finding_categories: Iterable[str],
    reference: str,
    reason: str,
    recorded_by: str,
) -> ProjectAssessmentControl:
    title = " ".join(str(title or "").split())
    reason = str(reason or "").strip()
    recorded_by = " ".join(str(recorded_by or "").split())
    if not 2 <= len(title) <= 200:
        raise ScopeError("검사 이름은 2~200자로 입력하세요.")
    if not reason:
        raise ScopeError("기준 외 검사를 추가하는 사유가 필요합니다.")
    if not recorded_by:
        raise ScopeError("등록자가 필요합니다.")
    if platform_scope not in PLATFORM_SCOPES:
        raise ScopeError("지원하지 않는 플랫폼 범위입니다.")
    if evaluator not in EVALUATOR_KEYS:
        raise ScopeError("지원하지 않는 판정 방식입니다.")
    if automation not in AUTOMATION_KINDS:
        raise ScopeError("지원하지 않는 실행 방식입니다.")
    if automation == "static" and evaluator != "static_review":
        raise ScopeError("정적 실행 방식은 정적 분석 검토 판정과 함께 사용해야 합니다.")
    criteria_lines = _clean_lines(criteria, limit=20, item_limit=600)
    procedure_lines = _clean_lines(procedure, limit=30, item_limit=600)
    categories = [
        item.lower().replace(" ", "_")
        for item in _clean_lines(finding_categories, limit=10, item_limit=60)
    ]
    row = ProjectAssessmentControl(
        project_id=project.id,
        kind=CUSTOM_KIND,
        profile=project.assessment_profile,
        control_id=_next_custom_id(db, project),
        platform_scope=platform_scope,
        group=" ".join(str(group or "").split())[:100] or "사용자 정의 검사",
        title=title,
        criteria=criteria_lines,
        automation=automation,
        evaluator=evaluator,
        risk=risk,
        severity=severity,
        finding_categories=categories,
        procedure=procedure_lines,
        reference=str(reference or "").strip()[:2000],
        reason=reason[:2000],
        recorded_by=recorded_by[:100],
        enabled=True,
    )
    try:
        definition = _definition_from_row(row)
    except ValueError as exc:
        raise ScopeError(str(exc)) from exc
    row.finding_categories = list(definition.finding_categories)
    row.definition_sha256 = _definition_hash(definition, row)
    _insert_unique(db, row, "동시에 같은 검사 ID가 만들어졌습니다. 다시 시도하세요.")
    sync_project_baselines(db, project)
    return row


def custom_control_usage(db: Session, project: Project, control_id: str) -> int:
    return len(
        db.scalars(
            select(ControlTest.id).where(
                ControlTest.project_id == project.id,
                ControlTest.run_id.is_not(None),
                ControlTest.mastg_id == control_id,
            )
        ).all()
    )


def set_custom_control_enabled(
    db: Session, project: Project, control_id: str, *, enabled: bool
) -> ProjectAssessmentControl:
    row = custom_row_for(db, project_id=project.id, control_id=control_id)
    if row is None:
        raise ScopeError("사용자 정의 검사를 찾을 수 없습니다.", 404)
    row.enabled = enabled
    db.flush()
    sync_project_baselines(db, project)
    return row


def delete_custom_control(db: Session, project: Project, control_id: str) -> None:
    row = custom_row_for(db, project_id=project.id, control_id=control_id)
    if row is None:
        raise ScopeError("사용자 정의 검사를 찾을 수 없습니다.", 404)
    if custom_control_usage(db, project, control_id):
        raise ScopeError(
            "Run 원장에 사용된 사용자 정의 검사는 삭제할 수 없습니다. 비활성화하면 새 Run에서만 제외됩니다.",
            409,
        )
    row.kind = CUSTOM_DELETED_KIND
    row.enabled = False
    db.flush()
    sync_project_baselines(db, project)


def set_exclusion(
    db: Session,
    project: Project,
    control_id: str,
    *,
    reason: str,
    recorded_by: str,
) -> ProjectAssessmentControl:
    if is_custom_control_id(control_id):
        raise ScopeError("사용자 정의 검사는 제외 대신 비활성화하세요.")
    definition = control_by_id(project.assessment_profile, control_id)
    if definition is None:
        raise ScopeError("현재 프로젝트 기준에 없는 항목입니다.", 404)
    reason = str(reason or "").strip()
    recorded_by = " ".join(str(recorded_by or "").split())
    if len(reason) < 5:
        raise ScopeError("범위 제외 사유를 5자 이상 입력하세요.")
    if not recorded_by:
        raise ScopeError("기록자가 필요합니다.")
    row = db.scalar(
        select(ProjectAssessmentControl).where(
            ProjectAssessmentControl.project_id == project.id,
            ProjectAssessmentControl.kind == EXCLUSION_KIND,
            ProjectAssessmentControl.control_id == control_id,
        )
    )
    if row is None:
        row = ProjectAssessmentControl(
            project_id=project.id,
            kind=EXCLUSION_KIND,
            profile=project.assessment_profile,
            control_id=control_id,
            title=definition.title,
            group=definition.group,
            recorded_by=recorded_by[:100],
            reason=reason[:2000],
        )
        _insert_unique(db, row, "동시에 같은 항목의 범위 제외가 기록되었습니다. 다시 시도하세요.")
    row.reason = reason[:2000]
    row.recorded_by = recorded_by[:100]
    row.enabled = True
    db.flush()
    sync_project_baselines(db, project)
    return row


def clear_exclusion(db: Session, project: Project, control_id: str) -> None:
    row = db.scalar(
        select(ProjectAssessmentControl).where(
            ProjectAssessmentControl.project_id == project.id,
            ProjectAssessmentControl.kind == EXCLUSION_KIND,
            ProjectAssessmentControl.control_id == control_id,
        )
    )
    if row is None:
        raise ScopeError("범위 제외 기록이 없습니다.", 404)
    db.delete(row)
    db.flush()
    sync_project_baselines(db, project)


def scope_row_to_dict(row: ProjectAssessmentControl, *, usage: int | None = None) -> dict[str, Any]:
    value: dict[str, Any] = {
        "id": row.id,
        "kind": row.kind,
        "profile": row.profile,
        "control_id": row.control_id,
        "title": row.title,
        "group": row.group,
        "reason": row.reason,
        "recorded_by": row.recorded_by,
        "enabled": row.enabled,
        "created_at": row.created_at,
        "updated_at": row.updated_at,
    }
    if row.kind == CUSTOM_KIND:
        requirements = EVIDENCE_REQUIREMENTS_BY_EVALUATOR.get(
            row.evaluator, (("manual_assessment_attachment",),)
        )
        value.update(
            {
                "platform_scope": row.platform_scope,
                "criteria": list(row.criteria or []),
                "procedure": list(row.procedure or []),
                "automation": row.automation,
                "evaluator": row.evaluator,
                "evaluator_label": EVALUATOR_LABELS.get(row.evaluator, row.evaluator),
                "evidence_requirements": [list(group) for group in requirements],
                "risk": row.risk,
                "severity": row.severity,
                "finding_categories": list(row.finding_categories or []),
                "reference": row.reference,
                "definition_sha256": row.definition_sha256,
                "run_usage": usage or 0,
            }
        )
    return value


def project_scope_payload(db: Session, project: Project) -> dict[str, Any]:
    scope = load_project_scope(db, project)
    catalog = controls_for_profile(project.assessment_profile)
    custom = [
        scope_row_to_dict(row, usage=custom_control_usage(db, project, row.control_id))
        for row in scope.custom.values()
    ]
    return {
        "project_id": project.id,
        "profile": project.assessment_profile,
        "profile_source": PROFILE_SOURCES[project.assessment_profile],
        "catalog_total": len(catalog),
        "excluded_total": len(scope.exclusions),
        "custom_total": len(custom),
        "custom_enabled": sum(1 for row in scope.custom.values() if row.enabled),
        "effective_total": len(catalog) - len(scope.exclusions)
        + sum(1 for row in scope.custom.values() if row.enabled),
        "catalog": [
            {
                "control_id": item.control_id,
                "group": item.group,
                "title": item.title,
                "evaluator": item.evaluator,
                "automation": item.automation,
                "risk": item.risk,
                "excluded": item.control_id in scope.exclusions,
            }
            for item in catalog
        ],
        "exclusions": [scope_row_to_dict(row) for row in scope.exclusions.values()],
        "custom": custom,
        "options": scope_options(),
    }
