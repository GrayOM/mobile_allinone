from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from docx import Document
from docx.enum.table import WD_CELL_VERTICAL_ALIGNMENT, WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Cm, Pt, RGBColor
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.ai.masking import mask_context
from backend.app.catalog import control_by_id, execution_plan
from backend.app.core.config import AppSettings, get_settings
from backend.app.database.models import (
    AppArtifact,
    ControlTest,
    DiagnosticRun,
    Evidence,
    Finding,
    Project,
)


PROFILE_NAMES = {
    "critical_infrastructure": "주요정보통신기반시설",
    "electronic_financial": "전자금융기반시설",
}
EXCLUDED_EVIDENCE_TYPES = {
    "assessment_ledger",
    "assessment_ledger_amendment",
    "vulnerability_assessment",
}


class VulnerabilityDocxReportRenderer:
    def __init__(self, settings: AppSettings | None = None):
        self.settings = settings or get_settings()

    def render(self, db: Session, run_id: str) -> Path:
        run = db.get(DiagnosticRun, run_id)
        if not run:
            raise LookupError("진단 실행을 찾을 수 없습니다.")
        project = db.get(Project, run.project_id)
        app = db.get(AppArtifact, run.app_id) if run.app_id else None
        if not project or not app:
            raise LookupError("보고서에 필요한 프로젝트 또는 앱을 찾을 수 없습니다.")
        profile = str(run.options.get("assessment_profile") or project.assessment_profile)
        controls = db.scalars(
            select(ControlTest)
            .where(
                ControlTest.run_id == run.id,
                ControlTest.standard == profile,
                ControlTest.result == "confirmed",
            )
            .order_by(ControlTest.mastg_id)
        ).all()
        if not controls:
            raise ValueError("취약 확정 항목이 없어 DOCX 보고서를 생성하지 않았습니다.")

        finding_ids = {
            finding_id for control in controls for finding_id in control.finding_ids
        }
        findings = {
            item.id: item
            for item in db.scalars(
                select(Finding).where(
                    Finding.id.in_(finding_ids or {"-"}),
                    Finding.run_id == run.id,
                    Finding.verdict == "confirmed",
                )
            ).all()
        }
        evidence_ids = {
            evidence_id for control in controls for evidence_id in control.evidence_ids
        }
        evidence = {
            item.id: item
            for item in db.scalars(
                select(Evidence).where(
                    Evidence.id.in_(evidence_ids or {"-"}),
                    Evidence.run_id == run.id,
                )
            ).all()
            if item.evidence_type not in EXCLUDED_EVIDENCE_TYPES
        }

        document = Document()
        self._configure(document)
        self._cover(document, project, app, run, profile, len(controls))
        self._summary(document, controls, findings)
        document.add_page_break()
        for index, control in enumerate(controls, start=1):
            self._control_section(
                document,
                index=index,
                control=control,
                findings=[findings[item] for item in control.finding_ids if item in findings],
                evidence=[evidence[item] for item in control.evidence_ids if item in evidence],
            )
            if index != len(controls):
                document.add_page_break()

        output = self.settings.reports_dir / f"{run.id}-{profile}-vulnerabilities.docx"
        temporary = output.with_name(f".{output.name}.{uuid.uuid4()}.tmp.docx")
        try:
            document.save(temporary)
            os.replace(temporary, output)
        finally:
            temporary.unlink(missing_ok=True)
        return output

    @staticmethod
    def _configure(document: Document) -> None:
        section = document.sections[0]
        section.top_margin = Cm(1.8)
        section.bottom_margin = Cm(1.7)
        section.left_margin = Cm(1.8)
        section.right_margin = Cm(1.8)
        normal = document.styles["Normal"]
        normal.font.name = "Malgun Gothic"
        normal._element.rPr.rFonts.set(qn("w:eastAsia"), "맑은 고딕")
        normal.font.size = Pt(9)
        for name, size, color in (
            ("Title", 27, "17333A"),
            ("Heading 1", 18, "17333A"),
            ("Heading 2", 12, "B65722"),
            ("Heading 3", 10, "286A6B"),
        ):
            style = document.styles[name]
            style.font.name = "Malgun Gothic"
            style._element.rPr.rFonts.set(qn("w:eastAsia"), "맑은 고딕")
            style.font.size = Pt(size)
            style.font.color.rgb = RGBColor.from_string(color)

    def _cover(
        self,
        document: Document,
        project: Project,
        app: AppArtifact,
        run: DiagnosticRun,
        profile: str,
        count: int,
    ) -> None:
        marker = document.add_paragraph("MOBILE SECURITY WORKBENCH / CONFIRMED ONLY")
        marker.style = document.styles["Subtitle"]
        marker.runs[0].font.color.rgb = RGBColor(40, 106, 107)
        title = document.add_heading("모바일 앱 취약점 진단 결과보고서", 0)
        title.alignment = WD_ALIGN_PARAGRAPH.LEFT
        subtitle = document.add_paragraph(
            f"{PROFILE_NAMES.get(profile, profile)} · 취약 확정 항목 전용"
        )
        subtitle.runs[0].bold = True
        subtitle.runs[0].font.size = Pt(14)
        subtitle.runs[0].font.color.rgb = RGBColor(182, 87, 34)
        document.add_paragraph("\n")
        table = document.add_table(rows=0, cols=2)
        table.alignment = WD_TABLE_ALIGNMENT.LEFT
        table.style = "Table Grid"
        for label, value in (
            ("프로젝트", project.name),
            ("대상 앱", app.app_name or app.original_name),
            ("Package / Bundle", app.package_name or "미확인"),
            ("앱 SHA-256", app.sha256),
            ("진단 Run", run.id),
            ("취약 확정", f"{count}건"),
            ("생성 시각", datetime.now(timezone.utc).isoformat()),
        ):
            cells = table.add_row().cells
            cells[0].text = label
            cells[1].text = value
            cells[0].vertical_alignment = WD_CELL_VERTICAL_ALIGNMENT.CENTER
            cells[0].paragraphs[0].runs[0].bold = True
        document.add_paragraph("\n이 문서는 취약 판정이 확정된 항목과 연결 증적만 포함합니다. 양호·해당없음·미확정 항목은 수록하지 않습니다.")
        if run.synthetic:
            warning = document.add_paragraph("SYNTHETIC MOCK — 실제 진단 결과로 사용할 수 없습니다.")
            warning.runs[0].bold = True
            warning.runs[0].font.color.rgb = RGBColor(182, 87, 34)

    @staticmethod
    def _summary(
        document: Document,
        controls: list[ControlTest],
        findings: dict[str, Finding],
    ) -> None:
        document.add_heading("취약점 요약", level=1)
        table = document.add_table(rows=1, cols=4)
        table.style = "Table Grid"
        table.alignment = WD_TABLE_ALIGNMENT.CENTER
        headers = ("기준 ID", "취약점", "위험도", "증적")
        for cell, value in zip(table.rows[0].cells, headers):
            cell.text = value
            cell.paragraphs[0].runs[0].bold = True
            _shade_cell(cell, "17333A")
            cell.paragraphs[0].runs[0].font.color.rgb = RGBColor(255, 255, 255)
        for control in controls:
            row = table.add_row().cells
            severities = [
                findings[item].severity for item in control.finding_ids if item in findings
            ]
            row[0].text = control.mastg_id
            row[1].text = control.title
            row[2].text = (severities[0] if severities else control.risk).upper()
            row[3].text = f"{len(control.evidence_ids)}건"

    def _control_section(
        self,
        document: Document,
        *,
        index: int,
        control: ControlTest,
        findings: list[Finding],
        evidence: list[Evidence],
    ) -> None:
        document.add_paragraph(f"VULNERABILITY {index:02d}", style="Subtitle")
        document.add_heading(f"{control.mastg_id}  {control.title}", level=1)
        definition = control_by_id(control.standard, control.mastg_id)
        plan = execution_plan(definition) if definition else {}
        facts = document.add_table(rows=2, cols=4)
        facts.style = "Table Grid"
        facts.cell(0, 0).text = "판정"
        facts.cell(0, 1).text = "CONFIRMED"
        facts.cell(0, 2).text = "위험도"
        facts.cell(0, 3).text = (findings[0].severity if findings else control.risk).upper()
        facts.cell(1, 0).text = "실행 방식"
        facts.cell(1, 1).text = control.automation.upper()
        facts.cell(1, 2).text = "증적 수"
        facts.cell(1, 3).text = str(len(evidence))
        for row in facts.rows:
            for cell_index in (0, 2):
                row.cells[cell_index].paragraphs[0].runs[0].bold = True
                _shade_cell(row.cells[cell_index], "DCE8E6")

        document.add_heading("판정 근거", level=2)
        document.add_paragraph(control.summary or "같은 Run의 재현 증적과 필수 증적 유형을 확인했습니다.")
        for finding in findings:
            if finding.rationale and finding.rationale != control.summary:
                document.add_paragraph(finding.rationale)

        document.add_heading("취약 판정 기준", level=2)
        for criterion in control.criteria:
            document.add_paragraph(criterion, style="List Bullet")

        document.add_heading("재현 절차", level=2)
        reproduction = list(
            dict.fromkeys(
                item for finding in findings for item in finding.reproduction if item
            )
        ) or list(control.criteria)
        for step in reproduction:
            document.add_paragraph(step, style="List Number")

        document.add_heading("취약 증적", level=2)
        if not evidence:
            document.add_paragraph("연결 증적 메타데이터를 찾지 못했습니다.")
        for position, item in enumerate(evidence, start=1):
            self._evidence(document, position, item)

        document.add_heading("조치 권고", level=2)
        document.add_paragraph(
            str(plan.get("remediation") or "문서의 보안 권고안에 따라 취약 조건을 제거하고 동일 절차로 재점검합니다.")
        )

    def _evidence(self, document: Document, position: int, item: Evidence) -> None:
        document.add_heading(f"E-{position:02d}  {item.title}", level=3)
        metadata = document.add_paragraph()
        metadata.add_run(f"TYPE {item.evidence_type}  ·  ID {item.id}\n").bold = True
        metadata.add_run(
            f"CAPTURED {item.captured_at.isoformat()}  ·  SHA-256 {item.sha256 or 'N/A'}"
        )
        if item.description:
            document.add_paragraph(item.description)
        if item.command:
            command = document.add_paragraph(item.command)
            command.runs[0].font.name = "Cascadia Mono"
            command.runs[0].font.size = Pt(7)
        if item.inline_data is not None:
            masked, _ = mask_context({"evidence": item.inline_data})
            excerpt = masked[:2500] + ("…" if len(masked) > 2500 else "")
            block = document.add_paragraph(excerpt)
            block.runs[0].font.name = "Cascadia Mono"
            block.runs[0].font.size = Pt(7)
        image = self._safe_image_path(item)
        if image:
            document.add_picture(str(image), width=Cm(15.2))
            document.paragraphs[-1].alignment = WD_ALIGN_PARAGRAPH.CENTER

    def _safe_image_path(self, item: Evidence) -> Path | None:
        if not item.file_path or not (item.mime_type or "").startswith("image/"):
            return None
        path = Path(item.file_path).resolve()
        root = self.settings.data_dir.resolve()
        if root not in path.parents or not path.is_file() or path.stat().st_size > 10 * 1024 * 1024:
            return None
        return path


def _shade_cell(cell: Any, fill: str) -> None:
    properties = cell._tc.get_or_add_tcPr()
    shading = OxmlElement("w:shd")
    shading.set(qn("w:fill"), fill)
    properties.append(shading)
