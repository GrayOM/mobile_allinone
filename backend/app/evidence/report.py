from __future__ import annotations

import base64
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.core.config import ROOT_DIR, AppSettings, get_settings
from backend.app.database.models import (
    DiagnosticRun,
    Evidence,
    Finding,
    FindingSource,
    Project,
)


class EvidenceReportRenderer:
    def __init__(self, settings: AppSettings | None = None):
        self.settings = settings or get_settings()
        self.environment = Environment(
            loader=FileSystemLoader(ROOT_DIR / "backend" / "app" / "evidence" / "templates"),
            autoescape=select_autoescape(["html", "xml"]),
        )

    def render(self, db: Session, finding_id: str) -> Path:
        finding = db.get(Finding, finding_id)
        if not finding:
            raise LookupError("발견항목을 찾을 수 없습니다.")
        project = db.get(Project, finding.project_id)
        run = db.get(DiagnosticRun, finding.run_id) if finding.run_id else None
        evidence = []
        if run:
            linked_ids: set[str] = set()
            sources = db.scalars(
                select(FindingSource).where(FindingSource.finding_id == finding.id)
            ).all()
            for source in sources:
                linked_ids.update(source.evidence_ids)
            evidence_filter = (
                Evidence.id.in_(linked_ids)
                if linked_ids
                else Evidence.finding_id == finding.id
            )
            rows = db.scalars(
                select(Evidence)
                .where(
                    Evidence.run_id == run.id,
                    evidence_filter,
                )
                .order_by(Evidence.sequence, Evidence.captured_at)
            ).all()
            evidence = [self._present(item) for item in rows]
        template = self.environment.get_template("finding.html")
        output = self.settings.reports_dir / f"{finding.id}.html"
        output.write_text(
            template.render(
                project=project,
                run=run,
                finding=finding,
                evidence=evidence,
            ),
            encoding="utf-8",
        )
        return output

    @staticmethod
    def _present(item: Evidence) -> dict[str, Any]:
        embedded_image = None
        filename = None
        if item.file_path:
            path = Path(item.file_path)
            filename = path.name
            if (
                path.is_file()
                and item.mime_type
                and item.mime_type.startswith("image/")
                and path.stat().st_size <= 5 * 1024 * 1024
            ):
                encoded = base64.b64encode(path.read_bytes()).decode("ascii")
                embedded_image = f"data:{item.mime_type};base64,{encoded}"
        return {
            "id": item.id,
            "type": item.evidence_type,
            "title": item.title,
            "description": item.description,
            "sequence": item.sequence,
            "captured_at": item.captured_at,
            "command": item.command,
            "inline_data": item.inline_data,
            "filename": filename,
            "mime_type": item.mime_type,
            "sha256": item.sha256,
            "embedded_image": embedded_image,
        }
