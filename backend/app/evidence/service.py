from __future__ import annotations

import hashlib
import json
import mimetypes
from pathlib import Path
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.app.core.config import AppSettings, get_settings
from backend.app.database.models import DiagnosticRun, Evidence


class EvidenceService:
    def __init__(self, settings: AppSettings | None = None):
        self.settings = settings or get_settings()

    def run_dir(self, run_id: str) -> Path:
        path = self.settings.evidence_dir / run_id
        path.mkdir(parents=True, exist_ok=True)
        return path

    def next_sequence(self, db: Session, run_id: str) -> int:
        current = db.scalar(
            select(func.max(Evidence.sequence)).where(Evidence.run_id == run_id)
        )
        return int(current or 0) + 1

    def add(
        self,
        db: Session,
        *,
        run_id: str,
        evidence_type: str,
        title: str,
        description: str = "",
        finding_id: str | None = None,
        file_path: Path | str | None = None,
        mime_type: str | None = None,
        command: str | None = None,
        inline_data: dict[str, Any] | list[Any] | None = None,
        synthetic: bool | None = None,
    ) -> Evidence:
        path = Path(file_path) if file_path else None
        sha256 = None
        if path and path.is_file():
            digest = hashlib.sha256()
            with path.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
            sha256 = digest.hexdigest()
            mime_type = mime_type or mimetypes.guess_type(path.name)[0]
        if synthetic is None:
            run = db.get(DiagnosticRun, run_id)
            synthetic = bool(run.synthetic) if run else False
        evidence = Evidence(
            run_id=run_id,
            finding_id=finding_id,
            evidence_type=evidence_type,
            title=title,
            description=description,
            sequence=self.next_sequence(db, run_id),
            file_path=str(path) if path else None,
            mime_type=mime_type,
            command=command,
            inline_data=inline_data,
            sha256=sha256,
            synthetic=synthetic,
        )
        db.add(evidence)
        db.commit()
        db.refresh(evidence)
        return evidence

    def add_json(
        self,
        db: Session,
        *,
        run_id: str,
        filename: str,
        title: str,
        data: Any,
        evidence_type: str,
        description: str = "",
        finding_id: str | None = None,
        command: str | None = None,
    ) -> Evidence:
        path = self.run_dir(run_id) / filename
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
        return self.add(
            db,
            run_id=run_id,
            finding_id=finding_id,
            evidence_type=evidence_type,
            title=title,
            description=description,
            file_path=path,
            mime_type="application/json",
            command=command,
            inline_data=data if _json_size(data) < 64_000 else None,
        )


def _json_size(value: Any) -> int:
    try:
        return len(json.dumps(value, ensure_ascii=False, default=str))
    except (TypeError, ValueError):
        return 999_999
