from __future__ import annotations

from datetime import datetime, timezone

from docx import Document

from backend.app.database.models import Evidence
from backend.app.evidence.docx_report import (
    VulnerabilityDocxReportRenderer,
    curate_customer_evidence,
)


def _evidence(
    evidence_id: str,
    evidence_type: str,
    *,
    sha256: str | None = None,
    mime_type: str | None = None,
    inline_data: dict | None = None,
) -> Evidence:
    return Evidence(
        id=evidence_id,
        run_id="run-1",
        evidence_type=evidence_type,
        title=evidence_id,
        description="reader-facing description",
        sha256=sha256,
        mime_type=mime_type,
        inline_data=inline_data,
        captured_at=datetime(2026, 10, 16, tzinfo=timezone.utc),
        synthetic=False,
    )


def test_customer_report_evidence_removes_wrappers_and_duplicate_images():
    first = _evidence("screen-1", "screenshot", sha256="a" * 64, mime_type="image/png")
    duplicate = _evidence("screen-2", "screenshot", sha256="a" * 64, mime_type="image/png")
    log = _evidence("log-1", "device_log", sha256="b" * 64)
    wrapper = _evidence("checkpoint-1", "interaction_checkpoint", sha256="c" * 64)
    attestation = _evidence("attestation-1", "assessment_attestation")

    selected = curate_customer_evidence(
        [first, duplicate, log, wrapper, attestation, log]
    )

    assert [item.id for item in selected] == ["screen-1", "log-1"]


def test_docx_evidence_uses_compact_facts_instead_of_raw_dump():
    evidence = _evidence(
        "process-proof",
        "command_log",
        sha256="d" * 64,
        inline_data={
            "status": "available",
            "message": "대상 앱 프로세스가 실행 중임을 확인했습니다.",
            "output": "RAW_NOISE_" * 1000,
        },
    )
    evidence.command = "tool --verbose --raw"
    document = Document()

    VulnerabilityDocxReportRenderer()._evidence(document, 1, evidence)

    text = "\n".join(paragraph.text for paragraph in document.paragraphs)
    assert "대상 앱 프로세스가 실행 중임을 확인했습니다." in text
    assert "RAW_NOISE" not in text
    assert "tool --verbose --raw" not in text
    assert "SHA-256" in text
