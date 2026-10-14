"""Build the local advisory guidance JSON from the customer-provided DOCX files.

The repository is public and the project rule is not to copy the advisory text,
so the extracted guidance is generated locally and never committed:

    python scripts/extract_korean_guidance.py --cii "<주요정보통신기반시설>.docx" \
        --efi "<전자금융기반시설>.docx"

Each ``Heading 1`` starts one item; ``Heading 2`` sections (취약점 설명, 진단 예시,
조치 방안) and the tables that follow them are mapped to structured fields.
Item numbers follow document order, which matches ``korean_standards`` IDs.
"""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path
from typing import Any

PROFILES = (
    ("critical_infrastructure", "CII-MA"),
    ("electronic_financial", "EFI-MA"),
)


def _cell_lines(cell: Any) -> list[str]:
    return [paragraph.text.strip() for paragraph in cell.paragraphs if paragraph.text.strip()]


def parse_advisory(path: Path, profile: str, prefix: str) -> list[dict[str, Any]]:
    import docx
    from docx.oxml.ns import qn
    from docx.table import Table
    from docx.text.paragraph import Paragraph

    document = docx.Document(str(path))
    items: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    section: str | None = None
    for child in document.element.body.iterchildren():
        if child.tag == qn("w:p"):
            paragraph = Paragraph(child, document)
            style = paragraph.style.name if paragraph.style is not None else ""
            text = paragraph.text.strip()
            if style == "Heading 1" and text:
                current = {
                    "title": text,
                    "description": [],
                    "threats": [],
                    "diagnostic_criteria": [],
                    "diagnostic_examples": [],
                    "remediation": [],
                    "remediation_examples": {},
                    "check_scripts": [],
                }
                items.append(current)
                section = None
            elif style == "Heading 2" and current is not None:
                section = text
            elif (
                current is not None
                and text
                and section == "취약점 설명"
                and "표" not in style
                and not text.startswith("[표")
            ):
                current["description"].append(text)
        elif child.tag == qn("w:tbl") and current is not None and section:
            table = Table(child, document)
            for row in table.rows:
                cells = row.cells
                if len(cells) < 2:
                    continue
                head = cells[0].text.strip()
                body = next((cell for cell in cells[1:] if cell.text.strip() != head), None)
                if body is None:
                    continue
                lines = _cell_lines(body)
                if section == "진단 예시":
                    if head == "위협 요소":
                        current["threats"].extend(lines)
                    elif head == "진단 기준":
                        current["diagnostic_criteria"].extend(lines)
                    elif head == "진단 예시":
                        current["diagnostic_examples"].extend(lines)
                    elif head != "구분":
                        current["diagnostic_examples"].extend(f"[{head}] {line}" for line in lines)
                elif section == "조치 방안":
                    if head == "조치 방안":
                        current["remediation"].extend(lines)
                    elif head == "점검 스크립트":
                        current["check_scripts"].extend(lines)
                    elif head != "구분":
                        current["remediation_examples"].setdefault(head, []).extend(lines)
    for index, item in enumerate(items, start=1):
        item["profile"] = profile
        item["control_id"] = f"{prefix}-{index:02d}"
    return items


def build_guidance(cii: Path, efi: Path) -> dict[str, Any]:
    controls = [
        *parse_advisory(cii, *PROFILES[0]),
        *parse_advisory(efi, *PROFILES[1]),
    ]
    return {
        "source": {
            PROFILES[0][0]: cii.name,
            PROFILES[1][0]: efi.name,
        },
        "extracted_at": date.today().isoformat(),
        "controls": controls,
    }


def verify_against_catalog(payload: dict[str, Any]) -> list[str]:
    """Return mismatches between extracted items and the catalog IDs/titles."""
    import re

    from backend.app.catalog.korean_standards import STANDARD_CONTROLS

    def normalize(value: str) -> str:
        return re.sub(r"[\s()\[\]·]", "", value).lower()

    extracted = {
        (item["profile"], item["control_id"]): item["title"]
        for item in payload.get("controls", [])
    }
    problems: list[str] = []
    for control in STANDARD_CONTROLS:
        title = extracted.get((control.profile, control.control_id))
        if title is None:
            problems.append(f"{control.control_id}: 문서에서 항목을 찾지 못했습니다.")
        elif normalize(title) != normalize(control.title):
            problems.append(f"{control.control_id}: 문서 제목 '{title}' ≠ 카탈로그 '{control.title}'")
    extra = len(extracted) - len(STANDARD_CONTROLS)
    if extra > 0:
        problems.append(f"문서 항목이 카탈로그보다 {extra}개 많습니다.")
    return problems


def write_guidance(payload: dict[str, Any], output: Path) -> Path:
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(".tmp")
    temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=1), encoding="utf-8")
    temporary.replace(output)
    return output
