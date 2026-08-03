from __future__ import annotations

import hashlib
import json
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from backend.app.core.config import AppSettings
from backend.app.core.status import CapabilityStatus


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def finding_fingerprint(
    source_tool: str,
    rule_id: str,
    category: str,
    location: str,
    title: str,
) -> str:
    normalized = "|".join(
        part.strip().lower()
        for part in (source_tool, rule_id, category, location, title)
    )
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


@dataclass(slots=True)
class AnalyzerFinding:
    title: str
    category: str
    severity: str
    location: str
    rationale: str
    confidence: float
    source_tool: str
    rule_id: str
    verdict: str = "needs_review"
    references: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def fingerprint(self) -> str:
        return finding_fingerprint(
            self.source_tool,
            self.rule_id,
            self.category,
            self.location,
            self.title,
        )

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["fingerprint"] = self.fingerprint
        return data


@dataclass(slots=True)
class AnalyzerResult:
    tool: str
    status: CapabilityStatus
    version: str | None = None
    command: list[str] = field(default_factory=list)
    started_at: datetime = field(default_factory=utcnow)
    finished_at: datetime | None = None
    raw_output_path: str | None = None
    raw_sha256: str | None = None
    error: str | None = None
    findings: list[AnalyzerFinding] = field(default_factory=list)
    enrichment: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def finish(self) -> "AnalyzerResult":
        self.finished_at = utcnow()
        return self

    def save_raw(self, output_dir: Path, payload: Any) -> None:
        output_dir.mkdir(parents=True, exist_ok=True)
        destination = output_dir / f"{self.tool}.json"
        encoded = json.dumps(
            payload, ensure_ascii=False, indent=2, default=str
        ).encode("utf-8")
        destination.write_bytes(encoded)
        self.raw_output_path = str(destination)
        self.raw_sha256 = hashlib.sha256(encoded).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "status": self.status.value,
            "version": self.version,
            "command": self.command,
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "raw_output_path": self.raw_output_path,
            "raw_sha256": self.raw_sha256,
            "error": self.error,
            "finding_count": len(self.findings),
            "metadata": self.metadata,
        }


class AnalyzerAdapter(ABC):
    name: str

    def __init__(self, settings: AppSettings):
        self.settings = settings

    @abstractmethod
    async def health(self) -> dict[str, Any]:
        raise NotImplementedError

    @abstractmethod
    async def analyze(
        self,
        artifact_path: Path,
        output_dir: Path,
        *,
        platform: str,
        decompiled_dir: Path | None = None,
    ) -> AnalyzerResult:
        raise NotImplementedError

