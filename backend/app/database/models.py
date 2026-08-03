from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, TimestampMixin, utcnow


def new_id() -> str:
    return str(uuid.uuid4())


class Project(Base, TimestampMixin):
    __tablename__ = "projects"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    ai_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    external_ai_allowed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    mock_mode: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    apps: Mapped[list["AppArtifact"]] = relationship(
        back_populates="project", cascade="all, delete-orphan"
    )
    runs: Mapped[list["DiagnosticRun"]] = relationship(
        back_populates="project", cascade="all, delete-orphan"
    )
    findings: Mapped[list["Finding"]] = relationship(
        back_populates="project", cascade="all, delete-orphan"
    )


class AppArtifact(Base, TimestampMixin):
    __tablename__ = "app_artifacts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), index=True)
    original_name: Mapped[str] = mapped_column(String(255), nullable=False)
    stored_path: Mapped[str] = mapped_column(Text, nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    platform: Mapped[str] = mapped_column(String(24), nullable=False)
    app_name: Mapped[str | None] = mapped_column(String(255))
    package_name: Mapped[str | None] = mapped_column(String(255))
    version: Mapped[str | None] = mapped_column(String(100))
    analysis_status: Mapped[str] = mapped_column(String(32), default="pending")
    analysis_result: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    project: Mapped["Project"] = relationship(back_populates="apps")
    runs: Mapped[list["DiagnosticRun"]] = relationship(back_populates="app")
    tool_runs: Mapped[list["ToolRun"]] = relationship(
        back_populates="app", cascade="all, delete-orphan"
    )
    raw_findings: Mapped[list["RawFinding"]] = relationship(
        back_populates="app", cascade="all, delete-orphan"
    )
    control_tests: Mapped[list["ControlTest"]] = relationship(
        back_populates="app", cascade="all, delete-orphan"
    )


class DiagnosticRun(Base, TimestampMixin):
    __tablename__ = "diagnostic_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), index=True)
    app_id: Mapped[str | None] = mapped_column(ForeignKey("app_artifacts.id"))
    device_id: Mapped[str] = mapped_column(String(255), nullable=False)
    device_adapter: Mapped[str] = mapped_column(String(50), default="mock")
    proxy_adapter: Mapped[str] = mapped_column(String(50), default="mock")
    status: Mapped[str] = mapped_column(String(32), default="created", index=True)
    current_stage: Mapped[str] = mapped_column(String(100), default="ready")
    progress: Mapped[int] = mapped_column(Integer, default=0)
    options: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    error: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    project: Mapped["Project"] = relationship(back_populates="runs")
    app: Mapped["AppArtifact | None"] = relationship(back_populates="runs")
    findings: Mapped[list["Finding"]] = relationship(
        back_populates="run", cascade="all, delete-orphan"
    )
    evidence: Mapped[list["Evidence"]] = relationship(
        back_populates="run", cascade="all, delete-orphan"
    )
    flows: Mapped[list["ProxyFlow"]] = relationship(
        back_populates="run", cascade="all, delete-orphan"
    )


class Finding(Base, TimestampMixin):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), index=True)
    run_id: Mapped[str | None] = mapped_column(ForeignKey("diagnostic_runs.id"), index=True)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    category: Mapped[str] = mapped_column(String(100), nullable=False)
    platform: Mapped[str] = mapped_column(String(24), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), default="info")
    location: Mapped[str] = mapped_column(Text, default="")
    verdict: Mapped[str] = mapped_column(String(30), default="needs_review")
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    rationale: Mapped[str] = mapped_column(Text, default="")
    reproduction: Mapped[list[str]] = mapped_column(JSON, default=list)
    false_positive_risk: Mapped[str] = mapped_column(Text, default="")
    additional_checks: Mapped[list[str]] = mapped_column(JSON, default=list)
    source: Mapped[str] = mapped_column(String(50), default="static")

    project: Mapped["Project"] = relationship(back_populates="findings")
    run: Mapped["DiagnosticRun | None"] = relationship(back_populates="findings")
    evidence: Mapped[list["Evidence"]] = relationship(back_populates="finding")
    sources: Mapped[list["FindingSource"]] = relationship(
        back_populates="finding", cascade="all, delete-orphan"
    )


class Evidence(Base):
    __tablename__ = "evidence"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    run_id: Mapped[str] = mapped_column(ForeignKey("diagnostic_runs.id"), index=True)
    finding_id: Mapped[str | None] = mapped_column(ForeignKey("findings.id"), index=True)
    evidence_type: Mapped[str] = mapped_column(String(50), nullable=False)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    sequence: Mapped[int] = mapped_column(Integer, default=0)
    file_path: Mapped[str | None] = mapped_column(Text)
    mime_type: Mapped[str | None] = mapped_column(String(100))
    command: Mapped[str | None] = mapped_column(Text)
    inline_data: Mapped[dict[str, Any] | list[Any] | None] = mapped_column(JSON)
    sha256: Mapped[str | None] = mapped_column(String(64))
    captured_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )

    run: Mapped["DiagnosticRun"] = relationship(back_populates="evidence")
    finding: Mapped["Finding | None"] = relationship(back_populates="evidence")


class FridaScript(Base, TimestampMixin):
    __tablename__ = "frida_scripts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    platform: Mapped[str] = mapped_column(String(24), nullable=False)
    category: Mapped[str] = mapped_column(String(100), nullable=False)
    target_framework: Mapped[str] = mapped_column(String(100), default="generic")
    conditions: Mapped[list[str]] = mapped_column(JSON, default=list)
    risk: Mapped[str] = mapped_column(String(20), default="medium")
    content: Mapped[str] = mapped_column(Text, nullable=False)
    source: Mapped[str] = mapped_column(String(30), default="builtin")
    approval_status: Mapped[str] = mapped_column(String(30), default="approved")
    syntax_status: Mapped[str] = mapped_column(String(30), default="unchecked")
    success_count: Mapped[int] = mapped_column(Integer, default=0)
    failure_count: Mapped[int] = mapped_column(Integer, default=0)


class ProxyFlow(Base):
    __tablename__ = "proxy_flows"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    run_id: Mapped[str] = mapped_column(ForeignKey("diagnostic_runs.id"), index=True)
    method: Mapped[str] = mapped_column(String(16), nullable=False)
    url: Mapped[str] = mapped_column(Text, nullable=False)
    request_headers: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    request_body: Mapped[str] = mapped_column(Text, default="")
    status_code: Mapped[int | None] = mapped_column(Integer)
    response_headers: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    response_body: Mapped[str] = mapped_column(Text, default="")
    sensitive_candidates: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    captured_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )

    run: Mapped["DiagnosticRun"] = relationship(back_populates="flows")


class AIInvocation(Base):
    __tablename__ = "ai_invocations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), index=True)
    run_id: Mapped[str | None] = mapped_column(ForeignKey("diagnostic_runs.id"))
    provider: Mapped[str] = mapped_column(String(50), nullable=False)
    model: Mapped[str] = mapped_column(String(150), nullable=False)
    task: Mapped[str] = mapped_column(String(100), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    masked: Mapped[bool] = mapped_column(Boolean, default=True)
    quality_score: Mapped[float | None] = mapped_column(Float)
    raw_response_path: Mapped[str | None] = mapped_column(Text)
    error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )


class IOSDeviceProfile(Base, TimestampMixin):
    __tablename__ = "ios_device_profiles"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    host: Mapped[str] = mapped_column(String(255), nullable=False)
    ssh_port: Mapped[int] = mapped_column(Integer, default=22, nullable=False)
    username: Mapped[str] = mapped_column(String(100), default="root", nullable=False)
    frida_endpoint: Mapped[str | None] = mapped_column(String(255))
    notes: Mapped[str] = mapped_column(Text, default="", nullable=False)


class ToolRun(Base):
    __tablename__ = "tool_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    app_id: Mapped[str] = mapped_column(ForeignKey("app_artifacts.id"), index=True)
    run_id: Mapped[str | None] = mapped_column(
        ForeignKey("diagnostic_runs.id"), index=True
    )
    tool_name: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    tool_version: Mapped[str | None] = mapped_column(String(200))
    status: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    command: Mapped[list[str]] = mapped_column(JSON, default=list)
    raw_output_path: Mapped[str | None] = mapped_column(Text)
    raw_sha256: Mapped[str | None] = mapped_column(String(64))
    error: Mapped[str | None] = mapped_column(Text)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    app: Mapped["AppArtifact"] = relationship(back_populates="tool_runs")
    raw_findings: Mapped[list["RawFinding"]] = relationship(back_populates="tool_run")


class RawFinding(Base):
    __tablename__ = "raw_findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    app_id: Mapped[str] = mapped_column(ForeignKey("app_artifacts.id"), index=True)
    tool_run_id: Mapped[str | None] = mapped_column(ForeignKey("tool_runs.id"), index=True)
    source_tool: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    rule_id: Mapped[str] = mapped_column(String(300), nullable=False)
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    category: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    location: Mapped[str] = mapped_column(Text, default="")
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    references: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    raw_payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )

    app: Mapped["AppArtifact"] = relationship(back_populates="raw_findings")
    tool_run: Mapped["ToolRun | None"] = relationship(back_populates="raw_findings")


class FindingSource(Base):
    __tablename__ = "finding_sources"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    finding_id: Mapped[str] = mapped_column(ForeignKey("findings.id"), index=True)
    raw_finding_id: Mapped[str | None] = mapped_column(
        ForeignKey("raw_findings.id"), index=True
    )
    source_tool: Mapped[str] = mapped_column(String(80), nullable=False)
    source_rule_id: Mapped[str] = mapped_column(String(300), nullable=False)
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    evidence_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )

    finding: Mapped["Finding"] = relationship(back_populates="sources")


class ControlTest(Base, TimestampMixin):
    __tablename__ = "control_tests"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), index=True)
    app_id: Mapped[str] = mapped_column(ForeignKey("app_artifacts.id"), index=True)
    run_id: Mapped[str | None] = mapped_column(
        ForeignKey("diagnostic_runs.id"), index=True
    )
    mastg_id: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    masvs_id: Mapped[str] = mapped_column(String(60), nullable=False, index=True)
    platform: Mapped[str] = mapped_column(String(24), nullable=False)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    automation: Mapped[str] = mapped_column(String(30), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    result: Mapped[str] = mapped_column(String(32), nullable=False)
    summary: Mapped[str] = mapped_column(Text, default="")
    replacement_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    source_url: Mapped[str] = mapped_column(Text, default="")
    evidence_ids: Mapped[list[str]] = mapped_column(JSON, default=list)

    app: Mapped["AppArtifact"] = relationship(back_populates="control_tests")
