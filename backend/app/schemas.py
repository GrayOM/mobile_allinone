from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class ProjectCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    description: str = ""
    ai_enabled: bool = True
    external_ai_allowed: bool = False
    mock_mode: bool = True


class ProjectUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = None
    ai_enabled: bool | None = None
    external_ai_allowed: bool | None = None
    mock_mode: bool | None = None


class ProjectOut(ORMModel):
    id: str
    name: str
    description: str
    ai_enabled: bool
    external_ai_allowed: bool
    mock_mode: bool
    created_at: datetime
    updated_at: datetime


class AppArtifactOut(ORMModel):
    id: str
    project_id: str
    original_name: str
    sha256: str
    size_bytes: int
    platform: str
    app_name: str | None
    package_name: str | None
    version: str | None
    analysis_status: str
    analysis_result: dict[str, Any]
    created_at: datetime


class RunCreate(BaseModel):
    project_id: str
    app_id: str | None = None
    device_id: str = "mock-android-01"
    device_adapter: str = "mock"
    proxy_adapter: str = "mock"
    frida_script_ids: list[str] = Field(default_factory=list)
    pause_for_login: bool = False
    options: dict[str, Any] = Field(default_factory=dict)


class RunOut(ORMModel):
    id: str
    project_id: str
    app_id: str | None
    device_id: str
    device_adapter: str
    proxy_adapter: str
    status: str
    current_stage: str
    progress: int
    options: dict[str, Any]
    error: str | None
    started_at: datetime | None
    finished_at: datetime | None
    created_at: datetime


class FindingOut(ORMModel):
    id: str
    project_id: str
    run_id: str | None
    title: str
    category: str
    platform: str
    severity: str
    location: str
    verdict: str
    confidence: float
    rationale: str
    reproduction: list[str]
    false_positive_risk: str
    additional_checks: list[str]
    source: str
    created_at: datetime


class EvidenceOut(ORMModel):
    id: str
    run_id: str
    finding_id: str | None
    evidence_type: str
    title: str
    description: str
    sequence: int
    file_path: str | None
    mime_type: str | None
    command: str | None
    inline_data: dict[str, Any] | list[Any] | None
    sha256: str | None
    captured_at: datetime


class FridaScriptCreate(BaseModel):
    name: str
    platform: str
    category: str
    target_framework: str = "generic"
    conditions: list[str] = Field(default_factory=list)
    risk: str = "medium"
    content: str
    source: str = "custom"


class FridaScriptOut(ORMModel):
    id: str
    name: str
    platform: str
    category: str
    target_framework: str
    conditions: list[str]
    risk: str
    content: str
    source: str
    approval_status: str
    syntax_status: str
    success_count: int
    failure_count: int
    created_at: datetime


class ProxyFlowOut(ORMModel):
    id: str
    run_id: str
    method: str
    url: str
    request_headers: dict[str, Any]
    request_body: str
    status_code: int | None
    response_headers: dict[str, Any]
    response_body: str
    sensitive_candidates: list[dict[str, Any]]
    captured_at: datetime


class AIAnalysis(BaseModel):
    title: str
    category: str
    platform: str
    location: str
    verdict: str
    confidence: float = Field(ge=0, le=1)
    rationale: str
    reproduction: list[str]
    evidence_ids: list[str]
    false_positive_risk: str
    additional_checks: list[str]


class FridaScriptCandidate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    platform: str
    category: str
    target_framework: str = "generic"
    conditions: list[str] = Field(default_factory=list)
    risk: str = Field(pattern="^(low|medium|high)$")
    content: str = Field(min_length=20)
    rationale: str
    confidence: float = Field(ge=0, le=1)
    safety_notes: list[str] = Field(default_factory=list)


class ToolStatusOut(BaseModel):
    name: str
    status: str
    configured_path: str
    resolved_path: str | None
    install_hint: str


class IOSDeviceProfileCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    host: str = Field(min_length=1, max_length=255)
    ssh_port: int = Field(default=22, ge=1, le=65535)
    username: str = Field(default="root", min_length=1, max_length=100)
    frida_endpoint: str | None = Field(default=None, max_length=255)
    notes: str = ""


class IOSDeviceProfileOut(ORMModel):
    id: str
    name: str
    host: str
    ssh_port: int
    username: str
    frida_endpoint: str | None
    notes: str
    created_at: datetime
