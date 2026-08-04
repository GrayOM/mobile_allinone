from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from backend.app.core.status import FindingVerdict, RunMode
from backend.app.core.targets import SSH_USERNAME_PATTERN, is_valid_host


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class ProjectCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    description: str = ""
    ai_enabled: bool = True
    external_ai_allowed: bool = False
    external_analyzer_allowed: bool = False
    run_mode: RunMode = RunMode.LIVE
    mock_mode: bool | None = None

    @model_validator(mode="after")
    def normalize_legacy_mode(self):
        if self.mock_mode is not None:
            self.run_mode = RunMode.MOCK if self.mock_mode else RunMode.LIVE
        self.mock_mode = self.run_mode == RunMode.MOCK
        return self


class ProjectUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = None
    ai_enabled: bool | None = None
    external_ai_allowed: bool | None = None
    external_analyzer_allowed: bool | None = None
    mock_mode: bool | None = None
    run_mode: RunMode | None = None

    @model_validator(mode="after")
    def normalize_legacy_mode(self):
        if self.run_mode is None and self.mock_mode is not None:
            self.run_mode = RunMode.MOCK if self.mock_mode else RunMode.LIVE
        if self.run_mode is not None:
            self.mock_mode = self.run_mode == RunMode.MOCK
        return self


class ProjectOut(ORMModel):
    id: str
    name: str
    description: str
    ai_enabled: bool
    external_ai_allowed: bool
    external_analyzer_allowed: bool
    external_analyzer_approved_by: str | None
    external_analyzer_approved_at: datetime | None
    external_analyzer_destination: str | None
    external_analyzer_addresses: list[str]
    external_analyzer_certificate_sha256: str | None
    mock_mode: bool
    run_mode: str
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
    synthetic: bool
    created_at: datetime


class RunCreate(BaseModel):
    project_id: str
    app_id: str | None = None
    device_id: str = Field(min_length=1, max_length=255)
    device_adapter: str = Field(min_length=1, max_length=50)
    proxy_adapter: str = Field(min_length=1, max_length=50)
    frida_script_ids: list[str] = Field(default_factory=list)
    auto_select_frida: bool = False
    pause_for_login: bool = False
    options: dict[str, Any] = Field(default_factory=dict)


class RunOut(ORMModel):
    id: str
    project_id: str
    app_id: str | None
    device_id: str
    device_adapter: str
    proxy_adapter: str
    run_mode: str
    synthetic: bool
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
    synthetic: bool
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
    synthetic: bool
    captured_at: datetime


class FridaScriptCreate(BaseModel):
    name: str
    platform: str = Field(pattern="^(android|ios)$")
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
    approved_by: str | None
    approved_at: datetime | None
    approved_sha256: str | None
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
    source_ip: str | None
    synthetic: bool
    captured_at: datetime


class AIFindingCandidate(BaseModel):
    title: str
    category: str
    platform: str = Field(pattern="^(android|ios)$")
    severity: str = Field(pattern="^(critical|high|medium|low|info)$")
    location: str
    verdict: FindingVerdict
    confidence: float = Field(ge=0, le=1)
    rationale: str
    reproduction: list[str]
    evidence_ids: list[str]
    false_positive_risk: str
    additional_checks: list[str]

    @model_validator(mode="after")
    def confirmed_requires_evidence(self):
        if self.verdict == FindingVerdict.CONFIRMED and not self.evidence_ids:
            raise ValueError("confirmed 판정에는 최소 1개의 증적 ID가 필요합니다.")
        return self


class AIAnalysis(BaseModel):
    findings: list[AIFindingCandidate] = Field(default_factory=list, max_length=50)

    @property
    def confidence(self) -> float:
        return max((item.confidence for item in self.findings), default=0.0)


class FridaScriptCandidate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    platform: str = Field(pattern="^(android|ios)$")
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

    @field_validator("host")
    @classmethod
    def validate_host(cls, value: str) -> str:
        normalized = value.strip().rstrip(".")
        if not is_valid_host(normalized):
            raise ValueError("SSH 호스트는 유효한 IP 주소 또는 hostname이어야 합니다.")
        return normalized

    @field_validator("username")
    @classmethod
    def validate_username(cls, value: str) -> str:
        if not SSH_USERNAME_PATTERN.fullmatch(value):
            raise ValueError("SSH 사용자명 형식이 올바르지 않습니다.")
        return value


class IOSDeviceProfileOut(ORMModel):
    id: str
    name: str
    host: str
    ssh_port: int
    username: str
    frida_endpoint: str | None
    notes: str
    created_at: datetime
