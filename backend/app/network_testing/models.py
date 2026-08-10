from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass(slots=True)
class PassiveFlowAnalysis:
    source_flow_id: str
    method: str
    origin: str
    endpoint: str
    content_type: str
    auth_scheme: str | None
    cookie_names: list[str]
    query_parameters: list[dict[str, Any]]
    body_fields: list[dict[str, Any]]
    object_id_candidates: list[dict[str, Any]]
    pagination_parameters: list[str]
    file_upload: bool
    protocol_style: str
    sensitive_response_fields: list[str]
    synthetic: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class NetworkTestCandidate:
    id: str
    test_type: str
    source_flow_id: str
    method: str
    endpoint: str
    modified_fields: list[dict[str, Any]]
    expected_result: str
    risk: str
    requires_approval: bool
    auto_executable: bool
    rationale: str
    status: str = "candidate"
    synthetic: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ResponseComparison:
    status_changed: bool
    original_status: int | None
    candidate_status: int | None
    body_length_delta: int
    body_length_ratio: float | None
    json_structure_changed: bool
    added_keys: list[str]
    removed_keys: list[str]
    value_type_changes: list[dict[str, str]]
    sensitive_fields_added: list[str]
    redirect_changed: bool
    authentication_changed: bool
    authorization_changed: bool
    summary: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class NetworkExecution:
    candidate_id: str
    status: str
    message: str
    comparison: ResponseComparison | None = None
    evidence_ids: list[str] = field(default_factory=list)
    executed_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    synthetic: bool = False

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["comparison"] = (
            self.comparison.to_dict() if self.comparison else None
        )
        return data
