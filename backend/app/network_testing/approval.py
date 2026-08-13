from __future__ import annotations

from typing import Any

from backend.app.proxy.base import ProxyFlowData

from .candidate import NetworkCandidateEngine
from .classifier import classify_proxy_flow
from .models import NetworkTestCandidate


class NetworkApprovalError(ValueError):
    """Raised when an API candidate is stale or outside the executable policy."""


def resolve_network_candidate(
    options: dict[str, Any],
    candidate_id: str,
    source_flow: ProxyFlowData,
    *,
    source_flow_id: str,
) -> NetworkTestCandidate:
    summary = options.get("network_testing")
    stored_candidates = summary.get("candidates") if isinstance(summary, dict) else None
    if not isinstance(stored_candidates, list) or not any(
        isinstance(item, dict) and item.get("id") == candidate_id
        for item in stored_candidates
    ):
        raise NetworkApprovalError(
            "현재 Run의 API Candidate 원장에서 후보를 찾을 수 없습니다."
        )
    analysis = classify_proxy_flow(source_flow, source_flow_id=source_flow_id)
    candidate = next(
        (
            item
            for item in NetworkCandidateEngine().generate(analysis)
            if item.id == candidate_id
        ),
        None,
    )
    if candidate is None:
        raise NetworkApprovalError(
            "원본 Flow가 변경되어 API Candidate ID를 다시 확인해야 합니다."
        )
    if (
        candidate.test_type != "read_only_replay"
        or candidate.method not in {"GET", "HEAD"}
        or source_flow.request_body
    ):
        raise NetworkApprovalError(
            "GET/HEAD 무본문 읽기 전용 재현만 실행할 수 있습니다. 상태 변경·Object 경계 요청은 수동 검증으로 남깁니다."
        )
    return candidate
