from __future__ import annotations

from backend.app.core.status import CapabilityStatus
from backend.app.proxy.base import ProxyFlowData

from .comparator import compare_responses
from .models import NetworkExecution, NetworkTestCandidate


class MockNetworkTestExecutor:
    """Synthetic executor; it never opens a socket."""

    async def execute(
        self,
        candidate: NetworkTestCandidate,
        source_flow: ProxyFlowData,
    ) -> NetworkExecution:
        if candidate.requires_approval or not candidate.auto_executable:
            return NetworkExecution(
                candidate_id=candidate.id,
                status=CapabilityStatus.MANUAL_REQUIRED.value,
                message="승인 대기 Candidate는 자동 실행하지 않았습니다.",
                synthetic=True,
            )
        if candidate.test_type == "passive_metadata":
            return NetworkExecution(
                candidate_id=candidate.id,
                status=CapabilityStatus.AVAILABLE.value,
                message="네트워크 전송 없이 합성 Flow metadata를 분류했습니다.",
                synthetic=True,
            )
        if candidate.test_type != "read_only_replay":
            return NetworkExecution(
                candidate_id=candidate.id,
                status=CapabilityStatus.UNSUPPORTED.value,
                message="Mock executor가 지원하지 않는 Candidate입니다.",
                synthetic=True,
            )
        comparison = compare_responses(
            original_status=source_flow.status_code,
            original_headers=source_flow.response_headers,
            original_body=source_flow.response_body,
            candidate_status=source_flow.status_code,
            candidate_headers=source_flow.response_headers,
            candidate_body=source_flow.response_body,
        )
        return NetworkExecution(
            candidate_id=candidate.id,
            status=CapabilityStatus.AVAILABLE.value,
            message="외부 전송 없이 Mock 읽기 전용 재현과 응답 비교를 합성 실행했습니다.",
            comparison=comparison,
            synthetic=True,
        )
