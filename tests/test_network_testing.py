from __future__ import annotations

import pytest

from backend.app.core.status import CapabilityStatus
from backend.app.network_testing import (
    LiveNetworkExecutionError,
    LiveReadOnlyNetworkExecutor,
    MockNetworkTestExecutor,
    NetworkApprovalError,
    NetworkCandidateEngine,
    classify_proxy_flow,
    compare_responses,
    resolve_network_candidate,
)
from backend.app.proxy.base import ProxyFlowData


def _flow(method: str, url: str, *, synthetic: bool = False) -> ProxyFlowData:
    return ProxyFlowData(
        method=method,
        url=url,
        request_headers={
            "Content-Type": "application/json",
            "Authorization": "Bearer must-not-leak",
            "Cookie": "session=secret; theme=dark",
        },
        request_body='{"account_id":100,"page":2}',
        status_code=200,
        response_headers={"Content-Type": "application/json"},
        response_body='{"account_id":100,"email":"owner@example.test"}',
        synthetic=synthetic,
    )


def test_proxy_flow_classification_is_structured_and_masks_values():
    analysis = classify_proxy_flow(
        _flow("GET", "https://api.example.test/v1/account/100?user_id=200"),
        source_flow_id="flow-1",
    )
    payload = analysis.to_dict()
    assert analysis.endpoint == "/v1/account/{id}"
    assert analysis.auth_scheme == "Bearer"
    assert analysis.cookie_names == ["session", "theme"]
    assert {item["location"] for item in analysis.object_id_candidates} >= {
        "path:2",
        "query:user_id",
        "json:account_id",
    }
    assert "must-not-leak" not in str(payload)
    assert "owner@example.test" not in str(payload)
    assert "email" in analysis.sensitive_response_fields


def test_safe_and_dangerous_api_candidates_have_explicit_approval_boundary():
    engine = NetworkCandidateEngine()
    safe_analysis = classify_proxy_flow(
        _flow("GET", "https://api.example.test/v1/profile", synthetic=True),
        source_flow_id="safe",
    )
    safe = engine.generate(safe_analysis)
    replay = next(item for item in safe if item.test_type == "read_only_replay")
    assert replay.auto_executable is True
    assert replay.requires_approval is False

    dangerous_analysis = classify_proxy_flow(
        _flow("POST", "https://api.example.test/v1/profile", synthetic=True),
        source_flow_id="dangerous",
    )
    dangerous = engine.generate(dangerous_analysis)
    mutation = next(item for item in dangerous if item.test_type == "state_changing_replay")
    object_boundary = next(item for item in dangerous if item.test_type == "object_boundary")
    assert mutation.requires_approval is True
    assert mutation.auto_executable is False
    assert object_boundary.modified_fields[0]["candidate"] == "<approved-test-object-id-required>"


def test_response_comparator_checks_structure_auth_redirect_and_sensitive_fields():
    comparison = compare_responses(
        original_status=403,
        original_headers={},
        original_body='{"error":{"code":"forbidden"}}',
        candidate_status=200,
        candidate_headers={"Location": "/profile/101"},
        candidate_body='{"profile":{"email":"other@example.test","id":101}}',
    )
    assert comparison.status_changed is True
    assert comparison.authorization_changed is True
    assert comparison.redirect_changed is True
    assert comparison.json_structure_changed is True
    assert "$.profile.email" in comparison.sensitive_fields_added
    assert comparison.body_length_delta != 0


@pytest.mark.asyncio
async def test_mock_safe_candidate_executes_without_network_and_dangerous_waits():
    flow = _flow("GET", "https://api.example.test/v1/profile", synthetic=True)
    analysis = classify_proxy_flow(flow, source_flow_id="mock-flow")
    candidates = NetworkCandidateEngine().generate(analysis)
    replay = next(item for item in candidates if item.test_type == "read_only_replay")
    execution = await MockNetworkTestExecutor().execute(replay, flow)
    assert execution.status == CapabilityStatus.AVAILABLE.value
    assert execution.synthetic is True
    assert execution.comparison is not None
    assert execution.comparison.json_structure_changed is False


def test_only_bodyless_get_head_candidates_cross_the_approved_execution_boundary():
    get_flow = _flow("GET", "https://api.example.test/v1/profile")
    get_flow.request_body = ""
    analysis = classify_proxy_flow(get_flow, source_flow_id="live-get")
    replay = next(
        item
        for item in NetworkCandidateEngine().generate(analysis)
        if item.test_type == "read_only_replay"
    )
    options = {
        "network_testing": {
            "candidates": [replay.to_dict()],
            "executions": [],
        }
    }
    resolved = resolve_network_candidate(
        options,
        replay.id,
        get_flow,
        source_flow_id="live-get",
    )
    assert resolved.method == "GET"

    get_flow.request_body = '{"unexpected":"body"}'
    with pytest.raises(NetworkApprovalError, match="무본문 읽기 전용"):
        resolve_network_candidate(
            options,
            replay.id,
            get_flow,
            source_flow_id="live-get",
        )


@pytest.mark.asyncio
async def test_live_executor_rejects_state_changing_request_before_dns_or_socket():
    flow = _flow("POST", "https://api.example.test/v1/profile")
    analysis = classify_proxy_flow(flow, source_flow_id="live-post")
    mutation = next(
        item
        for item in NetworkCandidateEngine().generate(analysis)
        if item.test_type == "state_changing_replay"
    )
    with pytest.raises(LiveNetworkExecutionError, match="상태 변경"):
        await LiveReadOnlyNetworkExecutor().execute(
            mutation,
            flow,
            allowed_hosts=["api.example.test"],
        )
