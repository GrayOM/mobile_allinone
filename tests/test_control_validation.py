from __future__ import annotations

import json
import importlib.util
import sys
import types
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from backend.app.control_validation import (
    ControlScopeError,
    active_control_scope,
    evaluate_network_scope,
    network_host_allowed,
    normalize_control_validation_request,
    normalize_network_hosts,
)
from backend.app.core.config import AppSettings
from backend.app.core.status import RunMode
from backend.app.database.models import DiagnosticRun, Project, ProxyFlow
from backend.app.database.session import SessionLocal
from backend.app.orchestration import DiagnosticOrchestrator
from backend.app.proxy import MitmProxyAdapter
from backend.app.proxy.base import ProxyFlowData


def _request(now: datetime) -> dict[str, object]:
    return {
        "authorization_reference": "CUSTOMER-TICKET-2048",
        "approved_by": "Customer Security Owner",
        "authorization_expires_at": (now + timedelta(hours=8)).isoformat(),
        "authorized_device_id": "rooted-android-01",
        "test_account_reference": "QA-ACCOUNT-03",
        "allowed_network_hosts": [
            "API.TEST.EXAMPLE.",
            "*.sandbox.example",
            "api.test.example",
        ],
        "scope_description": "승인된 루팅 단말과 테스트 서버에서 원본 증적만 수집",
        "authorized_scope_confirmed": True,
        "test_environment_confirmed": True,
        "test_data_only_confirmed": True,
    }


def test_control_scope_is_normalized_and_rechecked_at_execution_time():
    now = datetime(2026, 8, 13, 1, 0, tzinfo=timezone.utc)
    normalized = normalize_control_validation_request(
        _request(now),
        RunMode.LIVE,
        "rooted-android-01",
        now=now,
    )

    assert normalized["allowed_network_hosts"] == [
        "api.test.example",
        "*.sandbox.example",
    ]
    assert normalized["out_of_scope_action"] == "stop_and_manual_review"
    assert active_control_scope(
        {"control_validation": normalized},
        "rooted-android-01",
        now=now + timedelta(hours=1),
    ) == normalized

    with pytest.raises(ControlScopeError, match="만료"):
        active_control_scope(
            {"control_validation": normalized},
            "rooted-android-01",
            now=now + timedelta(hours=9),
        )
    with pytest.raises(ControlScopeError, match="실행 단말"):
        active_control_scope(
            {"control_validation": normalized},
            "different-device",
            now=now + timedelta(hours=1),
        )


def test_network_scope_uses_exact_and_subdomain_rules_with_default_deny():
    allowed = normalize_network_hosts(["api.test.example", "*.sandbox.example"])
    assert network_host_allowed("api.test.example", allowed) is True
    assert network_host_allowed("v2.sandbox.example", allowed) is True
    assert network_host_allowed("sandbox.example", allowed) is False
    assert network_host_allowed("sandbox.example.evil.test", allowed) is False
    with pytest.raises(ControlScopeError, match="URL이 아니라"):
        normalize_network_hosts(["https://api.test.example/v1"])

    flows = [
        ProxyFlowData("GET", "https://api.test.example/v1/profile"),
        ProxyFlowData("POST", "https://v2.sandbox.example/session"),
        ProxyFlowData(
            "GET",
            "https://outside.example/telemetry?token=secret",
            status_code=451,
            response_headers={"X-MSW-Control-Scope": "blocked"},
        ),
    ]
    summary = evaluate_network_scope(flows, ["flow-1", "flow-2", "flow-3"], allowed)

    assert summary["status"] == "violation"
    assert summary["evaluated_flow_count"] == 3
    assert summary["in_scope_count"] == 2
    assert summary["automatic_execution_stopped"] is True
    assert summary["violations"] == [
        {
            "source_flow_id": "flow-3",
            "method": "GET",
            "origin": "https://outside.example",
            "blocked_before_upstream": True,
        }
    ]
    assert "secret" not in json.dumps(summary)


def test_mitmproxy_receives_only_the_validated_destination_allowlist(
    tmp_path, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setenv("MSW_MITM_ALLOWED_HOSTS", "[\"stale.example\"]")
    monkeypatch.setenv("MSW_MITM_ALLOWED_CLIENT_IP", "198.51.100.99")
    adapter = MitmProxyAdapter(
        AppSettings(data_dir=tmp_path),
        host="192.0.2.10",
        port=8080,
        allowed_client_ip="192.0.2.25",
        allowed_destination_hosts=["api.test.example", "*.sandbox.example"],
    )

    env = adapter._environment(tmp_path / "capture.jsonl")

    assert env["MSW_MITM_ALLOWED_CLIENT_IP"] == "192.0.2.25"
    assert json.loads(env["MSW_MITM_ALLOWED_HOSTS"]) == [
        "api.test.example",
        "*.sandbox.example",
    ]

    unscoped = MitmProxyAdapter(AppSettings(data_dir=tmp_path))
    clean_env = unscoped._environment(tmp_path / "unscoped.jsonl")
    assert "MSW_MITM_ALLOWED_HOSTS" not in clean_env
    assert "MSW_MITM_ALLOWED_CLIENT_IP" not in clean_env


def test_mitm_addon_blocks_out_of_scope_host_before_upstream(
    tmp_path, monkeypatch: pytest.MonkeyPatch
):
    class FakeResponse:
        @staticmethod
        def make(status_code, content, headers):
            return {
                "status_code": status_code,
                "content": content,
                "headers": headers,
            }

    fake_mitmproxy = types.ModuleType("mitmproxy")
    fake_mitmproxy.http = types.SimpleNamespace(Response=FakeResponse)
    monkeypatch.setitem(sys.modules, "mitmproxy", fake_mitmproxy)
    monkeypatch.setenv("MSW_MITM_OUTPUT", str(tmp_path / "capture.jsonl"))
    monkeypatch.setenv(
        "MSW_MITM_ALLOWED_HOSTS",
        json.dumps(["api.test.example", "*.sandbox.example"]),
    )
    monkeypatch.setenv("MSW_MITM_ALLOWED_CLIENT_IP", "192.0.2.25")

    addon_path = Path(__file__).parents[1] / "scripts" / "mitm_capture_addon.py"
    spec = importlib.util.spec_from_file_location("test_mitm_capture_addon", addon_path)
    assert spec and spec.loader
    addon = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(addon)

    flow = types.SimpleNamespace(
        request=types.SimpleNamespace(host="outside.example"),
        client_conn=types.SimpleNamespace(peername=("192.0.2.25", 53000)),
        response=None,
        kill=lambda: pytest.fail("승인된 진단 단말 연결을 종료하면 안 됩니다."),
    )
    addon.request(flow)

    assert flow.response["status_code"] == 451
    assert flow.response["headers"]["X-MSW-Control-Scope"] == "blocked"


@pytest.mark.asyncio
async def test_scope_violation_is_persisted_as_local_audit_evidence(client):
    orchestrator = DiagnosticOrchestrator(client.app.state.settings)
    flow = ProxyFlowData(
        "GET",
        "https://outside.example/telemetry?token=secret",
        status_code=451,
        response_headers={"X-MSW-Control-Scope": "blocked"},
    )
    with SessionLocal() as db:
        project = Project(name="Control scope audit", run_mode="live", mock_mode=False)
        db.add(project)
        db.flush()
        run = DiagnosticRun(
            project_id=project.id,
            device_id="rooted-android-01",
            device_adapter="android_adb",
            proxy_adapter="mitmproxy",
            run_mode="live",
            synthetic=False,
            options={},
        )
        db.add(run)
        db.flush()
        row = ProxyFlow(
            run_id=run.id,
            method=flow.method,
            url=flow.url,
            response_headers=flow.response_headers,
            status_code=flow.status_code,
            synthetic=False,
        )
        db.add(row)
        db.flush()

        summary, evidence = await orchestrator._record_control_scope_enforcement(
            db,
            run,
            [flow],
            [row],
            {"allowed_network_hosts": ["api.test.example"]},
        )

        assert summary["violation_count"] == 1
        assert summary["automatic_execution_stopped"] is True
        assert run.options["control_scope_enforcement"]["evidence_id"] == evidence.id
        assert evidence.evidence_type == "control_scope_enforcement"
        assert evidence.synthetic is False
        assert "secret" not in json.dumps(evidence.inline_data)
        db.delete(project)
        db.commit()
