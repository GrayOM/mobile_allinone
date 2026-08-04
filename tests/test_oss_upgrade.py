from __future__ import annotations

import pytest

from backend.app.catalog.mastg import evaluate_controls
from backend.app.core.config import AppSettings, ToolPaths
from backend.app.runtime import ObjectionRuntimeAdapter


def test_analysis_provenance_and_control_ledger_api(client):
    demo = client.post("/api/demo/bootstrap").json()
    app_id = demo["app"]["id"]
    project_id = demo["project"]["id"]

    overview = client.get(f"/api/apps/{app_id}/analysis/overview")
    assert overview.status_code == 200
    payload = overview.json()
    assert any(item["tool_name"] == "native_static" for item in payload["tool_runs"])
    assert payload["raw_findings"]
    assert payload["controls"]
    assert all(item["synthetic"] is True for item in payload["tool_runs"])
    assert all(item["synthetic"] is True for item in payload["raw_findings"])
    assert all(item["synthetic"] is True for item in payload["controls"])
    assert all(item["mastg_id"].startswith("MASTG-TEST-") for item in payload["controls"])

    coverage = client.get(f"/api/coverage?app_id={app_id}").json()
    assert coverage["tests"]
    assert coverage["total_catalog"] >= len(coverage["tests"])
    assert all(item["run_id"] is None for item in coverage["tests"])

    findings = client.get(f"/api/findings?project_id={project_id}").json()
    static = next(item for item in findings if item["source"].startswith("static:"))
    sources = client.get(f"/api/findings/{static['id']}/sources").json()
    assert sources
    assert all(item["source_tool"] for item in sources)
    assert all(len(item["fingerprint"]) == 64 for item in sources)


def test_mock_ai_frida_candidate_is_never_auto_approved(client):
    demo = client.post("/api/demo/bootstrap").json()
    generated = client.post(
        "/api/frida/scripts/generate",
        json={
            "project_id": demo["project"]["id"],
            "platform": "android",
            "category": "Anti-Frida",
            "target_framework": "Android Java",
            "runtime_log": "ClassNotFoundException: demo",
            "use_mock": True,
        },
    )
    assert generated.status_code == 200
    payload = generated.json()
    assert payload["execution_policy"].startswith("never_auto_execute")
    assert payload["script"]["approval_status"] == "pending_approval"
    assert payload["selected"]["provider"] == "mock"

    execution = client.post(
        f"/api/frida/scripts/{payload['script']['id']}/execute",
        json={"mock": True},
    )
    assert execution.status_code == 409


def test_catalog_static_evaluation_keeps_manual_controls_explicit():
    analysis = {
        "manifest": {"debuggable": True, "allow_backup": True},
        "signals": {"root_detection": [{"value": "RootBeer"}]},
    }
    controls = evaluate_controls("android", analysis)
    debug = next(item for item in controls if item["mastg_id"] == "MASTG-TEST-0039")
    assert debug["status"] == "completed"
    assert debug["result"] == "fail"
    assert any(item["status"] == "manual_required" for item in controls)


@pytest.mark.asyncio
async def test_runtime_mutation_requires_approval_before_tool_lookup():
    missing = "definitely-missing-msw-tool"
    settings = AppSettings(tools=ToolPaths(objection=missing))
    result = await ObjectionRuntimeAdapter(settings).execute(
        device_id="test-device",
        target="com.example.test",
        action="android_ssl_pinning_disable",
        approved=False,
    )
    assert result.status.value == "manual_required"
    assert result.command is None
