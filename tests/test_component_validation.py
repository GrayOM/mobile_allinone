from __future__ import annotations

import time

from backend.app.component_validation import build_component_candidates
from backend.app.database.models import DiagnosticRun
from backend.app.database.session import SessionLocal


def _wait_until_paused(client, run_id: str) -> dict:
    current = {}
    for _ in range(120):
        current = client.get(f"/api/runs/{run_id}").json()
        if current.get("status") in {"safely_paused", "failed"}:
            return current
        time.sleep(0.05)
    return current


def test_static_component_candidates_are_bounded_to_declared_targets():
    candidates = build_component_candidates(
        platform="android",
        package_name="com.example.demo",
        analysis_result={
            "components": [
                {
                    "type": "activity",
                    "name": ".EntryActivity",
                    "exported": True,
                    "permission": None,
                },
                {
                    "type": "receiver",
                    "name": ".DebugReceiver",
                    "exported": True,
                    "permission": None,
                },
                {
                    "type": "activity",
                    "name": ".ProtectedActivity",
                    "exported": True,
                    "permission": "com.example.PRIVATE",
                },
                {
                    "type": "activity",
                    "name": ".Entry$NestedActivity",
                    "exported": True,
                    "permission": None,
                },
            ],
            "deep_links": [
                {
                    "component": ".EntryActivity",
                    "scheme": "demo",
                    "host": "login",
                    "path": "/callback",
                },
                {"scheme": "file", "path": "/data/local/tmp/value"},
                {"scheme": "demo", "host": "login", "path": "/ok;id"},
            ],
        },
    )

    assert len(candidates) == 4
    activity = next(item for item in candidates if item.get("component_type") == "activity" and item["kind"] == "exported_component")
    receiver = next(item for item in candidates if item.get("component_type") == "receiver")
    nested = next(item for item in candidates if item.get("component_name") == ".Entry$NestedActivity")
    deep_link = next(item for item in candidates if item["kind"] == "deep_link")
    assert activity["execution_status"] == "approval_required"
    assert receiver["execution_status"] == "manual_required"
    assert nested["execution_status"] == "manual_required"
    assert deep_link["target"] == "demo://login/callback"
    assert all(len(item["id"]) == 24 for item in candidates)


def test_component_verification_consumes_candidate_scoped_approval_and_links_evidence(client):
    demo = client.post("/api/demo/bootstrap").json()
    created = client.post(
        "/api/runs",
        json={
            "project_id": demo["project"]["id"],
            "app_id": demo["app"]["id"],
            "device_id": "mock-android-01",
            "device_adapter": "mock",
            "proxy_adapter": "mock",
            "pause_for_login": True,
        },
    ).json()
    paused = _wait_until_paused(client, created["id"])
    assert paused["status"] == "safely_paused", paused.get("error")

    response = client.get(f"/api/runs/{created['id']}/component-candidates")
    assert response.status_code == 200
    candidates = response.json()["candidates"]
    activity = next(
        item
        for item in candidates
        if item["kind"] == "exported_component"
        and item["component_type"] == "activity"
    )
    receiver = next(item for item in candidates if item["component_type"] == "receiver")
    assert activity["finding_id"]
    assert receiver["execution_status"] == "manual_required"

    rejected = client.post(
        "/api/approvals",
        json={
            "project_id": demo["project"]["id"],
            "run_id": created["id"],
            "resource_type": "component",
            "action": "verify",
            "candidate_id": receiver["id"],
        },
    )
    assert rejected.status_code == 409

    approval = client.post(
        "/api/approvals",
        json={
            "project_id": demo["project"]["id"],
            "run_id": created["id"],
            "resource_type": "component",
            "action": "verify",
            "candidate_id": activity["id"],
            "approved_by": "mock-security-owner",
        },
    )
    assert approval.status_code == 201
    assert approval.json()["scope"]["target"] == activity["id"]

    executed = client.post(
        f"/api/runs/{created['id']}/component-candidates/{activity['id']}/verify",
        json={"approval_token": approval.json()["token"]},
    )
    assert executed.status_code == 200, executed.json()
    assert executed.json()["status"] == "available"
    assert executed.json()["reachable"] is True
    assert executed.json()["impact_confirmed"] is False

    reused = client.post(
        f"/api/runs/{created['id']}/component-candidates/{activity['id']}/verify",
        json={"approval_token": approval.json()["token"]},
    )
    assert reused.status_code == 409

    evidence = client.get(f"/api/runs/{created['id']}/evidence").json()
    expected_types = {
        "component_validation_before",
        "component_validation_action",
        "component_validation_after",
        "component_validation_log",
        "component_validation_result",
    }
    linked = [item for item in evidence if item["evidence_type"] in expected_types]
    assert {item["evidence_type"] for item in linked} == expected_types
    assert all(item["finding_id"] == activity["finding_id"] for item in linked)
    assert all(approval.json()["token"] not in str(item) for item in linked)

    refreshed = client.get(f"/api/runs/{created['id']}/component-candidates").json()
    verified = next(item for item in refreshed["candidates"] if item["id"] == activity["id"])
    assert verified["last_result"]["reachable"] is True
    assert client.post(f"/api/runs/{created['id']}/stop").status_code == 200


def test_live_component_verification_requires_active_control_scope(client):
    demo = client.post("/api/demo/bootstrap").json()
    with SessionLocal() as db:
        run = DiagnosticRun(
            project_id=demo["project"]["id"],
            app_id=demo["app"]["id"],
            device_id="android-test-device",
            device_adapter="android_adb",
            proxy_adapter="burp",
            run_mode="live",
            synthetic=False,
            status="safely_paused",
            options={},
        )
        db.add(run)
        db.commit()
        run_id = run.id

    candidates = client.get(f"/api/runs/{run_id}/component-candidates").json()["candidates"]
    activity = next(item for item in candidates if item["execution_status"] == "approval_required")
    approval = client.post(
        "/api/approvals",
        json={
            "project_id": demo["project"]["id"],
            "run_id": run_id,
            "resource_type": "component",
            "action": "verify",
            "candidate_id": activity["id"],
        },
    )
    assert approval.status_code == 201
    blocked = client.post(
        f"/api/runs/{run_id}/component-candidates/{activity['id']}/verify",
        json={"approval_token": approval.json()["token"]},
    )
    assert blocked.status_code == 409
    assert "승인 통제 검증 범위" in blocked.json()["detail"]
