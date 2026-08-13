from __future__ import annotations

import time


def _wait_until_paused(client, run_id: str) -> dict:
    current = {}
    for _ in range(240):
        current = client.get(f"/api/runs/{run_id}").json()
        if current.get("status") in {"safely_paused", "failed"}:
            return current
        time.sleep(0.05)
    return current


def test_medium_ui_candidate_uses_current_screen_one_time_approval_and_evidence(client):
    demo = client.post("/api/demo/bootstrap").json()
    created = client.post(
        "/api/runs",
        json={
            "project_id": demo["project"]["id"],
            "app_id": demo["app"]["id"],
            "device_id": "mock-android-01",
            "device_adapter": "mock",
            "proxy_adapter": "mock",
            "options": {
                "auto_navigation": True,
                "dynamic_storage": False,
                "pause_for_approval_candidates": True,
            },
        },
    )
    assert created.status_code == 201
    run_id = created.json()["id"]
    paused = _wait_until_paused(client, run_id)
    assert paused["status"] == "safely_paused", paused.get("error")
    assert paused["current_stage"] == "navigation"

    register = client.get(f"/api/runs/{run_id}/ui-action-candidates")
    assert register.status_code == 200
    candidates = register.json()["candidates"]
    medium = next(item for item in candidates if item["risk"] == "medium")
    blocked = next(item for item in candidates if item["risk"] == "high")
    assert medium["label"] == "로그아웃"
    assert medium["approval_eligible"] is True
    assert blocked["approval_eligible"] is False

    high_approval = client.post(
        "/api/approvals",
        json={
            "project_id": demo["project"]["id"],
            "run_id": run_id,
            "resource_type": "ui_action",
            "action": "tap",
            "candidate_id": blocked["id"],
        },
    )
    assert high_approval.status_code == 409
    assert "고위험" in high_approval.json()["detail"]

    approval = client.post(
        "/api/approvals",
        json={
            "project_id": demo["project"]["id"],
            "run_id": run_id,
            "resource_type": "ui_action",
            "action": "tap",
            "candidate_id": medium["id"],
            "approved_by": "mock-security-owner",
        },
    )
    assert approval.status_code == 201, approval.json()
    executed = client.post(
        f"/api/runs/{run_id}/ui-action-candidates/{medium['id']}/execute",
        json={"approval_token": approval.json()["token"]},
    )
    assert executed.status_code == 200, executed.json()
    assert executed.json()["status"] == "available"

    reused = client.post(
        f"/api/runs/{run_id}/ui-action-candidates/{medium['id']}/execute",
        json={"approval_token": approval.json()["token"]},
    )
    assert reused.status_code == 409

    refreshed = client.get(f"/api/runs/{run_id}/ui-action-candidates").json()
    assert all(item["id"] != medium["id"] for item in refreshed["candidates"])
    assert refreshed["history"][-1]["id"] == medium["id"]
    evidence = client.get(f"/api/runs/{run_id}/evidence").json()
    expected = {
        "approved_ui_action_before",
        "approved_ui_action_before_tree",
        "approved_ui_action_scope",
        "approved_ui_action",
        "approved_ui_action_after",
        "approved_ui_action_after_tree",
        "approved_ui_action_result",
    }
    assert expected <= {item["evidence_type"] for item in evidence}
    assert all(approval.json()["token"] not in str(item) for item in evidence)
    assert client.post(f"/api/runs/{run_id}/stop").status_code == 200
