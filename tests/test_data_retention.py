from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from backend.app.database.models import DiagnosticRun
from backend.app.database.session import SessionLocal


def _wait_for_terminal(client, run_id: str) -> dict:
    deadline = time.time() + 30
    while time.time() < deadline:
        run = client.get(f"/api/runs/{run_id}").json()
        if run["status"] in {
            "completed",
            "completed_with_gaps",
            "manual_required",
            "failed",
        }:
            return run
        time.sleep(0.05)
    raise AssertionError("run did not finish")


def test_project_retention_requires_exact_preview_and_raw_opt_in(client):
    demo = client.post("/api/demo/bootstrap").json()
    started = client.post(
        "/api/runs",
        json={
            "project_id": demo["project"]["id"],
            "app_id": demo["app"]["id"],
            "device_id": "mock-android-01",
            "device_adapter": "mock",
            "proxy_adapter": "mock",
        },
    )
    assert started.status_code == 201
    run = _wait_for_terminal(client, started.json()["id"])
    project_id = demo["project"]["id"]
    run_id = run["id"]

    denied = client.get(f"/api/projects/{project_id}/runs/{run_id}/raw-index")
    assert denied.status_code == 409
    policy = client.patch(
        f"/api/projects/{project_id}",
        json={"retention_days": 1, "raw_access_enabled": True},
    )
    assert policy.status_code == 200
    assert policy.json()["retention_days"] == 1
    assert policy.json()["raw_access_enabled"] is True

    raw_index = client.get(
        f"/api/projects/{project_id}/runs/{run_id}/raw-index"
    )
    assert raw_index.status_code == 200
    assert raw_index.headers["Cache-Control"] == "no-store"
    raw_payload = raw_index.json()
    assert raw_payload["evidence"]
    assert all("file_path" not in item for item in raw_payload["evidence"])
    assert raw_payload["raw_flows_endpoint"] == f"/runs/{run_id}/flows/raw"

    with SessionLocal() as db:
        stored = db.get(DiagnosticRun, run_id)
        assert stored is not None
        stored.finished_at = datetime.now(timezone.utc) - timedelta(days=2)
        db.commit()

    inventory_response = client.get(f"/api/projects/{project_id}/data-inventory")
    assert inventory_response.status_code == 200
    assert inventory_response.headers["Cache-Control"] == "no-store"
    inventory = inventory_response.json()
    assert inventory["automatic_deletion"] is False
    assert inventory["expired_run_ids"] == [run_id]
    assert inventory["runs"][0]["disk_bytes"] > 0
    run_directory = client.app.state.settings.evidence_dir / run_id
    assert run_directory.is_dir()

    wrong_name = client.post(
        f"/api/projects/{project_id}/retention/apply",
        json={
            "reviewed": True,
            "confirm_project_name": "wrong project",
            "expected_run_ids": [run_id],
        },
    )
    assert wrong_name.status_code == 422
    stale_preview = client.post(
        f"/api/projects/{project_id}/retention/apply",
        json={
            "reviewed": True,
            "confirm_project_name": demo["project"]["name"],
            "expected_run_ids": ["stale-run-id"],
        },
    )
    assert stale_preview.status_code == 409
    assert client.get(f"/api/runs/{run_id}").status_code == 200

    applied = client.post(
        f"/api/projects/{project_id}/retention/apply",
        json={
            "reviewed": True,
            "confirm_project_name": demo["project"]["name"],
            "expected_run_ids": [run_id],
        },
    )
    assert applied.status_code == 200
    result = applied.json()
    assert result["status"] == "completed"
    assert result["removed_run_ids"] == [run_id]
    assert result["removed_database"]["runs"] == 1
    assert result["recoverable"] is False
    assert result["remaining_inventory"]["run_count"] == 0
    assert client.get(f"/api/runs/{run_id}").status_code == 404
    assert not run_directory.exists()
