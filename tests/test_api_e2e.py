from __future__ import annotations

import time


def _wait_for_run(client, run_id: str, timeout: float = 8):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        run = client.get(f"/api/runs/{run_id}").json()
        if run["status"] in {"completed", "failed", "stopped"}:
            return run
        time.sleep(0.05)
    raise AssertionError("진단 실행이 제한 시간 안에 끝나지 않았습니다.")


def test_mock_demo_runs_end_to_end(client):
    bootstrap = client.post("/api/demo/bootstrap")
    assert bootstrap.status_code == 200
    demo = bootstrap.json()
    assert demo["app"]["package_name"] == "com.example.msw.demo"
    assert demo["app"]["analysis_status"] == "completed"

    started = client.post(
        "/api/runs",
        json={
            "project_id": demo["project"]["id"],
            "app_id": demo["app"]["id"],
            "device_id": "mock-android-01",
            "device_adapter": "mock",
            "proxy_adapter": "mock",
            "pause_for_login": False,
        },
    )
    assert started.status_code == 201
    run = _wait_for_run(client, started.json()["id"])
    assert run["status"] == "completed", run["error"]

    evidence = client.get(f"/api/runs/{run['id']}/evidence").json()
    flows = client.get(f"/api/runs/{run['id']}/flows").json()
    findings = client.get(f"/api/findings?run_id={run['id']}").json()

    assert len(evidence) >= 10
    assert {"screenshot", "frida_script", "network_capture", "device_log"} <= {
        item["evidence_type"] for item in evidence
    }
    assert len(flows) == 2
    assert findings and findings[0]["source"] == "ai:mock"

    report = client.post(f"/api/findings/{findings[0]['id']}/report")
    assert report.status_code == 200
    html = client.get(report.json()["url"])
    assert html.status_code == 200
    assert "증적 설명서" in html.text
    assert "원본 파일 내려받기" in html.text

    deleted = client.delete(f"/api/projects/{demo['project']['id']}")
    assert deleted.status_code == 200
    assert deleted.json()["recoverable"] is False
    assert client.get(f"/api/projects/{demo['project']['id']}").status_code == 404


def test_custom_frida_script_requires_approval(client):
    created = client.post(
        "/api/frida/scripts",
        json={
            "name": "Test candidate",
            "platform": "android",
            "category": "Custom",
            "target_framework": "generic",
            "conditions": [],
            "risk": "medium",
            "content": "setImmediate(function () { send({event: 'test'}); });",
            "source": "ai",
        },
    )
    assert created.status_code == 201
    script = created.json()
    assert script["approval_status"] == "pending_approval"

    denied = client.post(
        f"/api/frida/scripts/{script['id']}/execute",
        json={"mock": True},
    )
    assert denied.status_code == 409

    approved = client.post(f"/api/frida/scripts/{script['id']}/approve")
    assert approved.status_code == 200
    executed = client.post(
        f"/api/frida/scripts/{script['id']}/execute",
        json={"mock": True},
    )
    assert executed.status_code == 200
    assert executed.json()["status"] == "available"


def test_login_pause_and_resume(client):
    demo = client.post("/api/demo/bootstrap").json()
    started = client.post(
        "/api/runs",
        json={
            "project_id": demo["project"]["id"],
            "app_id": demo["app"]["id"],
            "device_id": "mock-android-01",
            "device_adapter": "mock",
            "proxy_adapter": "mock",
            "pause_for_login": True,
        },
    )
    run_id = started.json()["id"]
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        run = client.get(f"/api/runs/{run_id}").json()
        if run["status"] == "paused":
            break
        time.sleep(0.05)
    assert run["status"] == "paused"
    assert run["current_stage"] == "manual_interaction"

    resumed = client.post(f"/api/runs/{run_id}/resume")
    assert resumed.status_code == 200
    assert _wait_for_run(client, run_id)["status"] == "completed"
