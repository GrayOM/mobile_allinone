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
    assert run["run_mode"] == "mock"
    assert run["synthetic"] is True

    evidence = client.get(f"/api/runs/{run['id']}/evidence").json()
    flows = client.get(f"/api/runs/{run['id']}/flows").json()
    findings = client.get(f"/api/findings?run_id={run['id']}").json()

    assert len(evidence) >= 10
    assert {"screenshot", "network_capture", "device_log"} <= {
        item["evidence_type"] for item in evidence
    }
    assert not any(item["evidence_type"] == "frida_script" for item in evidence)
    assert len(flows) == 2
    assert all(item["synthetic"] is True for item in evidence)
    assert all(item["synthetic"] is True for item in flows)
    assert findings and findings[0]["source"] == "ai:mock"
    assert findings[0]["synthetic"] is True
    sources = client.get(f"/api/findings/{findings[0]['id']}/sources").json()
    assert sources[0]["evidence_ids"]

    report = client.post(f"/api/findings/{findings[0]['id']}/report")
    assert report.status_code == 200
    html = client.get(report.json()["url"])
    assert html.status_code == 200
    assert "증적 설명서" in html.text
    assert "SYNTHETIC MOCK" in html.text
    assert "원본 파일 내려받기" in html.text

    deleted = client.delete(f"/api/projects/{demo['project']['id']}")
    assert deleted.status_code == 200
    assert deleted.json()["recoverable"] is False
    assert client.get(f"/api/projects/{demo['project']['id']}").status_code == 404


def test_custom_frida_script_requires_approval(client):
    demo = client.post("/api/demo/bootstrap").json()
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
    ).json()
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        paused = client.get(f"/api/runs/{started['id']}").json()
        if paused["status"] == "safely_paused":
            break
        time.sleep(0.05)
    assert paused["status"] == "safely_paused"
    approval = client.post(
        "/api/approvals",
        json={
            "project_id": demo["project"]["id"],
            "run_id": started["id"],
            "resource_type": "frida",
            "action": f"execute:{script['id']}",
        },
    ).json()
    executed = client.post(
        f"/api/frida/scripts/{script['id']}/execute",
        json={
            "project_id": demo["project"]["id"],
            "run_id": started["id"],
            "approval_token": approval["token"],
        },
    )
    assert executed.status_code == 200
    assert executed.json()["status"] == "available"
    assert executed.json()["evidence_id"]
    assert client.post(f"/api/runs/{started['id']}/stop").status_code == 200
    refreshed = next(
        item
        for item in client.get("/api/frida/scripts").json()
        if item["id"] == script["id"]
    )
    assert refreshed["success_count"] == script["success_count"]


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
        if run["status"] == "safely_paused":
            break
        time.sleep(0.05)
    assert run["status"] == "safely_paused"
    assert run["current_stage"] == "manual_interaction"

    resumed = client.post(f"/api/runs/{run_id}/resume")
    assert resumed.status_code == 200
    assert _wait_for_run(client, run_id)["status"] == "completed"
