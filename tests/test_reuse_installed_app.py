from __future__ import annotations

import time

from backend.app.core.command import CommandResult
from backend.app.core.status import CapabilityStatus
from backend.app.devices.ios import IOSDeviceAdapter


def _wait(client, run_id: str, timeout: float = 45):
    deadline = time.monotonic() + timeout
    run: dict = {}
    while time.monotonic() < deadline:
        run = client.get(f"/api/runs/{run_id}").json()
        if run["status"] in {"completed", "completed_with_gaps", "failed", "stopped", "manual_required"}:
            return run
        time.sleep(0.05)
    raise AssertionError(f"run did not finish: {run.get('status')} {run.get('current_stage')}")


def test_reuse_installed_app_skips_install_when_bundle_is_present(client):
    demo = client.post("/api/demo/bootstrap").json()
    conflict = client.post(
        "/api/runs",
        json={
            "project_id": demo["project"]["id"],
            "app_id": demo["app"]["id"],
            "device_id": "mock-android-01",
            "device_adapter": "mock",
            "proxy_adapter": "mock",
            "options": {"reuse_installed_app": True, "use_resigned_ipa": True},
        },
    )
    assert conflict.status_code == 422
    started = client.post(
        "/api/runs",
        json={
            "project_id": demo["project"]["id"],
            "app_id": demo["app"]["id"],
            "device_id": "mock-android-01",
            "device_adapter": "mock",
            "proxy_adapter": "mock",
            "options": {"reuse_installed_app": True, "auto_navigation": False, "dynamic_storage": False, "background_screen_check": False},
        },
    )
    assert started.status_code == 201
    assert started.json()["options"]["reuse_installed_app"] is True
    run = _wait(client, started.json()["id"])
    # The Mock device does not list the demo package, so the upload is installed as usual.
    assert run["status"] == "completed", run.get("error")
    assert "install" not in run["options"] or run["options"]["install"].get("status") != "reused_installed"
    titles = [item["title"] for item in client.get(f"/api/runs/{run['id']}/evidence").json()]
    assert "설치된 앱 재사용 확인 실패" in titles
    assert "앱 설치" in titles


def test_ios_failure_summary_extracts_final_error_line():
    stderr = (
        "2026-10-14 INFO 40% Complete\n"
        "╭───── Traceback ─────╮\n"
        "│ /x/installation_proxy.py:92 in _watch_completion │\n"
        "╰─────────────────────╯\n"
        "AppInstallError: ApplicationVerificationFailed: Failed to verify code signature\n"
        "of /var/installd/... (A valid provisioning profile for this executable was not found.)\n"
    )
    result = CommandResult(status=CapabilityStatus.FAILED, command=["pymobiledevice3"], return_code=1, stderr=stderr)
    summary = IOSDeviceAdapter._failure_summary(result)
    assert summary.startswith("AppInstallError: ApplicationVerificationFailed")
    assert "│" not in summary
    plain = CommandResult(status=CapabilityStatus.FAILED, command=["x"], return_code=1, stderr="2026-10-14 host pymobiledevice3.__main__[1] ERROR Failed to connect to service port.")
    assert "Failed to connect to service port" in IOSDeviceAdapter._failure_summary(plain)
