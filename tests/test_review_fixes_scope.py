from __future__ import annotations

import asyncio
import plistlib
import time
import zipfile
from pathlib import Path

import pytest
from sqlalchemy import select

from backend.app.database.models import ControlTest
from backend.app.database.session import SessionLocal
from backend.app.demo import create_demo_apk
from backend.app.network_testing import tls_scan
from backend.app.network_testing.tls_scan import TlsScanError, TlsTarget, pin_targets


def _wait(client, run_id: str) -> dict:
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        run = client.get(f"/api/runs/{run_id}").json()
        if run["status"] in {"completed", "completed_with_gaps", "manual_required", "failed"}:
            return run
        time.sleep(0.05)
    raise AssertionError("Mock Run timeout")


def _project(client, name: str, profile: str = "electronic_financial") -> dict:
    return client.post(
        "/api/projects",
        json={"name": name, "run_mode": "mock", "assessment_profile": profile, "ai_enabled": False},
    ).json()


def _upload_apk(client, project_id: str, tmp_path: Path) -> dict:
    apk = create_demo_apk(tmp_path / f"{project_id}.apk")
    with apk.open("rb") as stream:
        return client.post(
            f"/api/projects/{project_id}/apps/upload",
            files={"file": (apk.name, stream, "application/vnd.android.package-archive")},
        ).json()


def _upload_ipa(client, project_id: str, tmp_path: Path) -> dict:
    ipa = tmp_path / f"{project_id}.ipa"
    with zipfile.ZipFile(ipa, "w") as archive:
        archive.writestr(
            "Payload/Demo.app/Info.plist",
            plistlib.dumps({"CFBundleIdentifier": "com.example.msw.ios", "CFBundleDisplayName": "MSW iOS"}),
        )
        archive.writestr("Payload/Demo.app/Demo", b"\xcf\xfa\xed\xfe")
    with ipa.open("rb") as stream:
        return client.post(
            f"/api/projects/{project_id}/apps/upload",
            files={"file": (ipa.name, stream, "application/octet-stream")},
        ).json()


def test_stale_baseline_policy_is_realigned_before_run_seeding(client, tmp_path):
    project = _project(client, "기준선 정책 갱신")
    app = _upload_apk(client, project["id"], tmp_path)
    stale = [["network_capture", "network_test", "manual_proxy_import"]]
    with SessionLocal() as db:
        row = db.scalar(
            select(ControlTest).where(
                ControlTest.app_id == app["id"],
                ControlTest.run_id.is_(None),
                ControlTest.mastg_id == "EFI-MA-41",
            )
        )
        row.evidence_requirements = stale
        row.automation = "manual"
        db.commit()
    started = client.post(
        "/api/runs",
        json={
            "project_id": project["id"],
            "app_id": app["id"],
            "device_id": "mock-android-01",
            "device_adapter": "mock",
            "proxy_adapter": "mock",
        },
    ).json()
    run = _wait(client, started["id"])
    rows = client.get(
        f"/api/coverage?run_id={run['id']}&scope=run&standard=electronic_financial"
    ).json()["tests"]
    efi41 = next(item for item in rows if item["control_id"] == "EFI-MA-41")
    assert efi41["evidence_requirements"] == [["tls_scan", "manual_assessment_attachment"]]
    assert efi41["automation"] == "hybrid"
    scan = client.post(f"/api/runs/{run['id']}/tls-scan", json={"targets": ["api.mock.test"]})
    assert scan.status_code == 200
    again = client.post(f"/api/runs/{run['id']}/tls-scan", json={"targets": ["api.mock.test"]})
    assert again.status_code == 200
    rows = client.get(
        f"/api/coverage?run_id={run['id']}&scope=run&standard=electronic_financial"
    ).json()["tests"]
    assert next(item for item in rows if item["control_id"] == "EFI-MA-41")["result"] == "confirmed"


def test_deleted_custom_ids_are_never_reused(client):
    project = _project(client, "예외 검사 ID 보존", "critical_infrastructure")
    base = f"/api/projects/{project['id']}/custom-controls"
    payload = {
        "title": "검사",
        "criteria": ["조건"],
        "reason": "고객 요청",
        "recorded_by": "reviewer",
    }
    assert client.post(base, json={**payload, "title": "검사 하나"}).json()["control_id"] == "CUS-MA-01"
    assert client.post(base, json={**payload, "title": "검사 둘"}).json()["control_id"] == "CUS-MA-02"
    assert client.delete(f"{base}/CUS-MA-02").status_code == 200
    assert client.post(base, json={**payload, "title": "검사 셋"}).json()["control_id"] == "CUS-MA-03"
    scope = client.get(f"/api/projects/{project['id']}/assessment-scope").json()
    assert [item["control_id"] for item in scope["custom"]] == ["CUS-MA-01", "CUS-MA-03"]


def test_resigned_ipa_option_is_validated_at_run_creation(client, tmp_path):
    project = _project(client, "재서명 옵션 검증", "critical_infrastructure")
    android = _upload_apk(client, project["id"], tmp_path)
    base = {
        "project_id": project["id"],
        "app_id": android["id"],
        "device_id": "mock-android-01",
        "device_adapter": "mock",
        "proxy_adapter": "mock",
    }
    assert client.post("/api/runs", json={**base, "options": {"use_resigned_ipa": "false"}}).status_code == 422
    assert client.post("/api/runs", json={**base, "options": {"use_resigned_ipa": True}}).status_code == 422


def test_resign_record_survives_reanalysis(client, tmp_path):
    project = _project(client, "재서명 기록 보존", "critical_infrastructure")
    app = _upload_ipa(client, project["id"], tmp_path)
    signed = client.post(
        f"/api/apps/{app['id']}/ios/resign",
        json={"requested_by": "tester", "confirm_original_sha256": app["sha256"]},
    )
    assert signed.status_code == 200
    reanalyzed = client.post(f"/api/apps/{app['id']}/reanalyze", json={})
    assert reanalyzed.status_code == 200
    record = reanalyzed.json()["analysis_result"]["ios_resigned"]
    assert record["id"] == signed.json()["id"]


def test_tls_targets_are_pinned_to_one_resolved_address(monkeypatch):
    targets = asyncio.run(pin_targets([TlsTarget("192.0.2.10", 443)]))
    assert targets[0].sslyze_target == "192.0.2.10:443"

    async def fake_getaddrinfo(host, port, **kwargs):
        if host == "loop.example.test":
            return [(2, 1, 6, "", ("127.0.0.1", port))]
        return [(2, 1, 6, "", ("198.51.100.7", port)), (2, 1, 6, "", ("198.51.100.5", port))]

    class FakeLoop:
        getaddrinfo = staticmethod(fake_getaddrinfo)

    monkeypatch.setattr(tls_scan.asyncio, "get_running_loop", lambda: FakeLoop())
    pinned = asyncio.run(pin_targets([TlsTarget("api.example.test", 8443)]))
    assert pinned[0].sslyze_target == "api.example.test:8443{198.51.100.5}"
    with pytest.raises(TlsScanError):
        asyncio.run(pin_targets([TlsTarget("loop.example.test", 443)]))
