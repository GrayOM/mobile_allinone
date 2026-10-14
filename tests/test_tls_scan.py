from __future__ import annotations

import copy
import json
import time
from pathlib import Path

import pytest

from backend.app.demo import create_demo_apk
from backend.app.network_testing.tls_scan import (
    TLS_ANY_KEY,
    TlsScanError,
    parse_sslyze_payload,
    parse_targets,
)

FIXTURE = Path(__file__).parent / "fixtures" / "sslyze_loopback_6_3_1.json"


def _fixture() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def _suite(name: str) -> dict:
    return {"cipher_suite": {"name": name}}


def test_real_sslyze_output_is_parsed_into_document_decisions():
    servers, controls = parse_sslyze_payload(_fixture())
    assert len(servers) == 1
    server = servers[0]
    assert server["host"] == "127.0.0.1"
    assert server["protocols"]["TLS 1.2"] is True
    assert server["heartbleed"] is False
    assert server["ccs_injection"] is False
    assert server["renegotiation"]["supports_secure_renegotiation"] is True
    assert set(controls) == {"EFI-MA-41", "EFI-MA-42", "EFI-MA-43", "EFI-MA-44", TLS_ANY_KEY}
    assert controls["EFI-MA-43"]["vulnerable"] is False
    assert controls["EFI-MA-44"]["vulnerable"] is False
    assert all(item["complete"] for item in controls.values())


def test_document_rules_flag_insecure_but_not_weak_configuration():
    payload = _fixture()
    result = payload["server_scan_results"][0]["scan_result"]
    weak_only = copy.deepcopy(payload)
    weak_result = weak_only["server_scan_results"][0]["scan_result"]
    weak_result["tls_1_0_cipher_suites"]["result"]["accepted_cipher_suites"] = []
    weak_result["tls_1_1_cipher_suites"]["result"]["accepted_cipher_suites"] = []
    weak_result["tls_1_2_cipher_suites"]["result"]["accepted_cipher_suites"] = [
        _suite("TLS_RSA_WITH_3DES_EDE_CBC_SHA"),
        _suite("TLS_RSA_WITH_AES_128_CBC_SHA"),
    ]
    _, weak_controls = parse_sslyze_payload(weak_only)
    assert weak_controls["EFI-MA-41"]["vulnerable"] is False
    assert weak_controls["EFI-MA-42"]["vulnerable"] is False
    assert weak_controls["EFI-MA-42"]["observations"]

    result["ssl_3_0_cipher_suites"]["result"]["accepted_cipher_suites"] = [
        _suite("TLS_RSA_WITH_RC4_128_SHA")
    ]
    result["tls_1_0_cipher_suites"]["result"]["accepted_cipher_suites"] = [
        _suite("TLS_RSA_EXPORT_WITH_RC4_40_MD5")
    ]
    result["heartbleed"]["result"]["is_vulnerable_to_heartbleed"] = True
    result["session_renegotiation"]["result"] = {
        "supports_secure_renegotiation": False,
        "is_vulnerable_to_client_renegotiation_dos": True,
    }
    _, controls = parse_sslyze_payload(payload)
    assert controls["EFI-MA-41"]["vulnerable"] is True
    assert any("SSL 3.0" in item for item in controls["EFI-MA-41"]["reasons"])
    assert controls["EFI-MA-42"]["vulnerable"] is True
    reasons_43 = " ".join(controls["EFI-MA-43"]["reasons"])
    assert "Heartbleed" in reasons_43 and "POODLE" in reasons_43 and "FREAK" in reasons_43
    assert controls["EFI-MA-44"]["vulnerable"] is True
    assert controls[TLS_ANY_KEY]["vulnerable"] is True


def test_incomplete_plugins_are_not_reported_as_secure():
    payload = _fixture()
    result = payload["server_scan_results"][0]["scan_result"]
    result["heartbleed"] = {"status": "ERROR", "result": None}
    result["session_renegotiation"] = {"status": "ERROR", "result": None}
    _, controls = parse_sslyze_payload(payload)
    assert controls["EFI-MA-43"]["complete"] is False
    assert controls["EFI-MA-44"]["complete"] is False


def test_targets_are_restricted_to_the_approved_host_scope():
    allowed = ["api.example.test", "*.bank.example.test"]
    targets = parse_targets(["api.example.test", "pay.bank.example.test:8443"], allowed)
    assert [item.display for item in targets] == ["api.example.test:443", "pay.bank.example.test:8443"]
    with pytest.raises(TlsScanError) as outside:
        parse_targets(["other.example.test"], allowed)
    assert outside.value.status_code == 403
    with pytest.raises(TlsScanError):
        parse_targets(["https://api.example.test/path"], allowed)
    with pytest.raises(TlsScanError):
        parse_targets(["*.bank.example.test"], allowed)
    with pytest.raises(TlsScanError):
        parse_targets(["api.example.test:70000"], allowed)
    with pytest.raises(TlsScanError):
        parse_targets([f"h{i}.bank.example.test" for i in range(6)], allowed)


def _wait_for_run(client, run_id: str, timeout: float = 30) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        run = client.get(f"/api/runs/{run_id}").json()
        if run["status"] in {"completed", "completed_with_gaps", "manual_required", "failed"}:
            return run
        time.sleep(0.05)
    raise AssertionError("Mock Run이 제한 시간 안에 끝나지 않았습니다.")


def _mock_run(client, tmp_path, profile: str, name: str) -> tuple[dict, dict]:
    project = client.post(
        "/api/projects",
        json={"name": name, "run_mode": "mock", "assessment_profile": profile, "ai_enabled": False},
    ).json()
    if profile == "critical_infrastructure":
        created = client.post(
            f"/api/projects/{project['id']}/custom-controls",
            json={
                "title": "모바일 API 서버 TLS 구성",
                "criteria": ["모바일 API 서버가 취약한 TLS 구성을 허용하면 취약으로 판단한다."],
                "automation": "hybrid",
                "evaluator": "tls_configuration",
                "reason": "주요정보통신기반시설 기준에 별도 TLS 구성 항목이 없어 추가합니다.",
                "recorded_by": "reviewer-a",
            },
        )
        assert created.status_code == 201
    apk = create_demo_apk(tmp_path / f"{name}.apk")
    with apk.open("rb") as stream:
        app = client.post(
            f"/api/projects/{project['id']}/apps/upload",
            files={"file": (apk.name, stream, "application/vnd.android.package-archive")},
        ).json()
    started = client.post(
        "/api/runs",
        json={
            "project_id": project["id"],
            "app_id": app["id"],
            "device_id": "mock-android-01",
            "device_adapter": "mock",
            "proxy_adapter": "mock",
        },
    )
    assert started.status_code == 201
    return project, _wait_for_run(client, started.json()["id"])


def test_mock_tls_scan_records_synthetic_evidence_and_confirms_only_flagged_items(client, tmp_path):
    _, run = _mock_run(client, tmp_path, "electronic_financial", "tls-efi")
    rejected = client.post(f"/api/runs/{run['id']}/tls-scan", json={"targets": ["https://x.test/"]})
    assert rejected.status_code == 422
    response = client.post(f"/api/runs/{run['id']}/tls-scan", json={"targets": ["api.mock.test"]})
    assert response.status_code == 200
    body = response.json()
    assert body["synthetic"] is True
    assert body["confirmed_controls"] == ["EFI-MA-41"]
    assert body["control_results"]["EFI-MA-42"]["vulnerable"] is False

    ledger = client.get(
        f"/api/coverage?run_id={run['id']}&scope=run&standard=electronic_financial"
    ).json()["tests"]
    rows = {item["control_id"]: item for item in ledger}
    assert rows["EFI-MA-41"]["result"] == "confirmed"
    assert body["evidence_id"] in rows["EFI-MA-41"]["evidence_ids"]
    assert rows["EFI-MA-42"]["result"] != "confirmed"
    evidence = client.get(f"/api/runs/{run['id']}/evidence").json()
    tls = next(item for item in evidence if item["id"] == body["evidence_id"])
    assert tls["evidence_type"] == "tls_scan"
    assert tls["synthetic"] is True


def test_custom_tls_control_uses_aggregate_tls_result(client, tmp_path):
    _, run = _mock_run(client, tmp_path, "critical_infrastructure", "tls-cii")
    response = client.post(f"/api/runs/{run['id']}/tls-scan", json={"targets": ["api.mock.test"]})
    assert response.status_code == 200
    assert response.json()["confirmed_controls"] == ["CUS-MA-01"]
