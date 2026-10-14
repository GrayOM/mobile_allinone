from __future__ import annotations

import io
import re
import time
import zipfile

from backend.app.catalog import STANDARD_CONTROLS
from backend.app.catalog.guidance import guidance_for, guidance_source
from backend.app.demo import create_demo_apk

import pytest

LOCAL_GUIDANCE = guidance_source()["available"]
requires_local_guidance = pytest.mark.skipif(
    not LOCAL_GUIDANCE,
    reason="advisory guidance is generated locally from customer DOCX files and is not committed",
)


def _wait_for_run(client, run_id: str, timeout: float = 30) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        run = client.get(f"/api/runs/{run_id}").json()
        if run["status"] in {"completed", "completed_with_gaps", "manual_required", "failed"}:
            return run
        time.sleep(0.05)
    raise AssertionError("Mock Run이 제한 시간 안에 끝나지 않았습니다.")


def _normalize(value: str) -> str:
    return re.sub(r"[\s()\[\]·]", "", value).lower()


@requires_local_guidance
def test_every_catalog_item_has_matching_document_guidance():
    source = guidance_source()
    assert source["control_count"] == 83
    for control in STANDARD_CONTROLS:
        guidance = guidance_for(control.profile, control.control_id)
        assert guidance is not None, control.control_id
        assert _normalize(guidance["title"]) == _normalize(control.title)
        assert guidance["description"], control.control_id
        assert guidance["remediation"], control.control_id
        assert guidance["threats"], control.control_id
        assert guidance["diagnostic_criteria"] or guidance["diagnostic_examples"]


@requires_local_guidance
def test_guidance_endpoint_and_catalog_rows_expose_document_basis(client):
    detail = client.get("/api/assessment/guidance/electronic_financial/EFI-MA-07")
    assert detail.status_code == 200
    body = detail.json()
    assert body["custom"] is False
    assert "루팅" in " ".join(body["description"])
    assert any("Android" in key for key in body["remediation_examples"])
    assert any("iOS" in key for key in body["remediation_examples"])
    assert client.get("/api/assessment/guidance/unknown/EFI-MA-07").status_code == 422
    assert client.get("/api/assessment/guidance/electronic_financial/EFI-MA-99").status_code == 404


def test_tls_items_use_tls_configuration_evaluator(client):
    matrix = client.get("/api/assessment/execution-matrix?profile=electronic_financial").json()
    rows = {
        item["control_id"]: item
        for item in matrix["profiles"]["electronic_financial"]["controls"]
    }
    for control_id in ("EFI-MA-41", "EFI-MA-42", "EFI-MA-43", "EFI-MA-44"):
        assert rows[control_id]["lane"] == "server_scope_required"
        assert rows[control_id]["capability"] == "tls_scan_ready"


def _create_project(client, name: str, profile: str = "critical_infrastructure") -> dict:
    response = client.post(
        "/api/projects",
        json={"name": name, "run_mode": "mock", "assessment_profile": profile, "ai_enabled": False},
    )
    assert response.status_code == 201
    return response.json()


def _custom_payload(**overrides) -> dict:
    payload = {
        "title": "앱 내 결제 웹뷰 외부 도메인 로딩",
        "group": "고객 추가 검사",
        "criteria": ["결제 화면 WebView가 허용 목록 밖 도메인을 로드하면 취약으로 판단한다."],
        "procedure": ["테스트 계정으로 결제 화면까지 이동한다.", "로드 URL과 화면을 캡처한다."],
        "automation": "manual",
        "evaluator": "ui_review",
        "risk": "medium",
        "severity": "medium",
        "platform_scope": "any",
        "finding_categories": ["webview external load"],
        "reference": "고객사 추가 요구사항 2026-10",
        "reason": "선택한 권고안에 없는 고객 요청 검사입니다.",
        "recorded_by": "reviewer-a",
    }
    payload.update(overrides)
    return payload


def test_custom_control_validation_rejects_unsafe_definitions(client):
    project = _create_project(client, "사용자 정의 검사 검증")
    base = f"/api/projects/{project['id']}"
    assert client.post(f"{base}/custom-controls", json=_custom_payload(evaluator="unknown")).status_code == 422
    assert client.post(
        f"{base}/custom-controls",
        json=_custom_payload(automation="static", evaluator="ui_review"),
    ).status_code == 422
    assert client.post(f"{base}/custom-controls", json=_custom_payload(criteria=[])).status_code == 422
    assert client.post(f"{base}/custom-controls", json=_custom_payload(reason="")).status_code == 422
    assert client.put(
        f"{base}/control-exclusions/CII-MA-99",
        json={"reason": "범위에 없는 항목입니다.", "recorded_by": "reviewer-a"},
    ).status_code == 404
    created = client.post(f"{base}/custom-controls", json=_custom_payload())
    assert created.status_code == 201
    assert created.json()["control_id"] == "CUS-MA-01"
    assert client.put(
        f"{base}/control-exclusions/CUS-MA-01",
        json={"reason": "사용자 정의 검사를 제외하려는 시도", "recorded_by": "reviewer-a"},
    ).status_code == 422
    assert client.put(
        f"{base}/control-exclusions/CII-MA-20",
        json={"reason": "짧음", "recorded_by": "reviewer-a"},
    ).status_code == 422


def test_custom_controls_and_exclusions_flow_through_baseline_run_and_report(client, tmp_path):
    project = _create_project(client, "예외 검사 전체 흐름")
    base = f"/api/projects/{project['id']}"

    android_custom = client.post(
        f"{base}/custom-controls", json=_custom_payload(evaluator="manual")
    )
    assert android_custom.status_code == 201
    ios_only = client.post(
        f"{base}/custom-controls",
        json=_custom_payload(
            title="iOS 앱 전환 스냅샷 노출",
            platform_scope="ios",
            evaluator="ui_review",
        ),
    )
    assert ios_only.status_code == 201
    assert ios_only.json()["control_id"] == "CUS-MA-02"
    excluded = client.put(
        f"{base}/control-exclusions/CII-MA-20",
        json={"reason": "고객사 합의로 자동화 공격 점검은 이번 범위에서 제외", "recorded_by": "pm-b"},
    )
    assert excluded.status_code == 200

    apk = create_demo_apk(tmp_path / "scope-demo.apk")
    with apk.open("rb") as stream:
        upload = client.post(
            f"{base}/apps/upload",
            files={"file": (apk.name, stream, "application/vnd.android.package-archive")},
        )
    assert upload.status_code == 201
    app = upload.json()

    baseline = client.get(
        f"/api/coverage?app_id={app['id']}&standard=critical_infrastructure"
    ).json()["tests"]
    by_id = {item["control_id"]: item for item in baseline}
    assert len(baseline) == 28
    assert "CUS-MA-01" in by_id and "CUS-MA-02" not in by_id
    custom_row = by_id["CUS-MA-01"]
    assert custom_row["custom"] is True
    assert custom_row["evidence_requirements"] == [["manual_assessment_attachment"]]
    assert custom_row["finding_categories"] == ["webview_external_load"]
    assert custom_row["execution"]["lane"] == "server_scope_required"
    assert by_id["CII-MA-20"]["status"] == "excluded"
    assert by_id["CII-MA-20"]["result"] == "not_applicable"
    assert by_id["CII-MA-20"]["excluded"] is True
    if LOCAL_GUIDANCE:
        assert by_id["CII-MA-22"]["guidance"]["available"] is True
    else:
        assert by_id["CII-MA-22"]["guidance"] is None

    plan = client.get(f"/api/apps/{app['id']}/assessment/plan").json()
    plan_rows = {item["control_id"]: item for item in plan["controls"]}
    assert plan["total"] == 28
    assert plan_rows["CII-MA-20"]["queue_status"] == "excluded"
    assert plan_rows["CUS-MA-01"]["custom"] is True
    assert "scope_sha256" in plan

    scope = client.get(f"{base}/assessment-scope").json()
    assert scope["catalog_total"] == 27
    assert scope["excluded_total"] == 1
    assert scope["custom_total"] == 2
    assert scope["effective_total"] == 28
    assert any(item["key"] == "tls_configuration" for item in scope["options"]["evaluators"])

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
    run = _wait_for_run(client, started.json()["id"])
    assert run["status"] in {"completed", "completed_with_gaps"}
    assert run["options"]["assessment_summary"]["total"] == 28

    ledger = client.get(
        f"/api/coverage?run_id={run['id']}&scope=run&standard=critical_infrastructure"
    ).json()["tests"]
    run_rows = {item["control_id"]: item for item in ledger}
    assert run_rows["CII-MA-20"]["status"] == "excluded"
    assert run_rows["CUS-MA-01"]["result"] != "confirmed"

    blocked = client.post(
        f"/api/assessment-controls/{run_rows['CII-MA-20']['id']}/record",
        json={
            "outcome": "confirmed",
            "reviewer": "reviewer-a",
            "summary": "범위 제외 항목 판정 시도",
            "criteria_confirmed": True,
        },
    )
    assert blocked.status_code == 409

    missing_evidence = client.post(
        f"/api/assessment-controls/{run_rows['CUS-MA-01']['id']}/record",
        json={
            "outcome": "confirmed",
            "reviewer": "reviewer-a",
            "summary": "증적 없이 확정 시도",
            "criteria_confirmed": True,
        },
    )
    assert missing_evidence.status_code == 422

    attachment = client.post(
        f"/api/assessment-controls/{run_rows['CUS-MA-01']['id']}/evidence",
        files={"file": ("webview.txt", io.BytesIO(b"synthetic webview proof"), "text/plain")},
    )
    assert attachment.status_code == 200
    recorded = client.post(
        f"/api/assessment-controls/{run_rows['CUS-MA-01']['id']}/record",
        json={
            "outcome": "confirmed",
            "reviewer": "reviewer-a",
            "summary": "결제 WebView가 허용 목록 밖 도메인을 로드한 합성 증적을 확인했습니다.",
            "evidence_ids": [attachment.json()["evidence_id"]],
            "criteria_confirmed": True,
        },
    )
    assert recorded.status_code == 200
    assert recorded.json()["result"] == "confirmed"
    assert recorded.json()["finding_ids"]

    report = client.post(f"/api/runs/{run['id']}/report/docx")
    assert report.status_code == 200
    downloaded = client.get(f"/api/runs/{run['id']}/report/docx")
    with zipfile.ZipFile(io.BytesIO(downloaded.content)) as archive:
        document_xml = archive.read("word/document.xml").decode("utf-8")
    assert "CUS-MA-01" in document_xml
    assert "기준 외 사용자 정의 검사" in document_xml

    in_use = client.delete(f"{base}/custom-controls/CUS-MA-01")
    assert in_use.status_code == 409
    unused = client.delete(f"{base}/custom-controls/CUS-MA-02")
    assert unused.status_code == 200

    disabled = client.patch(f"{base}/custom-controls/CUS-MA-01", json={"enabled": False})
    assert disabled.status_code == 200
    restored = client.delete(f"{base}/control-exclusions/CII-MA-20")
    assert restored.status_code == 200
    refreshed = client.get(
        f"/api/coverage?app_id={app['id']}&standard=critical_infrastructure"
    ).json()["tests"]
    refreshed_ids = {item["control_id"]: item for item in refreshed}
    assert len(refreshed) == 27
    assert "CUS-MA-01" not in refreshed_ids
    assert refreshed_ids["CII-MA-20"]["status"] != "excluded"

    history = client.get(
        f"/api/coverage?run_id={run['id']}&scope=run&standard=critical_infrastructure"
    ).json()["tests"]
    history_ids = {item["control_id"]: item for item in history}
    assert history_ids["CUS-MA-01"]["result"] == "confirmed"
    assert history_ids["CII-MA-20"]["status"] == "excluded"
    custom_guidance = client.get(
        f"/api/assessment/guidance/critical_infrastructure/CUS-MA-01?project_id={project['id']}"
    )
    assert custom_guidance.status_code == 200
    assert custom_guidance.json()["custom"] is True


def test_guidance_endpoint_reports_missing_local_file_without_failing(client):
    source = client.get("/api/assessment/guidance").json()
    assert source["available"] is LOCAL_GUIDANCE
    response = client.get("/api/assessment/guidance/electronic_financial/EFI-MA-07")
    assert response.status_code == (200 if LOCAL_GUIDANCE else 404)
