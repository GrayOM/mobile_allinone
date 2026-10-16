from __future__ import annotations

import io
import time
import zipfile

from backend.app.catalog.korean_standards import (
    CRITICAL_INFRASTRUCTURE_CONTROLS,
    DOMESTIC_ALL,
    ELECTRONIC_FINANCIAL_CONTROLS,
    controls_for_profile,
)
from backend.app.demo import create_demo_apk
from backend.app.database.models import AIInvocation, ControlTest, DiagnosticRun
from backend.app.database.session import SessionLocal


def _wait_for_run(client, run_id: str, timeout: float = 30) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        run = client.get(f"/api/runs/{run_id}").json()
        if run["status"] in {
            "completed",
            "completed_with_gaps",
            "manual_required",
            "failed",
        }:
            return run
        time.sleep(0.05)
    raise AssertionError("국내 기준 Mock Run이 제한 시간 안에 끝나지 않았습니다.")


def _wait_for_assessment_gate(client, run_id: str, timeout: float = 30) -> dict:
    deadline = time.monotonic() + timeout
    current: dict = {}
    while time.monotonic() < deadline:
        current = client.get(f"/api/runs/{run_id}").json()
        if (
            current.get("status") == "safely_paused"
            and current.get("current_stage") == "assessment_completion"
        ):
            return current
        if current.get("status") in {"failed", "stopped", "interrupted"}:
            break
        time.sleep(0.05)
    raise AssertionError(
        f"판정 완료 게이트에 도달하지 못했습니다: "
        f"{current.get('status')} {current.get('current_stage')}"
    )


def test_domestic_catalogs_preserve_document_item_counts_and_ids():
    assert len(CRITICAL_INFRASTRUCTURE_CONTROLS) == 27
    assert len(ELECTRONIC_FINANCIAL_CONTROLS) == 56
    assert CRITICAL_INFRASTRUCTURE_CONTROLS[21].title == "OS 변조 탐지 기능 적용 여부"
    assert ELECTRONIC_FINANCIAL_CONTROLS[53].title == "모바일 DeepLink 도용 취약점"
    ids = {
        item.control_id
        for item in (*CRITICAL_INFRASTRUCTURE_CONTROLS, *ELECTRONIC_FINANCIAL_CONTROLS)
    }
    assert len(ids) == 83
    assert all(item.criteria for item in ELECTRONIC_FINANCIAL_CONTROLS)
    assert all(item.evidence_requirements for item in CRITICAL_INFRASTRUCTURE_CONTROLS)
    assert len(controls_for_profile(DOMESTIC_ALL)) == 83
    assert {item.control_id for item in controls_for_profile(DOMESTIC_ALL)} == ids


def test_execution_matrix_separates_ready_and_device_deferred_controls(client):
    response = client.get("/api/assessment/execution-matrix")
    assert response.status_code == 200
    matrix = response.json()
    assert matrix["total"] == 83
    assert matrix["ready_without_device"] + matrix["device_deferred"] == 83
    critical = matrix["profiles"]["critical_infrastructure"]
    financial = matrix["profiles"]["electronic_financial"]
    assert critical["total"] == 27
    assert financial["total"] == 56
    root = next(
        item for item in critical["controls"] if item["control_id"] == "CII-MA-22"
    )
    obfuscation = next(
        item for item in critical["controls"] if item["control_id"] == "CII-MA-23"
    )
    assert root["lane"] == "device_required"
    assert root["device_required"] is True
    assert obfuscation["lane"] == "ready_now"
    assert obfuscation["device_required"] is False


def test_app_assessment_plan_is_generated_and_never_auto_confirms(client):
    demo = client.post("/api/demo/bootstrap").json()
    app = demo["app"]
    stored = app["analysis_result"]["assessment_plan"]
    assert stored["version"] == 1
    assert stored["artifact_sha256"] == app["sha256"]
    assert stored["assessment_profile"] == "critical_infrastructure"
    assert stored["total"] == 27
    assert stored["lane_counts"] == {
        "server_scope_required": 20,
        "ready_now": 2,
        "device_required": 5,
    }
    assert stored["ready_now_total"] == 2
    assert stored["ready_now_screened"] == 2

    controls = {item["control_id"]: item for item in stored["controls"]}
    assert controls["CII-MA-05"]["queue_status"] == "candidate_detected"
    assert controls["CII-MA-05"]["candidate_count"] > 0
    assert controls["CII-MA-23"]["queue_status"] == "review_ready"
    assert controls["CII-MA-22"]["queue_status"] == "waiting_device"
    assert "authorized_physical_device" in controls["CII-MA-22"]["blockers"]
    assert controls["CII-MA-01"]["queue_status"] == "waiting_server_scope"
    assert "approved_test_server_scope" in controls["CII-MA-01"]["blockers"]

    response = client.get(f"/api/apps/{app['id']}/assessment/plan")
    assert response.status_code == 200
    assert response.json()["artifact_sha256"] == app["sha256"]
    refreshed = client.post(f"/api/apps/{app['id']}/assessment/plan/refresh")
    assert refreshed.status_code == 200
    assert refreshed.json()["generated_by"] == "local_deterministic_policy"

    coverage = client.get(
        f"/api/coverage?app_id={app['id']}&standard=critical_infrastructure"
    ).json()
    assert coverage["result_counts"].get("confirmed", 0) == 0
    assert coverage["result_counts"].get("not_vulnerable", 0) == 0
    ready = {
        item["control_id"]: item
        for item in coverage["tests"]
        if item["execution"]["lane"] == "ready_now"
    }
    assert ready["CII-MA-05"]["result"] == "needs_review"
    assert ready["CII-MA-23"]["result"] == "not_tested"
    assert "양호 판정이 아니며" in ready["CII-MA-23"]["summary"]


def test_project_profile_seeds_only_selected_domestic_baseline(client, tmp_path):
    profiles = client.get("/api/assessment/profiles")
    assert profiles.status_code == 200
    assert {item["item_count"] for item in profiles.json()} == {0, 27, 56, 83}

    project = client.post(
        "/api/projects",
        json={
            "name": "전자금융 기준 Mock",
            "run_mode": "mock",
            "assessment_profile": "electronic_financial",
            "ai_enabled": False,
        },
    )
    assert project.status_code == 201
    project_id = project.json()["id"]
    apk = create_demo_apk(tmp_path / "assessment-demo.apk")
    with apk.open("rb") as stream:
        upload = client.post(
            f"/api/projects/{project_id}/apps/upload",
            files={"file": (apk.name, stream, "application/vnd.android.package-archive")},
        )
    assert upload.status_code == 201
    app_id = upload.json()["id"]
    app_plan = upload.json()["analysis_result"]["assessment_plan"]
    assert app_plan["assessment_profile"] == "electronic_financial"
    assert app_plan["total"] == 56
    assert app_plan["ready_now_total"] == 2
    assert app_plan["ready_now_screened"] == 2

    electronic = client.get(
        f"/api/coverage?app_id={app_id}&standard=electronic_financial"
    ).json()
    critical = client.get(
        f"/api/coverage?app_id={app_id}&standard=critical_infrastructure"
    ).json()
    assert electronic["total_catalog"] == 56
    assert len(electronic["tests"]) == 56
    assert not critical["tests"]
    assert all(item["standard"] == "electronic_financial" for item in electronic["tests"])
    assert all(item["result"] != "confirmed" for item in electronic["tests"])

    immutable = client.patch(
        f"/api/projects/{project_id}",
        json={"assessment_profile": "critical_infrastructure"},
    )
    assert immutable.status_code == 409


def test_combined_domestic_profile_seeds_all_83_controls(client, tmp_path):
    project = client.post(
        "/api/projects",
        json={
            "name": "국내 기준 83개 전수 진단",
            "run_mode": "mock",
            "ai_enabled": False,
        },
    )
    assert project.status_code == 201
    assert project.json()["assessment_profile"] == "domestic_all"
    apk = create_demo_apk(tmp_path / "domestic-all.apk")
    with apk.open("rb") as stream:
        uploaded = client.post(
            f"/api/projects/{project.json()['id']}/apps/upload",
            files={"file": (apk.name, stream, "application/vnd.android.package-archive")},
        )
    assert uploaded.status_code == 201
    app = uploaded.json()
    assert app["analysis_result"]["assessment_plan"]["assessment_profile"] == "domestic_all"
    assert app["analysis_result"]["assessment_plan"]["total"] == 83

    baseline = client.get(
        f"/api/coverage?app_id={app['id']}&standard=domestic_all"
    ).json()
    assert baseline["total_catalog"] == 83
    assert len(baseline["tests"]) == 83
    ids = {item["control_id"] for item in baseline["tests"]}
    assert "CII-MA-01" in ids and "CII-MA-27" in ids
    assert "EFI-MA-01" in ids and "EFI-MA-56" in ids
    assert {item["standard"] for item in baseline["tests"]} == {"domestic_all"}

    started = client.post(
        "/api/runs",
        json={
            "project_id": project.json()["id"],
            "app_id": app["id"],
            "device_id": "mock-android-01",
            "device_adapter": "mock",
            "proxy_adapter": "mock",
        },
    )
    assert started.status_code == 201
    run = _wait_for_run(client, started.json()["id"])
    assert run["options"]["assessment_profile"] == "domestic_all"
    assert run["options"]["assessment_summary"]["total"] == 83
    ledger = client.get(
        f"/api/coverage?run_id={run['id']}&scope=run&standard=domestic_all"
    ).json()
    assert len(ledger["tests"]) == 83


def test_run_generates_evidence_bound_ledger_and_manual_confirmation(client, tmp_path):
    project = client.post(
        "/api/projects",
        json={
            "name": "전자금융 증적 판정",
            "run_mode": "mock",
            "assessment_profile": "electronic_financial",
            "ai_enabled": False,
        },
    ).json()
    apk = create_demo_apk(tmp_path / "assessment-run.apk")
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
    run = _wait_for_run(client, started.json()["id"])
    assert run["status"] == "completed"
    assert run["options"]["assessment_profile"] == "electronic_financial"
    assert run["options"]["assessment_summary"]["total"] == 56

    ledger = client.get(
        f"/api/coverage?run_id={run['id']}&scope=run&standard=electronic_financial"
    ).json()
    assert len(ledger["tests"]) == 56
    root = next(item for item in ledger["tests"] if item["control_id"] == "EFI-MA-07")
    assert root["result"] == "confirmed"
    assert root["evidence_ids"]
    assert root["finding_ids"]
    evidence = client.get(f"/api/runs/{run['id']}/evidence").json()
    evidence_by_id = {item["id"]: item for item in evidence}
    root_evidence_types = {
        evidence_by_id[item]["evidence_type"] for item in root["evidence_ids"]
    }
    assert root_evidence_types == {"device_state", "command_log", "screenshot"}
    assert len(root["evidence_ids"]) == 3
    assert not any(item["evidence_type"] == "vulnerability_assessment" for item in evidence)

    transaction = next(
        item for item in ledger["tests"] if item["control_id"] == "EFI-MA-01"
    )
    attachment = client.post(
        f"/api/assessment-controls/{transaction['id']}/evidence",
        files={"file": ("transaction-proof.txt", io.BytesIO(b"synthetic proof"), "text/plain")},
    )
    assert attachment.status_code == 200
    attachment_id = attachment.json()["evidence_id"]
    another_manual = next(
        item
        for item in ledger["tests"]
        if item["id"] != transaction["id"]
        and item["evidence_requirements"] == [["manual_assessment_attachment"]]
    )
    reused = client.post(
        f"/api/assessment-controls/{another_manual['id']}/record",
        json={
            "outcome": "confirmed",
            "reviewer": "mock-reviewer",
            "summary": "다른 항목의 첨부 증적을 재사용하려는 시도입니다.",
            "evidence_ids": [attachment_id],
            "criteria_confirmed": True,
        },
    )
    assert reused.status_code == 422
    recorded = client.post(
        f"/api/assessment-controls/{transaction['id']}/record",
        json={
            "outcome": "confirmed",
            "reviewer": "mock-reviewer",
            "summary": "합성 거래 인증 우회 재현 증적을 검토했습니다.",
            "evidence_ids": [attachment_id],
            "criteria_confirmed": True,
        },
    )
    assert recorded.status_code == 200
    assert recorded.json()["result"] == "confirmed"
    assert recorded.json()["finding_ids"]

    blocked_report = client.post(f"/api/runs/{run['id']}/report/docx")
    assert blocked_report.status_code == 409
    assert "미점검·추가 검토" in blocked_report.json()["detail"]

    with SessionLocal() as db:
        controls = db.query(ControlTest).filter_by(
            run_id=run["id"],
            standard="electronic_financial",
        ).all()
        for control in controls:
            if control.result not in {"confirmed", "not_vulnerable", "not_applicable"}:
                control.status = "completed"
                control.result = "not_applicable"
                control.summary = "보고서 게이트 테스트를 위한 명시적 적용 제외 판정입니다."
        db.commit()

    report = client.post(f"/api/runs/{run['id']}/report/docx")
    assert report.status_code == 200
    assert report.json()["policy"] == "complete_assessment_confirmed_vulnerabilities_only"
    downloaded = client.get(f"/api/runs/{run['id']}/report/docx")
    assert downloaded.status_code == 200
    assert downloaded.headers["content-type"].startswith(
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    )
    with zipfile.ZipFile(io.BytesIO(downloaded.content)) as archive:
        document_xml = archive.read("word/document.xml").decode("utf-8")
    assert "OS 변조 탐지 기능 적용 여부" in document_xml
    assert "거래 인증수단 검증 오류" in document_xml
    assert "SQL Injection" not in document_xml
    assert "양호·해당없음·미확정 항목은 수록하지 않습니다" in document_xml


def test_confirmed_manual_result_rejects_missing_evidence(client):
    demo = client.post("/api/demo/bootstrap").json()
    with SessionLocal() as db:
        run = DiagnosticRun(
            project_id=demo["project"]["id"],
            app_id=demo["app"]["id"],
            device_id="mock-android-01",
            device_adapter="mock",
            proxy_adapter="mock",
            run_mode="mock",
            synthetic=True,
            status="completed_with_gaps",
            options={"assessment_profile": "critical_infrastructure"},
        )
        db.add(run)
        db.flush()
        template = db.query(ControlTest).filter_by(
            app_id=demo["app"]["id"],
            run_id=None,
            standard="critical_infrastructure",
        ).first()
        control = ControlTest(
            project_id=run.project_id,
            app_id=run.app_id,
            run_id=run.id,
            mastg_id=template.mastg_id,
            masvs_id=template.masvs_id,
            platform=template.platform,
            title=template.title,
            automation=template.automation,
            status="manual_required",
            result="not_tested",
            standard=template.standard,
            criteria=template.criteria,
            evidence_requirements=template.evidence_requirements,
            finding_categories=template.finding_categories,
            risk=template.risk,
            replacement_ids=[],
            evidence_ids=[],
            finding_ids=[],
            synthetic=True,
        )
        db.add(control)
        db.commit()
        control_id = control.id
        run_id = run.id

    response = client.post(
        f"/api/assessment-controls/{control_id}/record",
        json={
            "outcome": "confirmed",
            "reviewer": "reviewer",
            "summary": "증적 없는 확정을 시도합니다.",
            "criteria_confirmed": True,
        },
    )
    assert response.status_code == 422

    unattested_good = client.post(
        f"/api/assessment-controls/{control_id}/record",
        json={
            "outcome": "not_vulnerable",
            "reviewer": "reviewer",
            "summary": "실제 기준 수행 확인 없이 양호로 넘기려는 시도입니다.",
            "criteria_confirmed": False,
        },
    )
    assert unattested_good.status_code == 422
    assert "진단 기준 수행" in unattested_good.json()["detail"]

    evidence_before = client.get(f"/api/runs/{run_id}/evidence").json()
    good = client.post(
        f"/api/assessment-controls/{control_id}/record",
        json={
            "outcome": "not_vulnerable",
            "reviewer": "reviewer",
            "summary": "진단 기준을 수행했으며 취약 조건이 재현되지 않았습니다.",
            "criteria_confirmed": True,
        },
    )
    assert good.status_code == 200
    assert good.json()["result"] == "not_vulnerable"
    assert good.json()["evidence_ids"] == []
    evidence_after = client.get(f"/api/runs/{run_id}/evidence").json()
    assert len(evidence_after) == len(evidence_before)
    assert client.post(f"/api/runs/{run_id}/report/docx").status_code == 409

    attachment = client.post(
        f"/api/assessment-controls/{control_id}/evidence",
        files={"file": ("review-note.txt", io.BytesIO(b"local review note"), "text/plain")},
    )
    assert attachment.status_code == 200
    evidence_id = attachment.json()["evidence_id"]
    uploaded_evidence = client.get(f"/api/runs/{run_id}/evidence").json()

    not_applicable = client.post(
        f"/api/assessment-controls/{control_id}/record",
        json={
            "outcome": "not_applicable",
            "reviewer": "reviewer",
            "summary": "이 앱에는 해당 기능이 없어 적용 대상이 아닙니다.",
            "evidence_ids": [evidence_id],
            "criteria_confirmed": True,
        },
    )
    assert not_applicable.status_code == 200
    assert not_applicable.json()["result"] == "not_applicable"
    assert not_applicable.json()["evidence_ids"] == []
    final_evidence = client.get(f"/api/runs/{run_id}/evidence").json()
    assert len(final_evidence) == len(uploaded_evidence)
    assert not any(
        item["evidence_type"] == "assessment_attestation"
        and item["inline_data"].get("control_test_id") == control_id
        for item in final_evidence
    )

    review_summary = "실행은 완료했지만 취약 조건 판단에는 추가 재현이 필요합니다."
    needs_review = client.post(
        f"/api/assessment-controls/{control_id}/record",
        json={
            "outcome": "needs_review",
            "reviewer": "reviewer",
            "summary": review_summary,
        },
    )
    assert needs_review.status_code == 200
    assert needs_review.json()["status"] == "completed"
    assert needs_review.json()["result"] == "needs_review"
    assert needs_review.json()["summary"] == review_summary
    assert needs_review.json()["evidence_ids"] == []

    run_coverage = client.get(
        f"/api/coverage?run_id={run_id}&scope=run&standard=critical_infrastructure"
    ).json()
    recorded = next(item for item in run_coverage["tests"] if item["id"] == control_id)
    assert recorded["result"] == "needs_review"
    assert recorded["summary"] == review_summary

    second_attachment = client.post(
        f"/api/assessment-controls/{control_id}/evidence",
        files={"file": ("focused-proof.txt", io.BytesIO(b"focused proof"), "text/plain")},
    )
    assert second_attachment.status_code == 200
    focused_id = second_attachment.json()["evidence_id"]
    first_confirmation = client.post(
        f"/api/assessment-controls/{control_id}/record",
        json={
            "outcome": "confirmed",
            "reviewer": "reviewer",
            "summary": "두 원본을 검토해 취약 조건을 재현했습니다.",
            "evidence_ids": [evidence_id, focused_id],
            "criteria_confirmed": True,
        },
    )
    assert first_confirmation.status_code == 200
    narrowed = client.post(
        f"/api/assessment-controls/{control_id}/record",
        json={
            "outcome": "confirmed",
            "reviewer": "reviewer",
            "summary": "중복 원본을 제외하고 핵심 증적만 다시 선택했습니다.",
            "evidence_ids": [focused_id],
            "criteria_confirmed": True,
        },
    )
    assert narrowed.status_code == 200
    narrowed_ids = narrowed.json()["evidence_ids"]
    assert focused_id in narrowed_ids
    assert evidence_id not in narrowed_ids
    assert len(narrowed_ids) == 2  # 핵심 원본 + 새 판정 확인 원장


def test_required_assessment_stays_blocked_until_last_control_is_terminal(client):
    demo = client.post("/api/demo/bootstrap").json()
    with SessionLocal() as db:
        template = db.query(ControlTest).filter_by(
            app_id=demo["app"]["id"],
            run_id=None,
            standard="critical_infrastructure",
        ).first()
        run = DiagnosticRun(
            project_id=demo["project"]["id"],
            app_id=demo["app"]["id"],
            device_id="mock-android-01",
            device_adapter="mock",
            proxy_adapter="mock",
            run_mode="live",
            synthetic=False,
            status="manual_required",
            current_stage="assessment_completion",
            progress=96,
            options={
                "assessment_profile": "critical_infrastructure",
                "assessment_completion_required": True,
                "quality_gaps": [
                    {
                        "stage": "domestic_assessment",
                        "message": "1개 국내 기준 항목의 점검이 완료되지 않았습니다.",
                    }
                ],
                "failed_required_stages": ["domestic_assessment"],
            },
        )
        db.add(run)
        db.flush()
        control = ControlTest(
            project_id=run.project_id,
            app_id=run.app_id,
            run_id=run.id,
            mastg_id=template.mastg_id,
            masvs_id=template.masvs_id,
            platform=template.platform,
            title=template.title,
            automation=template.automation,
            status="manual_required",
            result="not_tested",
            standard=template.standard,
            criteria=template.criteria,
            evidence_requirements=template.evidence_requirements,
            finding_categories=template.finding_categories,
            risk=template.risk,
            replacement_ids=[],
            evidence_ids=[],
            finding_ids=[],
            synthetic=False,
        )
        db.add(control)
        db.commit()
        run_id = run.id
        control_id = control.id

    blocked = client.post(f"/api/runs/{run_id}/report/docx")
    assert blocked.status_code == 409
    assert "Run이 완료된 뒤" in blocked.json()["detail"]

    recorded = client.post(
        f"/api/assessment-controls/{control_id}/record",
        json={
            "outcome": "not_vulnerable",
            "reviewer": "completion-reviewer",
            "summary": "진단 기준을 수행했으며 취약 조건이 재현되지 않았습니다.",
            "criteria_confirmed": True,
        },
    )
    assert recorded.status_code == 200
    finished = client.get(f"/api/runs/{run_id}").json()
    assert finished["status"] == "completed"
    assert finished["current_stage"] == "completed"
    assert finished["progress"] == 100
    assert finished["options"]["assessment_status"] == "complete"
    assert finished["options"]["assessment_open_items"] == 0
    assert finished["options"]["assessment_gate"]["state"] == "passed"
    assert "domestic_assessment" not in finished["options"]["failed_required_stages"]


def test_required_run_pauses_and_resume_is_server_blocked_until_ledger_complete(client):
    demo = client.post("/api/demo/bootstrap").json()
    started = client.post(
        "/api/runs",
        json={
            "project_id": demo["project"]["id"],
            "app_id": demo["app"]["id"],
            "device_id": "mock-android-01",
            "device_adapter": "mock",
            "proxy_adapter": "mock",
            "options": {"assessment_completion_required": True},
        },
    )
    assert started.status_code == 201, started.text
    run_id = started.json()["id"]
    paused = _wait_for_assessment_gate(client, run_id)
    assert paused["progress"] == 94
    assert paused["options"]["assessment_gate"]["state"] == "open"
    assert paused["options"]["assessment_open_items"] > 0

    blocked_resume = client.post(f"/api/runs/{run_id}/resume")
    assert blocked_resume.status_code == 409
    assert "모두 판정" in blocked_resume.json()["detail"]

    with SessionLocal() as db:
        controls = db.query(ControlTest).filter_by(
            run_id=run_id,
            standard="critical_infrastructure",
        ).all()
        unresolved = [
            item
            for item in controls
            if item.result not in {"confirmed", "not_vulnerable", "not_applicable"}
        ]
        assert unresolved
        final_control = unresolved[-1]
        for control in unresolved[:-1]:
            control.status = "completed"
            control.result = "not_applicable"
            control.summary = "게이트 통합 테스트에서 적용 대상을 확인한 제외 판정입니다."
        db.commit()
        final_control_id = final_control.id

    final_decision = client.post(
        f"/api/assessment-controls/{final_control_id}/record",
        json={
            "outcome": "not_applicable",
            "reviewer": "gate-reviewer",
            "summary": "적용 대상 기능이 없음을 진단 기준에 따라 확인했습니다.",
            "criteria_confirmed": True,
        },
    )
    assert final_decision.status_code == 200, final_decision.text
    ready = client.get(f"/api/runs/{run_id}").json()
    assert ready["status"] == "safely_paused"
    assert ready["options"]["assessment_open_items"] == 0
    assert ready["options"]["assessment_gate"]["state"] == "passed"

    resumed = client.post(f"/api/runs/{run_id}/resume")
    assert resumed.status_code == 200, resumed.text
    completed = _wait_for_run(client, run_id)
    assert completed["status"] == "completed", completed.get("error")
    assert completed["progress"] == 100


def test_domestic_baseline_cannot_receive_run_evidence_or_decisions(client):
    demo = client.post("/api/demo/bootstrap").json()
    coverage = client.get(
        f"/api/coverage?app_id={demo['app']['id']}&standard=critical_infrastructure"
    ).json()
    baseline = coverage["tests"][0]
    assert baseline["run_id"] is None

    attachment = client.post(
        f"/api/assessment-controls/{baseline['id']}/evidence",
        files={"file": ("baseline.txt", io.BytesIO(b"not a run"), "text/plain")},
    )
    assert attachment.status_code == 409
    decision = client.post(
        f"/api/assessment-controls/{baseline['id']}/record",
        json={
            "outcome": "not_vulnerable",
            "reviewer": "reviewer",
            "summary": "앱 기준선에는 판정을 기록할 수 없어야 합니다.",
        },
    )
    assert decision.status_code == 409


def test_ai_evidence_priority_is_run_bound_and_never_records_a_verdict(client):
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
    run = _wait_for_run(client, started.json()["id"])
    before = client.get(
        f"/api/coverage?run_id={run['id']}&scope=run&standard=critical_infrastructure"
    ).json()
    before_results = {item["id"]: item["result"] for item in before["tests"]}
    terminal_ids = {
        item["id"]
        for item in before["tests"]
        if item["result"] in {"confirmed", "not_vulnerable", "not_applicable"}
    }
    evidence = client.get(f"/api/runs/{run['id']}/evidence").json()
    run_evidence_ids = {item["id"] for item in evidence}

    response = client.post(
        f"/api/runs/{run['id']}/ai/evidence-priority",
        json={"use_mock": True},
    )
    assert response.status_code == 200
    priority = response.json()
    assert priority["run_id"] == run["id"]
    assert priority["status"] == "available"
    assert priority["provider"] == "mock"
    assert priority["generated_by"] == "ai_with_local_policy"
    assert priority["decision_policy"] == "recommendation_only_no_automatic_verdict"
    assert priority["synthetic"] is True
    assert priority["terminal_controls_excluded"] == len(terminal_ids)
    assert priority["recommendations"]
    assert terminal_ids.isdisjoint(
        item["control_test_id"] for item in priority["recommendations"]
    )
    assert all(
        set(item["suggested_evidence_ids"]).issubset(run_evidence_ids)
        for item in priority["recommendations"]
    )
    assert all(
        item["decision_boundary"].startswith("추천은 증적 검토 순서만")
        for item in priority["recommendations"]
    )

    after = client.get(
        f"/api/coverage?run_id={run['id']}&scope=run&standard=critical_infrastructure"
    ).json()
    assert {item["id"]: item["result"] for item in after["tests"]} == before_results
    persisted = client.get(f"/api/runs/{run['id']}").json()
    assert persisted["options"]["ai_evidence_priority"]["generated_at"] == priority["generated_at"]
    with SessionLocal() as db:
        invocation = db.query(AIInvocation).filter_by(
            run_id=run["id"],
            task="assessment_evidence_priority",
        ).one()
        assert invocation.provider == "mock"
        assert invocation.synthetic is True
