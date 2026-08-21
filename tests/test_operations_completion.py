from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, delete, inspect, select, text

from backend.app.core.config import AppSettings, ToolPaths
from backend.app.core.command import stream_command_to_file_for_duration
from backend.app.database.alembic_runner import HEAD_REVISION, legacy_tables, upgrade_to_head
from backend.app.database.base import Base
from backend.app.database.models import (
    AuditLog,
    OrganizationSession,
    OrganizationUser,
)
from backend.app.database.session import SessionLocal, init_database
from backend.app.main import create_app
from backend.app.proxy import BurpProxyAdapter


def _clear_organization_rows() -> None:
    with SessionLocal() as db:
        db.execute(delete(AuditLog))
        db.execute(delete(OrganizationSession))
        db.execute(delete(OrganizationUser))
        db.commit()


def test_alembic_transitional_baseline_upgrades_legacy_database(tmp_path: Path):
    database = tmp_path / "legacy.db"
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    Base.metadata.create_all(bind=engine, tables=legacy_tables())

    upgrade_to_head(engine)

    tables = set(inspect(engine).get_table_names())
    assert {
        "alembic_version",
        "organization_users",
        "organization_sessions",
        "audit_logs",
        "capture_jobs",
    } <= tables
    with engine.connect() as connection:
        assert connection.scalar(text("SELECT version_num FROM alembic_version")) == HEAD_REVISION
    backups = list((tmp_path / "backups").glob("legacy-before-20260821_alembic_v8-*.db"))
    assert len(backups) == 1


def test_organization_roles_sessions_and_audit_chain(monkeypatch, tmp_path: Path):
    init_database()
    _clear_organization_rows()
    settings = AppSettings(
        data_dir=tmp_path,
        organization_auth=True,
        bootstrap_admin_username="admin",
        bootstrap_admin_password="admin-password-2026",
    )
    monkeypatch.setattr("backend.app.main.get_settings", lambda: settings)
    try:
        with TestClient(create_app(), base_url="http://127.0.0.1") as secured:
            config = secured.get("/api/auth/config")
            assert config.status_code == 200
            assert config.json()["enabled"] is True
            preflight = secured.options(
                "/api/projects",
                headers={
                    "Origin": "http://127.0.0.1:5173",
                    "Access-Control-Request-Method": "GET",
                },
            )
            assert preflight.status_code == 200
            assert secured.get("/api/projects").status_code == 401

            logged_in = secured.post(
                "/api/auth/login",
                json={"username": "admin", "password": "admin-password-2026"},
            )
            assert logged_in.status_code == 200
            admin_headers = {"Authorization": f"Bearer {logged_in.json()['token']}"}
            assert secured.get(
                "/api/projects",
                headers={**admin_headers, "User-Agent": "different-session-agent"},
            ).status_code == 401
            assert secured.post(
                "/api/auth/users",
                headers=admin_headers,
                json={
                    "username": "auditor",
                    "display_name": "Read Only Auditor",
                    "role": "viewer",
                    "password": "auditor-password-2026",
                },
            ).status_code == 201

            viewer_login = secured.post(
                "/api/auth/login",
                json={"username": "auditor", "password": "auditor-password-2026"},
            )
            viewer_headers = {
                "Authorization": f"Bearer {viewer_login.json()['token']}"
            }
            assert secured.get("/api/projects", headers=viewer_headers).status_code == 200
            denied = secured.post(
                "/api/projects",
                headers=viewer_headers,
                json={"name": "viewer-must-not-create"},
            )
            assert denied.status_code == 403
            assert denied.headers["X-MSW-Request-ID"]

            created = secured.post(
                "/api/projects",
                headers=admin_headers,
                json={"name": "audited-project", "run_mode": "mock"},
            )
            assert created.status_code == 201
            assert created.headers["Content-Security-Policy"].startswith("default-src 'self'")
            chain = secured.get("/api/audit-logs/verify", headers=admin_headers)
            assert chain.status_code == 200
            assert chain.json()["valid"] is True
            assert chain.json()["checked_count"] >= 6

            assert secured.post("/api/auth/logout", headers=viewer_headers).status_code == 200
            assert secured.get("/api/projects", headers=viewer_headers).status_code == 401
    finally:
        _clear_organization_rows()


def test_mock_long_capture_stops_and_obeys_raw_download_policy(client):
    demo = client.post("/api/demo/bootstrap").json()
    project_id = demo["project"]["id"]
    started = client.post(
        "/api/capture-jobs",
        json={
            "project_id": project_id,
            "device_id": "mock-android-01",
            "device_adapter": "mock",
            "kind": "device_logs",
            "max_duration_seconds": 10,
        },
    )
    assert started.status_code == 202, started.text
    job_id = started.json()["id"]
    duplicate = client.post(
        "/api/capture-jobs",
        json={
            "project_id": project_id,
            "device_id": "mock-android-01",
            "device_adapter": "mock",
            "kind": "device_logs",
            "max_duration_seconds": 10,
        },
    )
    assert duplicate.status_code == 409
    assert client.post(f"/api/capture-jobs/{job_id}/stop").status_code == 200

    deadline = time.monotonic() + 5
    job = None
    while time.monotonic() < deadline:
        rows = client.get(f"/api/capture-jobs?project_id={project_id}").json()
        job = next(item for item in rows if item["id"] == job_id)
        if job["status"] not in {"queued", "running", "stop_requested"}:
            break
        time.sleep(0.05)
    assert job and job["status"] == "stopped"
    assert job["synthetic"] is True
    assert job["sha256"] and job["size_bytes"] > 0
    assert client.get(f"/api/capture-jobs/{job_id}/download").status_code == 403

    assert client.patch(
        f"/api/projects/{project_id}", json={"raw_access_enabled": True}
    ).status_code == 200
    downloaded = client.get(f"/api/capture-jobs/{job_id}/download")
    assert downloaded.status_code == 200
    assert b"CAPTURE SEGMENT" in downloaded.content
    assert downloaded.headers["Cache-Control"] == "no-store"


async def _managed_proxy_scenario(monkeypatch, tmp_path: Path) -> None:
    calls: list[tuple[tuple, dict]] = []

    class FakeProcess:
        pid = 42424
        returncode = None

    fake = FakeProcess()

    async def fake_create(*args, **kwargs):
        calls.append((args, kwargs))
        return fake

    async def fake_terminate(process):
        assert process is fake
        process.returncode = 0

    monkeypatch.setattr("backend.app.proxy.manual.asyncio.create_subprocess_exec", fake_create)
    monkeypatch.setattr("backend.app.proxy.manual.terminate_process_tree", fake_terminate)
    settings = AppSettings(
        data_dir=tmp_path,
        tools=ToolPaths(burp=sys.executable),
    )
    adapter = BurpProxyAdapter(settings=settings)
    started = await adapter.start("run-managed")
    assert started.process_id == 42424
    assert started.status.value == "manual_required"
    assert calls[0][0] == (sys.executable,)
    assert "shell" not in calls[0][1]
    stopped = await adapter.stop("run-managed")
    assert stopped.status.value == "available"
    assert stopped.process_id == 42424


def test_burp_managed_session_only_stops_owned_process(monkeypatch, tmp_path: Path):
    asyncio.run(_managed_proxy_scenario(monkeypatch, tmp_path))


async def _bounded_stream_scenario(tmp_path: Path) -> None:
    destination = tmp_path / "bounded.log"
    completed = await stream_command_to_file_for_duration(
        [sys.executable, "-c", "import sys; sys.stdout.write('safe-log')"],
        destination,
        duration_seconds=5,
        max_bytes=1_024,
    )
    assert completed.ok
    assert destination.read_text(encoding="utf-8") == "safe-log"

    rejected = tmp_path / "oversized.log"
    limited = await stream_command_to_file_for_duration(
        [sys.executable, "-c", "import sys; sys.stdout.write('x' * 4096)"],
        rejected,
        duration_seconds=5,
        max_bytes=128,
    )
    assert not limited.ok
    assert "제한" in (limited.error or "")
    assert not rejected.exists()


def test_streaming_capture_is_atomic_and_size_bounded(tmp_path: Path):
    asyncio.run(_bounded_stream_scenario(tmp_path))
