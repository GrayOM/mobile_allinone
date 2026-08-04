from __future__ import annotations

import shutil
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import Engine, inspect, text


MIGRATION_ID = "20260804_safety_boundaries_v1"
MIGRATION_ID_V2 = "20260804_live_controls_v2"
MIGRATION_ID_V3 = "20260804_external_destination_v3"


ADDITIONS: dict[str, dict[str, str]] = {
    "projects": {"run_mode": "VARCHAR(16) NOT NULL DEFAULT 'live'"},
    "app_artifacts": {"synthetic": "BOOLEAN NOT NULL DEFAULT 0"},
    "diagnostic_runs": {
        "run_mode": "VARCHAR(16) NOT NULL DEFAULT 'live'",
        "synthetic": "BOOLEAN NOT NULL DEFAULT 0",
    },
    "findings": {"synthetic": "BOOLEAN NOT NULL DEFAULT 0"},
    "evidence": {"synthetic": "BOOLEAN NOT NULL DEFAULT 0"},
    "frida_scripts": {
        "approved_by": "VARCHAR(100)",
        "approved_at": "DATETIME",
        "approved_sha256": "VARCHAR(64)",
    },
    "proxy_flows": {
        "source_ip": "VARCHAR(64)",
        "synthetic": "BOOLEAN NOT NULL DEFAULT 0",
    },
    "ai_invocations": {"synthetic": "BOOLEAN NOT NULL DEFAULT 0"},
    "tool_runs": {"synthetic": "BOOLEAN NOT NULL DEFAULT 0"},
    "raw_findings": {"synthetic": "BOOLEAN NOT NULL DEFAULT 0"},
    "control_tests": {"synthetic": "BOOLEAN NOT NULL DEFAULT 0"},
}

V2_ADDITIONS: dict[str, dict[str, str]] = {
    "projects": {
        "external_analyzer_allowed": "BOOLEAN NOT NULL DEFAULT 0",
        "external_analyzer_approved_by": "VARCHAR(100)",
        "external_analyzer_approved_at": "DATETIME",
    },
}

V3_ADDITIONS: dict[str, dict[str, str]] = {
    "projects": {
        "external_analyzer_destination": "TEXT",
        "external_analyzer_addresses": "JSON NOT NULL DEFAULT '[]'",
        "external_analyzer_certificate_sha256": "VARCHAR(64)",
    }
}


def _backup_sqlite_database(
    engine: Engine, migration_id: str = MIGRATION_ID
) -> Path | None:
    database = engine.url.database
    if not database or database == ":memory:":
        return None
    source = Path(database)
    if not source.is_file() or source.stat().st_size == 0:
        return None
    backup_dir = source.parent / "backups"
    backup_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    destination = backup_dir / f"{source.stem}-before-{migration_id}-{stamp}{source.suffix}"
    shutil.copy2(source, destination)
    return destination


def _apply_v1(engine: Engine) -> None:
    if engine.dialect.name != "sqlite":
        return
    with engine.begin() as connection:
        connection.execute(
            text(
                "CREATE TABLE IF NOT EXISTS schema_migrations ("
                "id VARCHAR(100) PRIMARY KEY, applied_at DATETIME NOT NULL, backup_path TEXT)"
            )
        )
        applied = connection.scalar(
            text("SELECT id FROM schema_migrations WHERE id = :id"),
            {"id": MIGRATION_ID},
        )
    if applied:
        return

    inspector = inspect(engine)
    pending = {
        table: {
            column: definition
            for column, definition in columns.items()
            if column not in {item["name"] for item in inspector.get_columns(table)}
        }
        for table, columns in ADDITIONS.items()
        if inspector.has_table(table)
    }
    pending = {table: columns for table, columns in pending.items() if columns}
    backup = _backup_sqlite_database(engine) if pending else None

    with engine.begin() as connection:
        for table, columns in pending.items():
            for column, definition in columns.items():
                connection.execute(
                    text(f'ALTER TABLE "{table}" ADD COLUMN "{column}" {definition}')
                )

        # Existing records are classified conservatively from their legacy project/adapter state.
        connection.execute(
            text(
                "UPDATE projects SET run_mode = CASE WHEN mock_mode = 1 THEN 'mock' ELSE 'live' END"
            )
        )
        connection.execute(
            text(
                "UPDATE diagnostic_runs SET run_mode = COALESCE((SELECT p.run_mode FROM projects p "
                "WHERE p.id = diagnostic_runs.project_id), 'live')"
            )
        )
        connection.execute(
            text(
                "UPDATE diagnostic_runs SET synthetic = CASE WHEN run_mode = 'mock' OR "
                "device_adapter = 'mock' OR proxy_adapter = 'mock' THEN 1 ELSE 0 END"
            )
        )
        for table, join_column in (
            ("app_artifacts", "project_id"),
            ("findings", "project_id"),
            ("ai_invocations", "project_id"),
            ("control_tests", "project_id"),
        ):
            connection.execute(
                text(
                    f"UPDATE {table} SET synthetic = CASE WHEN EXISTS (SELECT 1 FROM projects p "
                    f"WHERE p.id = {table}.{join_column} AND p.run_mode = 'mock') THEN 1 ELSE synthetic END"
                )
            )
        for table in ("evidence", "proxy_flows"):
            connection.execute(
                text(
                    f"UPDATE {table} SET synthetic = CASE WHEN EXISTS (SELECT 1 FROM diagnostic_runs r "
                    f"WHERE r.id = {table}.run_id AND r.synthetic = 1) THEN 1 ELSE synthetic END"
                )
            )
        connection.execute(
            text(
                "UPDATE tool_runs SET synthetic = CASE WHEN EXISTS (SELECT 1 FROM app_artifacts a "
                "WHERE a.id = tool_runs.app_id AND a.synthetic = 1) THEN 1 ELSE synthetic END"
            )
        )
        connection.execute(
            text(
                "UPDATE raw_findings SET synthetic = CASE WHEN EXISTS (SELECT 1 FROM app_artifacts a "
                "WHERE a.id = raw_findings.app_id AND a.synthetic = 1) THEN 1 ELSE synthetic END"
            )
        )
        connection.execute(
            text(
                "UPDATE frida_scripts SET approval_status = 'pending_approval', "
                "approved_by = NULL, approved_at = NULL, approved_sha256 = NULL "
                "WHERE approval_status = 'approved' AND source != 'builtin'"
            )
        )
        connection.execute(
            text(
                "INSERT INTO schema_migrations(id, applied_at, backup_path) VALUES (:id, :applied_at, :backup)"
            ),
            {
                "id": MIGRATION_ID,
                "applied_at": datetime.now(timezone.utc).isoformat(),
                "backup": str(backup) if backup else None,
            },
        )


def _apply_v2(engine: Engine) -> None:
    with engine.begin() as connection:
        applied = connection.scalar(
            text("SELECT id FROM schema_migrations WHERE id = :id"),
            {"id": MIGRATION_ID_V2},
        )
    if applied:
        return
    inspector = inspect(engine)
    pending = {
        table: {
            column: definition
            for column, definition in columns.items()
            if column not in {item["name"] for item in inspector.get_columns(table)}
        }
        for table, columns in V2_ADDITIONS.items()
        if inspector.has_table(table)
    }
    pending = {table: columns for table, columns in pending.items() if columns}
    backup = (
        _backup_sqlite_database(engine, MIGRATION_ID_V2) if pending else None
    )
    with engine.begin() as connection:
        for table, columns in pending.items():
            for column, definition in columns.items():
                connection.execute(
                    text(f'ALTER TABLE "{table}" ADD COLUMN "{column}" {definition}')
                )
        connection.execute(
            text(
                "INSERT INTO schema_migrations(id, applied_at, backup_path) "
                "VALUES (:id, :applied_at, :backup)"
            ),
            {
                "id": MIGRATION_ID_V2,
                "applied_at": datetime.now(timezone.utc).isoformat(),
                "backup": str(backup) if backup else None,
            },
        )


def apply_migrations(engine: Engine) -> None:
    if engine.dialect.name != "sqlite":
        return
    _apply_v1(engine)
    _apply_v2(engine)
    _apply_v3(engine)


def _apply_v3(engine: Engine) -> None:
    with engine.begin() as connection:
        applied = connection.scalar(
            text("SELECT id FROM schema_migrations WHERE id = :id"),
            {"id": MIGRATION_ID_V3},
        )
    if applied:
        return
    inspector = inspect(engine)
    pending = {
        table: {
            column: definition
            for column, definition in columns.items()
            if column not in {item["name"] for item in inspector.get_columns(table)}
        }
        for table, columns in V3_ADDITIONS.items()
        if inspector.has_table(table)
    }
    pending = {table: columns for table, columns in pending.items() if columns}
    backup = _backup_sqlite_database(engine, MIGRATION_ID_V3) if pending else None
    with engine.begin() as connection:
        for table, columns in pending.items():
            for column, definition in columns.items():
                connection.execute(
                    text(f'ALTER TABLE "{table}" ADD COLUMN "{column}" {definition}')
                )
        connection.execute(
            text(
                "UPDATE projects SET external_analyzer_allowed = 0, "
                "external_analyzer_approved_by = NULL, external_analyzer_approved_at = NULL "
                "WHERE external_analyzer_allowed = 1"
            )
        )
        connection.execute(
            text(
                "INSERT INTO schema_migrations(id, applied_at, backup_path) "
                "VALUES (:id, :applied_at, :backup)"
            ),
            {
                "id": MIGRATION_ID_V3,
                "applied_at": datetime.now(timezone.utc).isoformat(),
                "backup": str(backup) if backup else None,
            },
        )
