from __future__ import annotations

from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, inspect

from backend.app.core.config import ROOT_DIR
from backend.app.database.base import Base
from backend.app.database.migrations import _backup_sqlite_database


BASELINE_REVISION = "20260821_0001"
HEAD_REVISION = "20260821_0003"
V8_REVISION = "20260821_0002"
V8_TABLES = {
    "organization_users",
    "organization_sessions",
    "audit_logs",
    "capture_jobs",
}
V9_TABLES = {"project_assessment_controls"}
ALEMBIC_TABLES = V8_TABLES | V9_TABLES


def legacy_tables():
    return [
        table
        for name, table in Base.metadata.tables.items()
        if name not in ALEMBIC_TABLES
    ]


def _config(engine: Engine) -> Config:
    config = Config(str(ROOT_DIR / "alembic.ini"))
    config.set_main_option(
        "script_location",
        str(ROOT_DIR / "backend" / "app" / "database" / "alembic"),
    )
    config.set_main_option("sqlalchemy.url", engine.url.render_as_string(hide_password=False))
    config.attributes["connection"] = engine
    return config


def _current_revision(engine: Engine) -> str | None:
    with engine.connect() as connection:
        row = connection.exec_driver_sql(
            "SELECT version_num FROM alembic_version LIMIT 1"
        ).first()
    return str(row[0]) if row else None


def upgrade_to_head(engine: Engine) -> None:
    config = _config(engine)
    inspector = inspect(engine)
    if not inspector.has_table("alembic_version"):
        existing_managed = {
            name for name in ALEMBIC_TABLES if inspector.has_table(name)
        }
        if existing_managed == ALEMBIC_TABLES:
            command.stamp(config, HEAD_REVISION)
            return
        if existing_managed == V8_TABLES:
            _backup_sqlite_database(engine, f"alembic_{V8_REVISION}_to_{HEAD_REVISION}")
            command.stamp(config, V8_REVISION)
            command.upgrade(config, "head")
            return
        if existing_managed:
            raise RuntimeError(
                "Alembic 관리 테이블이 일부만 존재합니다. 데이터베이스 백업을 보존한 채 관리자 점검이 필요합니다."
            )
        if inspector.has_table("projects"):
            _backup_sqlite_database(engine, "20260821_alembic_v8")
        command.stamp(config, BASELINE_REVISION)
    else:
        current = _current_revision(engine)
        if current and current != HEAD_REVISION and inspector.has_table("projects"):
            _backup_sqlite_database(engine, f"alembic_{current}_to_{HEAD_REVISION}")
    command.upgrade(config, "head")
