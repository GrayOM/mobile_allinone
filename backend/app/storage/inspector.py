from __future__ import annotations

import hashlib
import math
import sqlite3
import time
from pathlib import Path
from typing import Any
from urllib.parse import quote

from .models import DatabaseArtifact


SENSITIVE_COLUMN_TERMS = {
    "authorization",
    "auth",
    "token",
    "secret",
    "password",
    "passwd",
    "cookie",
    "session",
    "email",
    "phone",
    "address",
    "name",
    "account",
    "card",
    "ssn",
    "resident",
}


def _quoted_identifier(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {character: value.count(character) for character in set(value)}
    return -sum(
        (count / len(value)) * math.log2(count / len(value))
        for count in counts.values()
    )


def _sensitive(column: str, value: Any) -> bool:
    normalized = column.casefold().replace("-", "_")
    if any(term in normalized for term in SENSITIVE_COLUMN_TERMS):
        return True
    return isinstance(value, str) and len(value) >= 20 and _entropy(value) >= 3.5


def _preview(column: str, value: Any) -> Any:
    if value is None or isinstance(value, (int, float)):
        return value
    if isinstance(value, bytes):
        return {"masked": True, "type": "blob", "size": len(value)}
    text = str(value)
    if _sensitive(column, text):
        return {"masked": True, "type": "text", "size": len(text)}
    return text[:120] + ("…" if len(text) > 120 else "")


def inspect_sqlite_database(
    path: Path,
    *,
    logical_path: str | None = None,
    max_bytes: int = 50 * 1024 * 1024,
    preview_rows: int = 5,
    max_seconds: float = 5.0,
) -> DatabaseArtifact:
    if max_seconds <= 0:
        raise ValueError("max_seconds must be positive")
    deadline = time.monotonic() + max_seconds
    size = path.stat().st_size
    digest_builder = hashlib.sha256()
    header = b""
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            if len(header) < 16:
                header += chunk[: 16 - len(header)]
            digest_builder.update(chunk)
    digest = digest_builder.hexdigest()
    if time.monotonic() >= deadline:
        return DatabaseArtifact(
            path=logical_path or path.name,
            size=size,
            sha256=digest,
            tables=[],
            status="failed",
            message=f"SQLite 구조 해석 시간 제한({max_seconds:.3g}초)을 초과했습니다.",
        )
    if size > max_bytes:
        return DatabaseArtifact(
            path=logical_path or path.name,
            size=size,
            sha256=digest,
            tables=[],
            status="unsupported",
            message=f"DB가 구조화 보기 제한({max_bytes} bytes)을 초과했습니다.",
        )
    if header != b"SQLite format 3\x00":
        return DatabaseArtifact(
            path=logical_path or path.name,
            size=size,
            sha256=digest,
            tables=[],
            status="unsupported",
            message="SQLite header가 아닙니다.",
        )
    tables: list[dict[str, Any]] = []
    uri = f"file:{quote(path.resolve().as_posix())}?mode=ro&immutable=1"
    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(uri, uri=True, timeout=min(2, max_seconds))
        connection.execute("PRAGMA query_only=ON")
        connection.set_progress_handler(
            lambda: int(time.monotonic() >= deadline), 1_000
        )
        table_names = [
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
            ).fetchall()
        ][:200]
        for table in table_names:
            if time.monotonic() >= deadline:
                raise sqlite3.OperationalError("inspection time limit exceeded")
            quoted = _quoted_identifier(table)
            columns = [
                {"name": str(row[1]), "type": str(row[2] or "")}
                for row in connection.execute(f"PRAGMA table_info({quoted})").fetchall()
            ][:200]
            row_count = int(
                connection.execute(f"SELECT COUNT(*) FROM {quoted}").fetchone()[0]
            )
            names = [item["name"] for item in columns]
            preview = []
            for row in connection.execute(
                f"SELECT * FROM {quoted} LIMIT ?", (min(max(preview_rows, 0), 20),)
            ).fetchall():
                preview.append(
                    {
                        column: _preview(column, value)
                        for column, value in zip(names, row)
                    }
                )
            tables.append(
                {
                    "name": table,
                    "columns": columns,
                    "row_count": row_count,
                    "preview": preview,
                    "masked": True,
                }
            )
    except sqlite3.Error as exc:
        return DatabaseArtifact(
            path=logical_path or path.name,
            size=size,
            sha256=digest,
            tables=tables,
            status="failed",
            message=f"SQLite 구조 해석 실패: {exc}",
        )
    finally:
        if connection is not None:
            connection.close()
    return DatabaseArtifact(
        path=logical_path or path.name,
        size=size,
        sha256=digest,
        tables=tables,
        message=f"{len(tables)}개 테이블을 마스킹된 Preview로 구조화했습니다.",
    )
