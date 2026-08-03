from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.core.config import ROOT_DIR
from backend.app.database.models import FridaScript


@dataclass(frozen=True)
class BuiltinScriptMetadata:
    relative_path: str
    name: str
    platform: str
    category: str
    target_framework: str
    conditions: list[str]
    risk: str


BUILTINS = [
    BuiltinScriptMetadata(
        "Android/Root Detection/observe-root-signals.js",
        "Android 루팅 경로 검사 관찰",
        "android",
        "Root Detection",
        "Android Java",
        ["java.io.File.exists", "root path indicators"],
        "low",
    ),
    BuiltinScriptMetadata(
        "Android/SSL Pinning/observe-tls-trust.js",
        "OkHttp 인증서 고정 관찰",
        "android",
        "SSL Pinning",
        "OkHttp3",
        ["okhttp3.CertificatePinner"],
        "low",
    ),
    BuiltinScriptMetadata(
        "Android/Anti-Debug/observe-debug-checks.js",
        "Android 디버거 검사 관찰",
        "android",
        "Anti-Debug",
        "Android Java",
        ["android.os.Debug.isDebuggerConnected"],
        "low",
    ),
    BuiltinScriptMetadata(
        "iOS/Jailbreak Detection/observe-jailbreak-signals.js",
        "iOS 탈옥 경로 검사 관찰",
        "ios",
        "Jailbreak Detection",
        "iOS Native",
        ["libc access", "jailbreak path indicators"],
        "low",
    ),
]


def seed_builtin_scripts(db: Session) -> None:
    scripts_root = ROOT_DIR / "scripts" / "frida"
    for metadata in BUILTINS:
        exists = db.scalar(
            select(FridaScript).where(
                FridaScript.name == metadata.name,
                FridaScript.source == "builtin",
            )
        )
        if exists:
            continue
        path = scripts_root / metadata.relative_path
        if not path.is_file():
            continue
        db.add(
            FridaScript(
                name=metadata.name,
                platform=metadata.platform,
                category=metadata.category,
                target_framework=metadata.target_framework,
                conditions=metadata.conditions,
                risk=metadata.risk,
                content=path.read_text(encoding="utf-8"),
                source="builtin",
                approval_status="approved",
                syntax_status="unchecked",
            )
        )
    db.commit()

