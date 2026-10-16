from __future__ import annotations

import io
import plistlib
import zipfile
from pathlib import Path

import pytest

from backend.app.analyzers.security_solutions import (
    SIGNATURES,
    identify_security_solutions,
    security_solution_summary,
    solution_pattern,
)
from backend.app.analyzers.static import StaticAnalyzer
from backend.app.core.config import AppSettings


def test_identification_groups_indicators_per_product_and_platform():
    matches = [
        {"match": "com.inka.appsealing", "location": "classes.dex"},
        {"match": "AppSealing", "location": "lib/arm64-v8a/libcovault-appsec.so"},
        {"match": "mTransKey", "location": "classes2.dex"},
        {"match": "iXGuard", "location": "classes.dex"},  # iOS-only product must not appear for Android
    ]
    found = identify_security_solutions(
        platform="android", matches=matches, native_libraries=["lib/arm64-v8a/libcovault-appsec.so"]
    )
    products = {item["product"]: item for item in found}
    assert set(products) == {"AppSealing", "TouchEn mTransKey"}
    assert products["AppSealing"]["category"] == "app_shield"
    assert products["AppSealing"]["confidence"] > products["TouchEn mTransKey"]["confidence"]
    assert "libcovault" in products["AppSealing"]["indicators"]
    assert products["AppSealing"]["confidence_label"] == "high"
    assert {item["kind"] for item in products["AppSealing"]["evidence"]} >= {
        "package",
        "native_library",
    }
    assert all(item["verification_status"] == "dynamic_verification_required" for item in found)
    assert identify_security_solutions(platform="ios", matches=[], native_libraries=[]) == []


def test_pattern_matches_longest_indicator_first():
    pattern = solution_pattern()
    assert pattern.search("com.inka.appsealing").group(0) == "com.inka.appsealing"
    assert pattern.search("Lcom/inka/appsealing/Foo;").group(0) == "com/inka/appsealing"
    assert pattern.search("no match here") is None
    assert pattern.search("ApplicationProtectionLayer") is None
    assert pattern.search("libdroidx-security.so").group(0) == "libdroidx"
    assert pattern.search("uses nProtect AppGuard") is not None


def test_archive_paths_and_modern_attestation_sdks_are_reported_with_limits():
    found = identify_security_solutions(
        platform="android",
        matches=[
            {"match": "StandardIntegrityManager", "location": "classes3.dex"},
            {"match": "freeRASP", "location": "classes4.dex"},
        ],
        native_libraries=[],
        archive_entries=[
            "app/talsec/rasp/Talsec.class",
            "com/google/android/play/core/integrity/IntegrityManager.class",
        ],
    )
    products = {item["product"]: item for item in found}
    assert {"freeRASP", "Play Integrity API"} <= set(products)
    assert products["freeRASP"]["static_assessment"] == "likely_integrated"
    assert products["Play Integrity API"]["category"] == "platform_attestation"
    summary = security_solution_summary(found)
    assert summary["detected_count"] == 2
    assert summary["catalog_signature_count"] == len(SIGNATURES)
    assert summary["limitations"]

    legacy = security_solution_summary(
        [
            {
                "vendor": "Legacy Vendor",
                "product": "Legacy Shield",
                "category": "app_shield",
                "confidence": 0.7,
                "indicators": ["LegacyShield"],
                "locations": ["classes.dex"],
            }
        ]
    )
    assert legacy["solutions"][0]["signature_id"] == "legacy-vendor-legacy-shield"
    assert legacy["solutions"][0]["evidence"][0]["location"] == "classes.dex"


def test_unattributed_in_app_protection_requires_independent_control_groups():
    root_only = identify_security_solutions(
        platform="ios",
        matches=[],
        native_libraries=[],
        control_signals={
            "root_jailbreak_detection": [
                {"match": "/Applications/Cydia.app", "location": "Payload/App.app/App"},
                {"match": "/Applications/Sileo.app", "location": "Payload/App.app/App"},
            ]
        },
    )
    assert root_only == []

    found = identify_security_solutions(
        platform="ios",
        matches=[],
        native_libraries=[],
        control_signals={
            "root_jailbreak_detection": [
                {"match": "/Applications/Cydia.app", "location": "Payload/App.app/App"}
            ],
            "frida_hook_detection": [
                {
                    "match": "/hfe/yvo/sevqn/sevqn-ntrag.qlyvo",
                    "location": "Payload/App.app/App",
                }
            ],
            "integrity_signature": [
                {"match": "integrity", "location": "Payload/App.app/App"}
            ],
        },
    )
    assert len(found) == 1
    profile = found[0]
    assert profile["signature_id"] == "custom-in-app-protection"
    assert profile["vendor"] == "Vendor not identified"
    assert profile["confidence_label"] == "medium"
    assert profile["static_assessment"] == "unattributed_defensive_controls_observed"
    assert profile["evidence_types"] == ["control_signal"]


@pytest.mark.asyncio
async def test_static_analyzer_reports_security_solutions_in_structure_and_findings(tmp_path: Path):
    manifest = (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.shielded">'
        '<application android:label="Shielded"><activity android:name=".MainActivity" android:exported="true">'
        '<intent-filter><action android:name="android.intent.action.MAIN"/><category android:name="android.intent.category.LAUNCHER"/></intent-filter>'
        "</activity></application></manifest>"
    )
    apk = tmp_path / "shielded.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("AndroidManifest.xml", manifest)
        archive.writestr("classes.dex", b"dex\n035\x00" + b"Lcom/lockincomp/liapp/Guard; LIAPP protection active " + b"\x00" * 64)
        archive.writestr("lib/arm64-v8a/libliapp.so", b"\x7fELF" + b"\x00" * 128)
        archive.writestr("assets/notes.txt", "TouchEn mTransKey keypad bundle")
    analyzer = StaticAnalyzer(AppSettings(), external_analyzers_allowed=False)
    result = await analyzer.analyze(apk, tmp_path / "out")
    solutions = result.structure.get("security_solutions") or []
    products = {item["product"] for item in solutions}
    assert {"LIAPP", "TouchEn mTransKey"} <= products
    liapp = next(item for item in solutions if item["product"] == "LIAPP")
    assert "libliapp" in liapp["indicators"]
    assert result.structure["security_solution_analysis"]["detected_count"] >= 2
    tool = next(
        item for item in result.tool_runs if item["tool"] == "security_solution_analyzer"
    )
    assert tool["status"] == "available"
    assert tool["metadata"]["catalog_signature_count"] == len(SIGNATURES)
    finding = next(item for item in result.findings if item.category == "security_solution")
    assert finding.severity == "info"
    assert "LIAPP" in finding.title
    assert finding.raw["assessment_type"] == "security_control"


@pytest.mark.asyncio
async def test_static_analyzer_detects_ios_sqlite_swift_local_storage(tmp_path: Path):
    ipa = tmp_path / "sqlite-app.ipa"
    with zipfile.ZipFile(ipa, "w") as archive:
        archive.writestr(
            "Payload/SQLiteApp.app/Info.plist",
            plistlib.dumps(
                {
                    "CFBundleIdentifier": "com.example.sqlite-app",
                    "CFBundleExecutable": "SQLiteApp",
                    "CFBundleName": "SQLiteApp",
                }
            ),
        )
        archive.writestr(
            "Payload/SQLiteApp.app/SQLiteApp",
            b"SQLite/Connection.swift\x00sqlite3_open_v2\x00Documents/db.sqlite3",
        )

    analyzer = StaticAnalyzer(AppSettings(), external_analyzers_allowed=False)
    result = await analyzer.analyze(ipa, tmp_path / "out")

    matches = result.signals.get("local_storage") or []
    assert {item["match"] for item in matches} >= {
        "SQLite/Connection.swift",
        "sqlite3_open_v2",
    }
