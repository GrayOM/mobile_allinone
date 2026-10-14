from __future__ import annotations

import io
import zipfile
from pathlib import Path

import pytest

from backend.app.analyzers.security_solutions import identify_security_solutions, solution_pattern
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
    assert all(item["verification_status"] == "dynamic_verification_required" for item in found)
    assert identify_security_solutions(platform="ios", matches=[], native_libraries=[]) == []


def test_pattern_matches_longest_indicator_first():
    pattern = solution_pattern()
    assert pattern.search("Lcom/inka/appsealing/Foo;").group(0) == "com.inka.appsealing" or pattern.search("com.inka.appsealing").group(0) == "com.inka.appsealing"
    assert pattern.search("no match here") is None
    assert pattern.search("ApplicationProtectionLayer") is None
    assert pattern.search("libdroidx-security.so").group(0) == "libdroidx"
    assert pattern.search("uses nProtect AppGuard") is not None


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
    finding = next(item for item in result.findings if item.category == "security_solution")
    assert finding.severity == "info"
    assert "LIAPP" in finding.title
    assert finding.raw["assessment_type"] == "security_control"
