from __future__ import annotations

import plistlib
import zipfile
from pathlib import Path

import pytest

from backend.app.analyzers import StaticAnalyzer
from backend.app.analyzers.static import detect_frameworks
from backend.app.core.config import AppSettings, ToolPaths
from backend.app.demo import DEMO_MANIFEST


def _settings(tmp_path: Path) -> AppSettings:
    return AppSettings(
        data_dir=tmp_path / "data",
        database_url=f"sqlite:///{tmp_path / 'test.db'}",
        tools=ToolPaths(
            adb="missing-adb",
            apktool="missing-apktool",
            jadx="missing-jadx",
            aapt="missing-aapt",
            apkanalyzer="missing-apkanalyzer",
            frida="missing-frida",
            mitmdump="missing-mitmdump",
            node="missing-node",
            ssh="missing-ssh",
        ),
    )


def test_framework_detection_covers_android_and_ios_layouts():
    android = detect_frameworks(
        ["lib/arm64-v8a/libflutter.so", "lib/arm64-v8a/libapp.so", "assets/index.android.bundle"]
    )
    ios = detect_frameworks(
        [
            "Payload/Demo.app/Frameworks/Flutter.framework/Flutter",
            "Payload/Demo.app/Frameworks/UnityFramework.framework/UnityFramework",
            "Payload/Demo.app/main.jsbundle",
        ]
    )
    assert {item["id"] for item in android} == {"flutter", "react_native"}
    assert {item["id"] for item in ios} == {"flutter", "unity", "react_native"}
    assert all(item["evidence"] for item in android + ios)
    assert detect_frameworks(["classes.dex", "AndroidManifest.xml"]) == []


@pytest.mark.asyncio
async def test_android_cleartext_and_new_secret_patterns(tmp_path: Path):
    manifest = DEMO_MANIFEST.replace(
        'android:usesCleartextTraffic="false"', 'android:usesCleartextTraffic="true"', 1
    )
    assert 'usesCleartextTraffic="true"' in manifest
    apk = tmp_path / "cleartext.apk"
    google_key = "AIza" + "S" * 35
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("AndroidManifest.xml", manifest)
        archive.writestr(
            "assets/config.json",
            f'{{"maps": "{google_key}", "db": "https://demo-app.firebaseio.com"}}',
        )
        archive.writestr("lib/arm64-v8a/libflutter.so", b"\x7fELF")
        archive.writestr("classes.dex", b"dex")
    result = await StaticAnalyzer(_settings(tmp_path)).analyze(apk)
    assert result.manifest["uses_cleartext_traffic"] is True
    cleartext = [item for item in result.findings if item.rule_id == "android.manifest.cleartext_traffic"]
    assert len(cleartext) == 1
    assert cleartext[0].category == "transport_security"
    kinds = {item.kind for item in result.candidates}
    assert {"google_api_key", "firebase_database_url"} <= kinds
    assert all(google_key not in item.masked_value for item in result.candidates)
    assert result.structure["frameworks"][0]["id"] == "flutter"
    assert any("Flutter" in warning for warning in result.warnings)


@pytest.mark.asyncio
async def test_ios_ats_exception_domains_and_frameworks(tmp_path: Path):
    plist = plistlib.dumps(
        {
            "CFBundleIdentifier": "com.example.msw.ios",
            "CFBundleDisplayName": "MSW iOS",
            "CFBundleShortVersionString": "1.0",
            "NSAppTransportSecurity": {
                "NSAllowsArbitraryLoadsInWebContent": True,
                "NSExceptionDomains": {
                    "legacy.example.test": {"NSExceptionAllowsInsecureHTTPLoads": True},
                    "secure.example.test": {"NSIncludesSubdomains": True},
                },
            },
        }
    )
    ipa = tmp_path / "demo.ipa"
    with zipfile.ZipFile(ipa, "w") as archive:
        archive.writestr("Payload/Demo.app/Info.plist", plist)
        archive.writestr("Payload/Demo.app/Demo", b"\xcf\xfa\xed\xfe")
        archive.writestr("Payload/Demo.app/main.jsbundle", "var x = 1;")
    result = await StaticAnalyzer(_settings(tmp_path)).analyze(ipa)
    assert result.platform == "ios"
    rules = {item.rule_id: item for item in result.findings}
    assert "ios.ats.exception_insecure_http" in rules
    assert "legacy.example.test" in rules["ios.ats.exception_insecure_http"].rationale
    assert "secure.example.test" not in rules["ios.ats.exception_insecure_http"].rationale
    assert "ios.ats.web_content_exception" in rules
    assert {item["id"] for item in result.structure["frameworks"]} == {"react_native"}


def test_url_candidates_ignore_binary_bytes_after_scheme(tmp_path: Path):
    analyzer = StaticAnalyzer(_settings(tmp_path))
    text = (
        "http://\x16\x06\x03U\x1d junk "
        "http://ocsp.apple.com/ocsp03-wwdrg3110\x02 "
        "https://api.example.test/v1/login?x=1"
    )
    urls = [item.value for item in analyzer._extract_candidates(text, "binary") if item.kind == "url"]
    assert urls == ["http://ocsp.apple.com/ocsp03-wwdrg3110", "https://api.example.test/v1/login?x=1"]
