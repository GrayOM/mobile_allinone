from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from backend.app.analyzers import StaticAnalyzer
from backend.app.core.config import AppSettings, ToolPaths
from backend.app.demo import DEMO_CODE, DEMO_MANIFEST


@pytest.mark.asyncio
async def test_analyzes_plaintext_apk_without_external_tools(tmp_path: Path):
    apk = tmp_path / "sample.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("AndroidManifest.xml", DEMO_MANIFEST)
        archive.writestr("sources/SecurityControls.java", DEMO_CODE)
        archive.writestr("classes.dex", b"CertificatePinner /system/xbin/su frida")
    settings = AppSettings(
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

    result = await StaticAnalyzer(settings).analyze(apk)

    assert result.status == "completed"
    assert result.platform == "android"
    assert result.package_name == "com.example.msw.demo"
    assert result.app_name == "MSW Demo Bank"
    assert "android.permission.INTERNET" in result.permissions
    assert result.manifest["debuggable"] is True
    assert any(item["exported"] for item in result.components)
    assert "certificate_pinning" in result.signals
    assert "root_jailbreak_detection" in result.signals
    assert result.tools["apktool"]["status"] == "not_configured"
    assert any(item.category == "build_configuration" for item in result.findings)


def test_rejects_unknown_artifact(tmp_path: Path):
    unknown = tmp_path / "sample.bin"
    unknown.write_bytes(b"not an app")

    with pytest.raises(ValueError):
        StaticAnalyzer.detect_platform(unknown)

