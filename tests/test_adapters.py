from __future__ import annotations

from pathlib import Path

import pytest

from backend.app.core.status import CapabilityStatus
from backend.app.devices import IOSDeviceAdapter, MockDeviceAdapter
from backend.app.proxy import BurpProxyAdapter, MockProxyAdapter


@pytest.mark.asyncio
async def test_mock_device_supports_evidence_operations(tmp_path: Path):
    adapter = MockDeviceAdapter()
    devices = await adapter.discover()
    assert devices[0].id == "mock-android-01"
    assert devices[0].availability == CapabilityStatus.AVAILABLE

    install = await adapter.install_app(devices[0].id, tmp_path / "demo.apk")
    launch = await adapter.start_app(devices[0].id, "com.example.demo")
    screen = await adapter.screenshot(devices[0].id, tmp_path / "screen.png")
    logs = await adapter.collect_logs(devices[0].id, tmp_path / "logcat.txt")

    assert install.status == CapabilityStatus.AVAILABLE
    assert launch.status == CapabilityStatus.AVAILABLE
    assert Path(screen.file_path or "").is_file()
    assert Path(logs.file_path or "").is_file()


@pytest.mark.asyncio
async def test_ios_windows_install_is_explicitly_manual(tmp_path: Path):
    result = await IOSDeviceAdapter().install_app("ios-test", tmp_path / "sample.ipa")
    assert result.status == CapabilityStatus.MANUAL_REQUIRED


@pytest.mark.asyncio
async def test_mock_proxy_collects_and_labels_sensitive_candidates(tmp_path: Path):
    adapter = MockProxyAdapter()
    await adapter.start("run-1")
    flows = await adapter.read_flows("run-1")
    exported = await adapter.export("run-1", tmp_path / "flows.json")

    assert len(flows) == 2
    assert flows[0].method == "POST"
    assert flows[0].sensitive_candidates
    assert Path(exported.capture_file or "").is_file()


@pytest.mark.asyncio
async def test_burp_adapter_does_not_fake_automation():
    status = await BurpProxyAdapter().start("run-1")
    assert status.status == CapabilityStatus.MANUAL_REQUIRED
    assert status.instructions

