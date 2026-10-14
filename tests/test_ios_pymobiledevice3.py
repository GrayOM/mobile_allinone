from __future__ import annotations

import json
from pathlib import Path

import pytest

import backend.app.devices.ios as ios_module
from backend.app.core.command import CommandResult
from backend.app.core.config import AppSettings
from backend.app.core.status import CapabilityStatus
from backend.app.devices.ios import IOSDeviceAdapter

UDID = "335e71692793a836a787f0bbbb9565c7646df1a3"
APPLIST = [
    {
        "CFBundleIdentifier": "com.example.bank",
        "BundlePath": "/private/var/containers/Bundle/Application/AAAA/Bank.app",
        "ExecutableName": "Bank",
    },
    {
        "CFBundleIdentifier": "com.apple.Preferences",
        "BundlePath": "/Applications/Preferences.app",
        "ExecutableName": "Preferences",
    },
]
PROCLIST = [
    {"pid": 101, "name": "Bank", "realAppName": "/private/var/containers/Bundle/Application/AAAA/Bank.app/Bank"},
    {"pid": 102, "name": "Preferences", "realAppName": "/Applications/Preferences.app/Preferences"},
    {"pid": 1, "name": "launchd", "realAppName": "/sbin/launchd"},
]
APPS = {
    "com.example.bank": {"ApplicationType": "User"},
    "com.apple.Preferences": {"ApplicationType": "System"},
}


def _ok(command, stdout=""):
    return CommandResult(status=CapabilityStatus.AVAILABLE, command=list(command), return_code=0, stdout=stdout)


@pytest.fixture()
def adapter(monkeypatch, tmp_path: Path):
    tool = tmp_path / "pymobiledevice3"
    tool.write_text("#!/bin/sh\n")
    frida_ps = tmp_path / "frida-ps"
    frida_ps.write_text("#!/bin/sh\n")
    settings = AppSettings(ios_usbmux_address="127.0.0.1:27016", ios_frida_forward_port=27042)
    settings.tools.pymobiledevice3 = str(tool)
    settings.tools.frida_ps = str(frida_ps)
    calls: list[tuple[list[str], dict[str, str]]] = []

    async def fake_run(command, *, timeout=30, env=None, **kwargs):
        args = [str(part) for part in command]
        calls.append((args, dict(env or {})))
        rest = args[1:]
        if rest[:2] == ["usbmux", "list"]:
            return _ok(args, json.dumps([{"Identifier": UDID, "DeviceName": "Cyberone", "ProductVersion": "16.7.10", "ConnectionType": "USB"}]))
        if rest[:2] == ["mounter", "list"]:
            return _ok(args, json.dumps([{"ImageSignature": "x"}]))
        if rest[:3] == ["developer", "dvt", "applist"]:
            return _ok(args, json.dumps(APPLIST))
        if rest[:3] == ["developer", "dvt", "proclist"]:
            return _ok(args, json.dumps(PROCLIST))
        if rest[:3] == ["developer", "dvt", "kill"]:
            return _ok(args)
        if rest[:3] == ["developer", "dvt", "screenshot"]:
            Path(rest[3]).write_bytes(b"\x89PNG\r\n\x1a\nfake")
            return _ok(args)
        if rest[:3] == ["developer", "dvt", "launch"]:
            return _ok(args, "Process launched with pid 101")
        if rest[:2] == ["apps", "list"]:
            return _ok(args, json.dumps(APPS))
        if args[0].endswith("frida-ps"):
            return _ok(args, "PID Name\n1 launchd\n")
        return _ok(args, "")

    forwards: list[tuple[str, int, int]] = []

    async def fake_ensure(self, executable, udid, local_port, remote_port, env):
        forwards.append((udid, local_port, remote_port))
        assert env.get("USBMUXD_SOCKET_ADDRESS") == "127.0.0.1:27016"
        return True

    monkeypatch.setattr(ios_module, "run_command", fake_run)
    monkeypatch.setattr(ios_module._UsbmuxForwards, "ensure", fake_ensure)
    ios_module._DVT_READY.clear()
    device = IOSDeviceAdapter(settings)
    device.calls = calls  # type: ignore[attr-defined]
    device.forwards = forwards  # type: ignore[attr-defined]
    return device


@pytest.mark.asyncio
async def test_usbmux_address_reaches_every_pymobiledevice3_call(adapter):
    devices = await adapter.discover()
    assert [item.id for item in devices] == [UDID]
    assert all(env.get("USBMUXD_SOCKET_ADDRESS") == "127.0.0.1:27016" for args, env in adapter.calls if args[0].endswith("pymobiledevice3"))
    info = devices[0]
    assert info.privileged is True
    assert info.details["jailbreak_signal"] == "frida_server_reachable"
    assert info.details["frida_target"]["transport"] == "remote"
    assert info.details["frida_target"]["endpoint"] == "127.0.0.1:27042"
    assert {"screenshot", "process", "launch", "install"} <= set(info.capabilities)
    assert adapter.forwards == [(UDID, 27042, 27042)]


@pytest.mark.asyncio
async def test_dvt_process_lookup_and_kill_are_bundle_scoped(adapter):
    process = await adapter.process_info(UDID, "com.example.bank")
    assert process.status == CapabilityStatus.AVAILABLE
    assert process.data == {"pids": ["101"], "running": True}
    missing = await adapter.process_info(UDID, "com.example.unknown")
    assert missing.data == {"pids": [], "running": False}
    stopped = await adapter.stop_app(UDID, "com.example.bank")
    assert stopped.status == CapabilityStatus.AVAILABLE
    kills = [args for args, _ in adapter.calls if args[1:4] == ["developer", "dvt", "kill"]]
    assert kills == [[adapter.pymobiledevice3, "developer", "dvt", "kill", "101"]]
    assert await adapter.start_app(UDID, "com.example.bank") is not None


@pytest.mark.asyncio
async def test_screenshot_and_package_list_use_dvt_and_installation_proxy(adapter, tmp_path: Path):
    shot = await adapter.screenshot(UDID, tmp_path / "shots" / "01.png")
    assert shot.status == CapabilityStatus.AVAILABLE
    assert Path(shot.file_path).read_bytes().startswith(b"\x89PNG")
    packages = await adapter.list_packages(UDID)
    assert packages.data["packages"] == ["com.example.bank"]
    # The developer image is mounted (or verified) only once per device.
    mounts = [args for args, _ in adapter.calls if args[1:3] == ["mounter", "list"]]
    assert len(mounts) == 1


def test_frida_target_without_tunnel_stays_usb(tmp_path: Path):
    settings = AppSettings()
    settings.tools.pymobiledevice3 = str(tmp_path / "missing")
    device = IOSDeviceAdapter(settings)
    assert device.frida_target(UDID).transport == "usb"
