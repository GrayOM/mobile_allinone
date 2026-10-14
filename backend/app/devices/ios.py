from __future__ import annotations

import asyncio
import json
import os
import re
import shlex
from pathlib import Path
from typing import Any

from backend.app.core.command import (
    CommandResult,
    capture_command_for_duration,
    run_command,
    stream_command_to_file_for_duration,
)
from backend.app.core.config import AppSettings, get_settings
from backend.app.core.status import CapabilityStatus, Platform
from backend.app.core.targets import (
    SSH_USERNAME_PATTERN,
    is_valid_app_identifier,
    is_valid_host,
)
from backend.app.devices.base import DeviceAdapter, DeviceInfo, DeviceOperation
from backend.app.frida.target import FridaTarget


class _UsbmuxForwards:
    """Workbench-owned ``pymobiledevice3 usbmux forward`` processes, one per device/port.

    They exist only while the server runs and are reaped on shutdown. They
    are needed when the Python Frida binding cannot see the phone over USB
    directly (WSL2 behind the usbmuxd tunnel) and must use host:port instead.
    """

    def __init__(self) -> None:
        self._processes: dict[tuple[str, int, int], asyncio.subprocess.Process] = {}
        self._lock = asyncio.Lock()

    async def ensure(
        self,
        executable: str,
        udid: str,
        local_port: int,
        remote_port: int,
        env: dict[str, str],
    ) -> bool:
        key = (udid, local_port, remote_port)
        async with self._lock:
            current = self._processes.get(key)
            if current is not None and current.returncode is None:
                return True
            try:
                process = await asyncio.create_subprocess_exec(
                    executable,
                    "usbmux",
                    "forward",
                    str(local_port),
                    str(remote_port),
                    "--serial",
                    udid,
                    env=env,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
            except OSError:
                return False
            await asyncio.sleep(0.6)
            if process.returncode is not None:
                return False
            self._processes[key] = process
            return True

    async def shutdown(self) -> None:
        async with self._lock:
            processes = list(self._processes.values())
            self._processes.clear()
        for process in processes:
            if process.returncode is None:
                process.terminate()
                try:
                    await asyncio.wait_for(process.wait(), timeout=5)
                except asyncio.TimeoutError:
                    process.kill()


USBMUX_FORWARDS = _UsbmuxForwards()
_DVT_READY: set[str] = set()


async def shutdown_ios_forwards() -> None:
    await USBMUX_FORWARDS.shutdown()


class IOSDeviceAdapter(DeviceAdapter):
    name = "ios_windows"

    def __init__(
        self,
        settings: AppSettings | None = None,
        *,
        host: str | None = None,
        port: int = 22,
        username: str = "root",
        frida_endpoint: str | None = None,
        profile_id: str | None = None,
        profile_name: str | None = None,
        include_usb: bool = True,
    ):
        self.settings = settings or get_settings()
        if host and not is_valid_host(host):
            raise ValueError("iOS SSH 호스트는 유효한 IP 주소 또는 hostname이어야 합니다.")
        if not SSH_USERNAME_PATTERN.fullmatch(username):
            raise ValueError("iOS SSH 사용자명 형식이 올바르지 않습니다.")
        self.host = host.strip().rstrip(".") if host else None
        self.port = port
        self.username = username
        self.remote_frida_target = (
            FridaTarget.remote(frida_endpoint) if frida_endpoint else None
        )
        self.profile_id = profile_id
        self.profile_name = profile_name
        self.include_usb = include_usb
        self.ssh = self.settings.resolved_tool("ssh")
        self.scp = self.settings.resolved_tool("scp")
        self.pymobiledevice3 = self.settings.resolved_tool("pymobiledevice3")
        self.idevice_id = self.settings.resolved_tool("idevice_id")
        self.ideviceinfo = self.settings.resolved_tool("ideviceinfo")
        self.ideviceinstaller = self.settings.resolved_tool("ideviceinstaller")
        self.idevicesyslog = self.settings.resolved_tool("idevicesyslog")
        self.idevicescreenshot = self.settings.resolved_tool("idevicescreenshot")
        self.frida_ps = self.settings.resolved_tool("frida_ps")

    @staticmethod
    def ssh_device_id(host: str, port: int) -> str:
        return f"ios-ssh:{host}:{port}"

    @property
    def usbmux_tunnel(self) -> bool:
        return bool(self.settings.ios_usbmux_address)

    def frida_target(self, device_id: str) -> FridaTarget:
        if device_id.startswith("ios-ssh:"):
            if not self.remote_frida_target:
                raise ValueError(
                    "SSH iOS 단말은 실제 Frida remote endpoint를 프로필에 설정해야 합니다."
                )
            return self.remote_frida_target
        if self.usbmux_tunnel:
            # The binding cannot enumerate USB devices through a TCP usbmuxd;
            # frida-server is reached through a workbench-owned port forward.
            return FridaTarget.remote(f"127.0.0.1:{self.settings.ios_frida_forward_port}")
        return FridaTarget.usb(device_id)

    async def ensure_frida_forward(self, device_id: str) -> bool:
        if device_id.startswith("ios-ssh:") or not self.usbmux_tunnel or not self.pymobiledevice3:
            return not self.usbmux_tunnel
        return await USBMUX_FORWARDS.ensure(
            self.pymobiledevice3,
            device_id,
            self.settings.ios_frida_forward_port,
            27042,
            self._pmd_env(device_id),
        )

    def _pmd_env(self, device_id: str | None = None) -> dict[str, str]:
        env = os.environ.copy()
        if device_id:
            env["PYMOBILEDEVICE3_UDID"] = device_id
        if self.settings.ios_usbmux_address:
            # Honoured by pymobiledevice3 and libimobiledevice alike.
            env["USBMUXD_SOCKET_ADDRESS"] = self.settings.ios_usbmux_address
            env["PYMOBILEDEVICE3_USBMUX"] = self.settings.ios_usbmux_address
        return env

    async def _ensure_dvt(self, device_id: str) -> DeviceOperation | None:
        """Mount the Developer Disk Image once so DVT services are available."""
        if device_id in _DVT_READY or not self.pymobiledevice3:
            return None
        listed = await self._pmd(device_id, "mounter", "list", timeout=60)
        if listed.ok:
            try:
                mounted = json.loads(listed.stdout or "[]")
            except json.JSONDecodeError:
                mounted = []
            if mounted:
                _DVT_READY.add(device_id)
                return None
        mounted_result = await self._pmd(device_id, "mounter", "auto-mount", timeout=300)
        if mounted_result.ok:
            _DVT_READY.add(device_id)
            return None
        return self._operation(mounted_result, "Developer Disk Image를 마운트했습니다.")

    async def _app_inventory(self, device_id: str) -> dict[str, dict[str, Any]]:
        result = await self._pmd(device_id, "developer", "dvt", "applist", timeout=90)
        if not result.ok:
            return {}
        try:
            payload = json.loads(result.stdout or "[]")
        except json.JSONDecodeError:
            return {}
        return {
            str(item.get("CFBundleIdentifier")): item
            for item in payload
            if isinstance(item, dict) and item.get("CFBundleIdentifier")
        }

    async def _app_pids(self, device_id: str, package_name: str) -> tuple[list[int], CommandResult]:
        processes = await self._pmd(device_id, "developer", "dvt", "proclist", timeout=90)
        if not processes.ok:
            return [], processes
        try:
            payload = json.loads(processes.stdout or "[]")
        except json.JSONDecodeError:
            return [], processes
        inventory = await self._app_inventory(device_id)
        app = inventory.get(package_name) or {}
        bundle_path = str(app.get("BundlePath") or app.get("ContainerBundlePath") or "")
        executable = str(app.get("ExecutableName") or "")
        pids = [
            int(item["pid"])
            for item in payload
            if isinstance(item, dict)
            and isinstance(item.get("pid"), int)
            and (
                (bundle_path and str(item.get("realAppName") or "").startswith(bundle_path))
                or (executable and item.get("name") == executable)
            )
        ]
        return pids, processes

    def _manual(self, message: str) -> DeviceOperation:
        return DeviceOperation(CapabilityStatus.MANUAL_REQUIRED, message)

    @staticmethod
    def _failure_summary(result: CommandResult) -> str:
        """Reduce a pymobiledevice3 traceback to its final error line."""
        text = (result.stderr or result.stdout or "").strip()
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        cleaned = [
            line
            for line in lines
            if not line.startswith(("│", "╭", "╰", "❱"))
        ]
        for line in reversed(cleaned):
            if re.match(r"^[A-Za-z]\w*(Error|Exception)\b", line):
                return line[:600]
        for line in reversed(cleaned):
            if " ERROR " in line or line.startswith("ERROR"):
                return line[:600]
        return (result.error or (cleaned[-1] if cleaned else "") or "iOS 도구 실행 실패")[:600]

    @classmethod
    def _operation(cls, result: CommandResult, success: str) -> DeviceOperation:
        return DeviceOperation(
            result.status,
            success if result.ok else cls._failure_summary(result),
            command=result.display_command,
            output=(result.stdout or result.stderr)[-20000:],
        )

    async def _ssh(self, *command: str) -> DeviceOperation:
        if not self.host or not self.ssh:
            return DeviceOperation(
                CapabilityStatus.NOT_CONFIGURED,
                "iOS SSH 호스트와 Windows OpenSSH 경로를 설정하세요.",
            )
        remote_command = " ".join(shlex.quote(part) for part in command)
        result = await run_command(
            [
                self.ssh,
                "-o",
                "BatchMode=yes",
                "-o",
                "ConnectTimeout=5",
                "-p",
                str(self.port),
                f"{self.username}@{self.host}",
                remote_command,
            ],
            timeout=self.settings.command_timeout_seconds,
        )
        return self._operation(result, "SSH 명령을 실행했습니다.")

    @staticmethod
    def _invalid_bundle_id(package_name: str) -> DeviceOperation | None:
        if is_valid_app_identifier("ios", package_name):
            return None
        return DeviceOperation(
            CapabilityStatus.FAILED,
            "iOS Bundle ID 형식이 올바르지 않아 단말 명령을 차단했습니다.",
        )

    async def _pmd(self, device_id: str, *command: str, timeout: int = 60) -> CommandResult:
        if not self.pymobiledevice3:
            return CommandResult(
                CapabilityStatus.NOT_CONFIGURED,
                ["pymobiledevice3", *command],
                error="pymobiledevice3를 찾을 수 없습니다.",
            )
        return await run_command(
            [self.pymobiledevice3, *command], timeout=timeout, env=self._pmd_env(device_id)
        )

    async def _libimobile_info(self, udid: str) -> dict[str, str]:
        if not self.ideviceinfo:
            return {}
        result = await run_command(
            [self.ideviceinfo, "-u", udid], timeout=20
        )
        if not result.ok:
            return {}
        values: dict[str, str] = {}
        for line in result.stdout.splitlines():
            if ": " in line:
                key, value = line.split(": ", 1)
                values[key.strip()] = value.strip()
        return values

    async def _discover_libimobiledevice(self) -> list[DeviceInfo]:
        if not self.idevice_id:
            return []
        listed = await run_command([self.idevice_id, "-l"], timeout=15)
        if not listed.ok:
            return []
        devices: list[DeviceInfo] = []
        for udid in [line.strip() for line in listed.stdout.splitlines() if line.strip()]:
            info = await self._libimobile_info(udid)
            frida = await self.frida_status(udid)
            capabilities = ["packages", "logs", "frida_status"]
            if self.ideviceinstaller:
                capabilities.extend(["install", "uninstall"])
            if self.idevicescreenshot:
                capabilities.append("screenshot")
            if self.pymobiledevice3:
                capabilities.extend(["launch_adapter", "port_forward", "pcap"])
            devices.append(
                DeviceInfo(
                    id=udid,
                    platform=Platform.IOS,
                    model=info.get("DeviceName") or info.get("ProductType") or "iOS Device",
                    os_version=info.get("ProductVersion", "unknown"),
                    architecture=info.get("CPUArchitecture", "unknown"),
                    connection="usb",
                    privileged=None,
                    frida_status=frida.status,
                    proxy_status=CapabilityStatus.NOT_CONFIGURED,
                    availability=CapabilityStatus.AVAILABLE,
                    capabilities=sorted(set(capabilities)),
                    adapter=self.name,
                    details={
                        "product_type": info.get("ProductType"),
                        "build_version": info.get("BuildVersion"),
                        "connection_backend": "libimobiledevice",
                        "frida_target": FridaTarget.usb(udid).to_dict(),
                    },
                )
            )
        return devices

    async def _discover_pymobiledevice3(self) -> list[DeviceInfo]:
        if not self.pymobiledevice3:
            return []
        command = await run_command(
            [self.pymobiledevice3, "usbmux", "list"], timeout=20, env=self._pmd_env()
        )
        if not command.ok:
            return []
        try:
            payload = json.loads(command.stdout)
        except json.JSONDecodeError:
            return []
        entries = payload if isinstance(payload, list) else payload.get("devices", [])
        devices: list[DeviceInfo] = []
        for item in entries:
            if not isinstance(item, dict):
                continue
            properties = item.get("Properties") or item
            udid = (
                properties.get("SerialNumber")
                or properties.get("UDID")
                or properties.get("Identifier")
            )
            if not udid:
                continue
            frida = await self.frida_status(str(udid))
            # A reachable frida-server as a system daemon only exists on a
            # jailbroken device; without it the state stays unknown.
            privileged = True if frida.status == CapabilityStatus.AVAILABLE else None
            devices.append(
                DeviceInfo(
                    id=str(udid),
                    platform=Platform.IOS,
                    model=str(properties.get("DeviceName") or "iOS Device"),
                    os_version=str(properties.get("ProductVersion") or "unknown"),
                    architecture=str(properties.get("CPUArchitecture") or "unknown"),
                    connection=str(properties.get("ConnectionType") or "usb").lower(),
                    privileged=privileged,
                    frida_status=frida.status,
                    proxy_status=CapabilityStatus.NOT_CONFIGURED,
                    availability=CapabilityStatus.AVAILABLE,
                    capabilities=[
                        "packages",
                        "install",
                        "uninstall",
                        "launch",
                        "screenshot",
                        "logs",
                        "process",
                        "port_forward",
                        "pcap",
                        "frida_status",
                    ],
                    adapter=self.name,
                    details={
                        "connection_backend": "pymobiledevice3",
                        "usbmux_address": self.settings.ios_usbmux_address,
                        "jailbreak_signal": (
                            "frida_server_reachable" if privileged else None
                        ),
                        "frida_target": self.frida_target(str(udid)).to_dict(),
                        **properties,
                    },
                )
            )
        return devices

    async def discover(self) -> list[DeviceInfo]:
        devices: list[DeviceInfo] = []
        if self.include_usb:
            devices = await self._discover_libimobiledevice()
            if not devices:
                devices = await self._discover_pymobiledevice3()
        if self.host:
            probe = await self._ssh("uname", "-a")
            ssh_id = self.ssh_device_id(self.host, self.port)
            if not any(item.id == ssh_id for item in devices):
                devices.append(
                    DeviceInfo(
                        id=ssh_id,
                        platform=Platform.IOS,
                        model="Configured jailbroken iOS device",
                        os_version="unknown",
                        architecture="unknown",
                        connection="wifi",
                        privileged=True if probe.status == CapabilityStatus.AVAILABLE else None,
                        frida_status=(await self.frida_status(ssh_id)).status,
                        proxy_status=CapabilityStatus.NOT_CONFIGURED,
                        availability=probe.status,
                        capabilities=[
                            "packages_adapter",
                            "launch_adapter",
                            "process_adapter",
                            "logs_adapter",
                            "pull_file",
                            "frida_status",
                        ],
                        adapter=self.name,
                        details={
                            "ssh_host": self.host,
                            "ssh_port": self.port,
                            "profile_id": self.profile_id,
                            "profile_name": self.profile_name,
                            "frida_target": (
                                self.remote_frida_target.to_dict()
                                if self.remote_frida_target
                                else {
                                    "transport": "remote",
                                    "endpoint": None,
                                    "status": CapabilityStatus.NOT_CONFIGURED.value,
                                }
                            ),
                        },
                    )
                )
        return devices

    async def list_packages(self, device_id: str) -> DeviceOperation:
        if device_id.startswith("ios-ssh:"):
            return await self._ssh(
                "find",
                "/Applications",
                "/var/containers/Bundle/Application",
                "-maxdepth",
                "3",
                "-name",
                "*.app",
            )
        if self.pymobiledevice3:
            result = await self._pmd(device_id, "apps", "list", timeout=60)
            operation = self._operation(result, "iOS 설치 앱 목록을 조회했습니다.")
            if result.ok:
                try:
                    payload = json.loads(result.stdout or "{}")
                except json.JSONDecodeError:
                    payload = {}
                operation.data["packages"] = sorted(
                    bundle
                    for bundle, info in payload.items()
                    if isinstance(info, dict) and info.get("ApplicationType") == "User"
                )
                operation.output = "\n".join(operation.data["packages"])
            return operation
        if self.ideviceinstaller:
            result = await run_command(
                [self.ideviceinstaller, "-u", device_id, "-l"], timeout=60
            )
            return self._operation(result, "iOS 설치 앱 목록을 조회했습니다.")
        return DeviceOperation(
            CapabilityStatus.NOT_CONFIGURED,
            "ideviceinstaller 또는 pymobiledevice3를 설정하세요.",
        )

    async def install_app(self, device_id: str, app_path: Path) -> DeviceOperation:
        if self.pymobiledevice3 and not device_id.startswith("ios-ssh:"):
            result = await self._pmd(
                device_id, "apps", "install", str(app_path), timeout=300
            )
            return self._operation(result, "서명된 IPA 설치를 요청했습니다.")
        if self.ideviceinstaller and not device_id.startswith("ios-ssh:"):
            result = await run_command(
                [self.ideviceinstaller, "-u", device_id, "-i", str(app_path)],
                timeout=180,
            )
            return self._operation(
                result,
                "서명된 IPA 설치를 요청했습니다.",
            )
        return self._manual(
            "IPA 서명·재서명은 macOS 도구가 필요합니다. 이미 서명된 IPA는 "
            "ideviceinstaller를 설정하면 Windows에서 설치를 시도할 수 있습니다."
        )

    async def uninstall_app(self, device_id: str, package_name: str) -> DeviceOperation:
        invalid = self._invalid_bundle_id(package_name)
        if invalid:
            return invalid
        if self.pymobiledevice3 and not device_id.startswith("ios-ssh:"):
            result = await self._pmd(device_id, "apps", "uninstall", package_name, timeout=120)
            return self._operation(result, "iOS 앱 삭제를 요청했습니다.")
        if self.ideviceinstaller and not device_id.startswith("ios-ssh:"):
            result = await run_command(
                [self.ideviceinstaller, "-u", device_id, "-U", package_name],
                timeout=120,
            )
            return self._operation(result, "iOS 앱 삭제를 요청했습니다.")
        return self._manual("ideviceinstaller가 없어 iOS 앱 삭제는 수동 작업이 필요합니다.")

    async def start_app(self, device_id: str, package_name: str) -> DeviceOperation:
        invalid = self._invalid_bundle_id(package_name)
        if invalid:
            return invalid
        if device_id.startswith("ios-ssh:"):
            return await self._ssh("open", package_name)
        if self.pymobiledevice3:
            blocked = await self._ensure_dvt(device_id)
            if blocked is not None:
                return blocked
            result = await self._pmd(
                device_id,
                "developer",
                "dvt",
                "launch",
                package_name,
                timeout=60,
            )
            operation = self._operation(result, "iOS 앱 실행을 요청했습니다.")
            if not result.ok:
                operation.message += (
                    " iOS 17 이상은 pymobiledevice3 터널과 Developer Disk Image가 "
                    "필요할 수 있습니다."
                )
            return operation
        return self._manual("pymobiledevice3 또는 SSH 실행 환경을 설정하세요.")

    async def stop_app(self, device_id: str, package_name: str) -> DeviceOperation:
        invalid = self._invalid_bundle_id(package_name)
        if invalid:
            return invalid
        if device_id.startswith("ios-ssh:"):
            return await self._ssh("killall", package_name)
        if self.pymobiledevice3:
            blocked = await self._ensure_dvt(device_id)
            if blocked is not None:
                return blocked
            pids, listed = await self._app_pids(device_id, package_name)
            if not listed.ok:
                return self._operation(listed, "iOS 프로세스 목록을 조회했습니다.")
            if not pids:
                return DeviceOperation(
                    CapabilityStatus.AVAILABLE,
                    "대상 앱 프로세스가 이미 실행 중이 아닙니다.",
                    command=listed.display_command,
                    data={"pids": []},
                )
            failures = []
            for pid in pids:
                killed = await self._pmd(device_id, "developer", "dvt", "kill", str(pid), timeout=30)
                if not killed.ok:
                    failures.append(f"{pid}: {killed.error or killed.stderr.strip()}")
            if failures:
                return DeviceOperation(
                    CapabilityStatus.FAILED,
                    "일부 프로세스를 종료하지 못했습니다: " + "; ".join(failures),
                    data={"pids": pids},
                )
            return DeviceOperation(
                CapabilityStatus.AVAILABLE,
                f"대상 앱 프로세스 {len(pids)}개를 DVT로 종료했습니다.",
                command=f"pymobiledevice3 developer dvt kill {' '.join(map(str, pids))}",
                data={"pids": pids},
            )
        return self._manual("비탈옥 iOS 앱 종료는 현재 수동 작업이 필요합니다.")

    async def screenshot(self, device_id: str, destination: Path) -> DeviceOperation:
        if self.pymobiledevice3 and not device_id.startswith("ios-ssh:"):
            blocked = await self._ensure_dvt(device_id)
            if blocked is not None:
                return blocked
            destination.parent.mkdir(parents=True, exist_ok=True)
            result = await self._pmd(
                device_id, "developer", "dvt", "screenshot", str(destination), timeout=60
            )
            operation = self._operation(result, "iOS 화면을 캡처했습니다.")
            if result.ok and destination.is_file() and destination.stat().st_size > 0:
                operation.file_path = str(destination)
            elif result.ok:
                operation.status = CapabilityStatus.FAILED
                operation.message = "명령은 완료됐지만 스크린샷 파일을 찾지 못했습니다."
            return operation
        if not self.idevicescreenshot or device_id.startswith("ios-ssh:"):
            return self._manual(
                "idevicescreenshot와 Developer Disk Image를 설정하거나 수동 캡처하세요."
            )
        destination.parent.mkdir(parents=True, exist_ok=True)
        result = await run_command(
            [self.idevicescreenshot, "-u", device_id, str(destination)],
            timeout=45,
        )
        operation = self._operation(result, "iOS 화면을 캡처했습니다.")
        if result.ok and destination.is_file():
            operation.file_path = str(destination)
        elif result.ok:
            operation.status = CapabilityStatus.FAILED
            operation.message = "명령은 완료됐지만 스크린샷 파일을 찾지 못했습니다."
        return operation

    async def start_screen_recording(
        self, device_id: str, destination: Path, duration_seconds: int = 15
    ) -> DeviceOperation:
        return self._manual(
            "Windows iOS 화면 녹화는 자동화 안정성이 낮아 수동 캡처가 필요합니다."
        )

    async def collect_logs(
        self, device_id: str, destination: Path, duration_seconds: int = 5
    ) -> DeviceOperation:
        if device_id.startswith("ios-ssh:"):
            operation = await self._ssh(
                "log", "show", "--last", f"{max(1, min(duration_seconds, 60))}s"
            )
            if operation.status == CapabilityStatus.AVAILABLE:
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_text(operation.output, encoding="utf-8")
                operation.file_path = str(destination)
            return operation
        if self.pymobiledevice3:
            destination.parent.mkdir(parents=True, exist_ok=True)
            result = await stream_command_to_file_for_duration(
                [self.pymobiledevice3, "syslog", "live"],
                destination,
                duration_seconds=max(1, min(duration_seconds, 60)),
                max_bytes=self.settings.capture_segment_max_bytes,
                shutdown_timeout=10,
                env=self._pmd_env(device_id),
            )
            operation = self._operation(result, "iOS syslog 스트림을 수집했습니다.")
            if result.ok and destination.is_file():
                operation.file_path = str(destination)
                try:
                    operation.output = destination.read_text(encoding="utf-8", errors="replace")[-20000:]
                except OSError:
                    operation.output = ""
            return operation
        if not self.idevicesyslog:
            return self._manual("idevicesyslog 또는 SSH 로그 수집 도구를 설정하세요.")
        destination.parent.mkdir(parents=True, exist_ok=True)
        command = [self.idevicesyslog, "-u", device_id]
        result, output = await capture_command_for_duration(
            command,
            duration_seconds=max(1, min(duration_seconds, 60)),
            shutdown_timeout=10,
        )
        operation = self._operation(result, "iOS syslog 스트림을 수집했습니다.")
        if result.ok:
            text = output.decode("utf-8", errors="replace")
            destination.write_text(text, encoding="utf-8")
            operation.output = text[-20000:]
            operation.file_path = str(destination)
        return operation

    async def pull_file(
        self, device_id: str, remote_path: str, destination: Path
    ) -> DeviceOperation:
        if not device_id.startswith("ios-ssh:") or not self.host or not self.scp:
            return self._manual(
                "비탈옥 단말의 앱 컨테이너 파일은 AFC/HouseArrest 지원 범위에서만 접근할 "
                "수 있습니다. 현재는 SSH 프로필과 scp가 필요합니다."
            )
        destination.parent.mkdir(parents=True, exist_ok=True)
        result = await run_command(
            [
                self.scp,
                "-P",
                str(self.port),
                f"{self.username}@{self.host}:{shlex.quote(remote_path)}",
                str(destination),
            ],
            timeout=120,
        )
        operation = self._operation(result, "iOS 파일을 가져왔습니다.")
        if result.ok and destination.exists():
            operation.file_path = str(destination)
        return operation

    async def process_info(self, device_id: str, package_name: str) -> DeviceOperation:
        if device_id.startswith("ios-ssh:"):
            return await self._ssh("ps", "aux")
        if self.pymobiledevice3:
            blocked = await self._ensure_dvt(device_id)
            if blocked is not None:
                return blocked
            pids, listed = await self._app_pids(device_id, package_name)
            operation = self._operation(listed, "iOS 앱 프로세스를 확인했습니다.")
            if listed.ok:
                operation.data["pids"] = [str(pid) for pid in pids]
                operation.data["running"] = bool(pids)
                operation.output = f"{package_name}: pids={pids}"
            return operation
        return self._manual(
            "비탈옥 단말 프로세스 조회는 pymobiledevice3 DVT 터널 구성 후 수동 확인이 필요합니다."
        )

    async def frida_status(self, device_id: str) -> DeviceOperation:
        try:
            target = self.frida_target(device_id)
        except ValueError as exc:
            return DeviceOperation(
                CapabilityStatus.NOT_CONFIGURED,
                str(exc),
                data={
                    "frida_target": {
                        "transport": "remote",
                        "endpoint": None,
                    }
                },
            )
        if not self.frida_ps:
            return DeviceOperation(
                CapabilityStatus.NOT_CONFIGURED,
                "frida-ps를 찾을 수 없습니다.",
                data={"frida_target": target.to_dict()},
            )
        if not await self.ensure_frida_forward(device_id):
            return DeviceOperation(
                CapabilityStatus.NOT_CONFIGURED,
                "usbmux 터널의 frida-server 포트 포워딩을 시작하지 못했습니다.",
                data={"frida_target": target.to_dict()},
            )
        target_args = [target.command_option, target.display]
        result = await run_command(
            [self.frida_ps, *target_args, "-a", "-i"], timeout=20
        )
        operation = self._operation(result, "Frida iOS 연결을 확인했습니다.")
        operation.data["frida_target"] = target.to_dict()
        if result.ok and not result.stdout.strip():
            operation.status = CapabilityStatus.NOT_CONFIGURED
            operation.message = "Frida에 연결됐지만 설치 앱 목록이 비어 있습니다."
        return operation

    async def forward_port(
        self, device_id: str, local_port: int, remote_port: int
    ) -> DeviceOperation:
        if self.pymobiledevice3 and not device_id.startswith("ios-ssh:"):
            result = await self._pmd(
                device_id,
                "usbmux",
                "forward",
                str(local_port),
                str(remote_port),
                timeout=30,
            )
            return self._operation(result, "iOS USB 포트 포워딩을 시작했습니다.")
        return self._manual("pymobiledevice3 usbmux 또는 SSH 터널을 설정하세요.")
