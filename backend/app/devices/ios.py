from __future__ import annotations

import asyncio
import json
from pathlib import Path

from backend.app.core.command import CommandResult, run_command
from backend.app.core.config import AppSettings, get_settings
from backend.app.core.status import CapabilityStatus, Platform
from backend.app.devices.base import DeviceAdapter, DeviceInfo, DeviceOperation


class IOSDeviceAdapter(DeviceAdapter):
    name = "ios_windows"

    def __init__(
        self,
        settings: AppSettings | None = None,
        *,
        host: str | None = None,
        port: int = 22,
        username: str = "root",
        include_usb: bool = True,
    ):
        self.settings = settings or get_settings()
        self.host = host
        self.port = port
        self.username = username
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

    def _manual(self, message: str) -> DeviceOperation:
        return DeviceOperation(CapabilityStatus.MANUAL_REQUIRED, message)

    @staticmethod
    def _operation(result: CommandResult, success: str) -> DeviceOperation:
        return DeviceOperation(
            result.status,
            success
            if result.ok
            else result.error or result.stderr.strip() or "iOS 도구 실행 실패",
            command=result.display_command,
            output=result.stdout or result.stderr,
        )

    async def _ssh(self, *command: str) -> DeviceOperation:
        if not self.host or not self.ssh:
            return DeviceOperation(
                CapabilityStatus.NOT_CONFIGURED,
                "iOS SSH 호스트와 Windows OpenSSH 경로를 설정하세요.",
            )
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
                *command,
            ],
            timeout=self.settings.command_timeout_seconds,
        )
        return self._operation(result, "SSH 명령을 실행했습니다.")

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
                    },
                )
            )
        return devices

    async def _discover_pymobiledevice3(self) -> list[DeviceInfo]:
        if not self.pymobiledevice3:
            return []
        command = await run_command(
            [self.pymobiledevice3, "usbmux", "list"], timeout=20
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
            devices.append(
                DeviceInfo(
                    id=str(udid),
                    platform=Platform.IOS,
                    model=str(properties.get("DeviceName") or "iOS Device"),
                    os_version=str(properties.get("ProductVersion") or "unknown"),
                    architecture=str(properties.get("CPUArchitecture") or "unknown"),
                    connection=str(properties.get("ConnectionType") or "usb").lower(),
                    privileged=None,
                    frida_status=(await self.frida_status(str(udid))).status,
                    proxy_status=CapabilityStatus.NOT_CONFIGURED,
                    availability=CapabilityStatus.AVAILABLE,
                    capabilities=[
                        "packages",
                        "launch_adapter",
                        "logs",
                        "port_forward",
                        "pcap",
                        "frida_status",
                    ],
                    adapter=self.name,
                    details={
                        "connection_backend": "pymobiledevice3",
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
            ssh_id = f"ios-ssh:{self.host}:{self.port}"
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
                        details={"ssh_host": self.host, "ssh_port": self.port},
                    )
                )
        return devices

    async def list_packages(self, device_id: str) -> DeviceOperation:
        if device_id.startswith("ios-ssh:"):
            return await self._ssh(
                "find /Applications /var/containers/Bundle/Application "
                "-maxdepth 3 -name '*.app' 2>/dev/null"
            )
        if self.ideviceinstaller:
            result = await run_command(
                [self.ideviceinstaller, "-u", device_id, "-l"], timeout=60
            )
            return self._operation(result, "iOS 설치 앱 목록을 조회했습니다.")
        if self.pymobiledevice3:
            result = await run_command(
                [self.pymobiledevice3, "apps", "list"], timeout=60
            )
            return self._operation(result, "iOS 설치 앱 목록을 조회했습니다.")
        return DeviceOperation(
            CapabilityStatus.NOT_CONFIGURED,
            "ideviceinstaller 또는 pymobiledevice3를 설정하세요.",
        )

    async def install_app(self, device_id: str, app_path: Path) -> DeviceOperation:
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
        if self.ideviceinstaller and not device_id.startswith("ios-ssh:"):
            result = await run_command(
                [self.ideviceinstaller, "-u", device_id, "-U", package_name],
                timeout=120,
            )
            return self._operation(result, "iOS 앱 삭제를 요청했습니다.")
        return self._manual("ideviceinstaller가 없어 iOS 앱 삭제는 수동 작업이 필요합니다.")

    async def start_app(self, device_id: str, package_name: str) -> DeviceOperation:
        if device_id.startswith("ios-ssh:"):
            return await self._ssh("open", package_name)
        if self.pymobiledevice3:
            result = await run_command(
                [
                    self.pymobiledevice3,
                    "developer",
                    "dvt",
                    "launch",
                    package_name,
                ],
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
        if device_id.startswith("ios-ssh:"):
            return await self._ssh("killall", package_name)
        return self._manual("비탈옥 iOS 앱 종료는 현재 수동 작업이 필요합니다.")

    async def screenshot(self, device_id: str, destination: Path) -> DeviceOperation:
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
            return await self._ssh("log", "show", "--last", f"{duration_seconds}s")
        if not self.idevicesyslog:
            return self._manual("idevicesyslog 또는 SSH 로그 수집 도구를 설정하세요.")
        destination.parent.mkdir(parents=True, exist_ok=True)
        command = [self.idevicesyslog, "-u", device_id]
        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.sleep(max(1, min(duration_seconds, 60)))
            process.terminate()
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=10)
            text = stdout.decode("utf-8", errors="replace")
            destination.write_text(text, encoding="utf-8")
            return DeviceOperation(
                CapabilityStatus.AVAILABLE,
                "iOS syslog 스트림을 수집했습니다.",
                command=" ".join(command),
                output=text[-20000:],
                file_path=str(destination),
            )
        except (OSError, asyncio.TimeoutError) as exc:
            return DeviceOperation(
                CapabilityStatus.FAILED,
                f"iOS syslog 수집 실패: {exc}",
                command=" ".join(command),
            )

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
                f"{self.username}@{self.host}:{remote_path}",
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
        return self._manual(
            "비탈옥 단말 프로세스 조회는 pymobiledevice3 DVT 터널 구성 후 수동 확인이 필요합니다."
        )

    async def frida_status(self, device_id: str) -> DeviceOperation:
        if device_id.startswith("ios-ssh:"):
            return await self._ssh("pgrep", "-af", "frida")
        if not self.frida_ps:
            return DeviceOperation(
                CapabilityStatus.NOT_CONFIGURED,
                "frida-ps를 찾을 수 없습니다.",
            )
        result = await run_command([self.frida_ps, "-Uai"], timeout=20)
        operation = self._operation(result, "Frida iOS 연결을 확인했습니다.")
        if result.ok and not result.stdout.strip():
            operation.status = CapabilityStatus.NOT_CONFIGURED
            operation.message = "Frida에 연결됐지만 설치 앱 목록이 비어 있습니다."
        return operation

    async def forward_port(
        self, device_id: str, local_port: int, remote_port: int
    ) -> DeviceOperation:
        if self.pymobiledevice3 and not device_id.startswith("ios-ssh:"):
            result = await run_command(
                [
                    self.pymobiledevice3,
                    "usbmux",
                    "forward",
                    str(local_port),
                    str(remote_port),
                ],
                timeout=30,
            )
            return self._operation(result, "iOS USB 포트 포워딩을 시작했습니다.")
        return self._manual("pymobiledevice3 usbmux 또는 SSH 터널을 설정하세요.")
