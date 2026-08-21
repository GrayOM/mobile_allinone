from __future__ import annotations

import asyncio
import re
from pathlib import Path

from backend.app.core.command import (
    CommandResult,
    run_binary_command,
    run_command,
    stream_command_to_file_for_duration,
)
from backend.app.core.config import AppSettings, get_settings
from backend.app.core.status import CapabilityStatus, Platform
from backend.app.core.targets import is_valid_app_identifier
from backend.app.devices.base import DeviceAdapter, DeviceInfo, DeviceOperation


_COMPONENT_NAME_PATTERN = re.compile(r"^[A-Za-z0-9_.]{1,220}$")


class AndroidDeviceAdapter(DeviceAdapter):
    name = "android_adb"

    def __init__(self, settings: AppSettings | None = None):
        self.settings = settings or get_settings()
        self.adb = self.settings.resolved_tool("adb")

    def _missing(self) -> DeviceOperation:
        return DeviceOperation(
            CapabilityStatus.NOT_CONFIGURED,
            "ADB를 찾을 수 없습니다. 설정 화면에서 adb.exe 경로를 지정하세요.",
        )

    @staticmethod
    def _invalid_package(package_name: str) -> DeviceOperation | None:
        if is_valid_app_identifier("android", package_name):
            return None
        return DeviceOperation(
            CapabilityStatus.FAILED,
            "Android 패키지명 형식이 올바르지 않아 단말 명령을 차단했습니다.",
        )

    async def _adb(self, device_id: str | None, *args: str, timeout: int | None = None):
        if not self.adb:
            return None
        command = [self.adb]
        if device_id:
            command.extend(["-s", device_id])
        command.extend(args)
        return await run_command(
            command, timeout=timeout or self.settings.command_timeout_seconds
        )

    @staticmethod
    def _operation(result: CommandResult, success: str) -> DeviceOperation:
        message = success if result.ok else (result.error or result.stderr.strip() or "명령 실패")
        return DeviceOperation(
            result.status,
            message,
            command=result.display_command,
            output=result.stdout or result.stderr,
        )

    async def _prop(self, device_id: str, key: str) -> str:
        result = await self._adb(device_id, "shell", "getprop", key)
        return result.stdout.strip() if result and result.ok else "unknown"

    async def discover(self) -> list[DeviceInfo]:
        if not self.adb:
            return []
        result = await self._adb(None, "devices", "-l")
        if not result or not result.ok:
            return []
        devices: list[DeviceInfo] = []
        for line in result.stdout.splitlines()[1:]:
            if not line.strip() or line.startswith("*"):
                continue
            parts = line.split()
            if len(parts) < 2 or parts[1] != "device":
                continue
            device_id = parts[0]
            metadata = dict(
                token.split(":", 1)
                for token in parts[2:]
                if ":" in token and len(token.split(":", 1)) == 2
            )
            model, version, arch = await asyncio.gather(
                self._prop(device_id, "ro.product.model"),
                self._prop(device_id, "ro.build.version.release"),
                self._prop(device_id, "ro.product.cpu.abi"),
            )
            root_result = await self._adb(device_id, "shell", "su", "-c", "id")
            frida = await self.frida_status(device_id)
            devices.append(
                DeviceInfo(
                    id=device_id,
                    platform=Platform.ANDROID,
                    model=model if model != "unknown" else metadata.get("model", "Android"),
                    os_version=version,
                    architecture=arch,
                    connection="wifi" if ":" in device_id else "usb",
                    privileged=bool(root_result and root_result.ok),
                    frida_status=frida.status,
                    proxy_status=CapabilityStatus.NOT_CONFIGURED,
                    availability=CapabilityStatus.AVAILABLE,
                    capabilities=[
                        "packages",
                        "install",
                        "uninstall",
                        "launch",
                        "screenshot",
                        "screen_record",
                        "logcat",
                        "pull_file",
                        "process",
                        "frida_status",
                        "port_forward",
                    ],
                    adapter=self.name,
                    details=metadata,
                )
            )
        return devices

    async def list_packages(self, device_id: str) -> DeviceOperation:
        if not self.adb:
            return self._missing()
        result = await self._adb(device_id, "shell", "pm", "list", "packages", "-3")
        op = self._operation(result, "설치 앱 목록을 조회했습니다.")
        if result.ok:
            op.data["packages"] = [
                line.removeprefix("package:").strip()
                for line in result.stdout.splitlines()
                if line.strip()
            ]
        return op

    async def install_app(self, device_id: str, app_path: Path) -> DeviceOperation:
        if not self.adb:
            return self._missing()
        result = await self._adb(
            device_id, "install", "-r", str(app_path), timeout=max(120, self.settings.command_timeout_seconds)
        )
        return self._operation(result, "APK를 설치했습니다.")

    async def uninstall_app(self, device_id: str, package_name: str) -> DeviceOperation:
        invalid = self._invalid_package(package_name)
        if invalid:
            return invalid
        if not self.adb:
            return self._missing()
        result = await self._adb(device_id, "uninstall", package_name, timeout=60)
        return self._operation(result, "앱을 삭제했습니다.")

    async def start_app(self, device_id: str, package_name: str) -> DeviceOperation:
        invalid = self._invalid_package(package_name)
        if invalid:
            return invalid
        if not self.adb:
            return self._missing()
        result = await self._adb(
            device_id,
            "shell",
            "monkey",
            "-p",
            package_name,
            "-c",
            "android.intent.category.LAUNCHER",
            "1",
        )
        return self._operation(result, "앱을 실행했습니다.")

    async def stop_app(self, device_id: str, package_name: str) -> DeviceOperation:
        invalid = self._invalid_package(package_name)
        if invalid:
            return invalid
        if not self.adb:
            return self._missing()
        result = await self._adb(device_id, "shell", "am", "force-stop", package_name)
        return self._operation(result, "앱을 종료했습니다.")

    async def screenshot(self, device_id: str, destination: Path) -> DeviceOperation:
        if not self.adb:
            return self._missing()
        destination.parent.mkdir(parents=True, exist_ok=True)
        result, png = await run_binary_command(
            [self.adb, "-s", device_id, "exec-out", "screencap", "-p"],
            timeout=30,
        )
        op = self._operation(result, "화면을 캡처했습니다.")
        if result.ok and png.startswith(b"\x89PNG"):
            destination.write_bytes(png)
            op.file_path = str(destination)
        elif result.ok:
            op.status = CapabilityStatus.FAILED
            op.message = "PNG 캡처 결과가 올바르지 않습니다."
        return op

    async def start_screen_recording(
        self, device_id: str, destination: Path, duration_seconds: int = 15
    ) -> DeviceOperation:
        if not self.adb:
            return self._missing()
        remote = f"/sdcard/msw-{destination.stem}.mp4"
        record = await self._adb(
            device_id,
            "shell",
            "screenrecord",
            "--time-limit",
            str(min(max(duration_seconds, 1), 180)),
            remote,
            timeout=min(max(duration_seconds + 15, 30), 210),
        )
        if not record or not record.ok:
            result = self._operation(record, "화면 녹화를 완료했습니다.")
        else:
            result = await self.pull_file(device_id, remote, destination)
        cleanup = await self._adb(device_id, "shell", "rm", "-f", "--", remote)
        if cleanup and not cleanup.ok:
            result.message += " 단말 임시 녹화 파일 정리는 확인이 필요합니다."
        return result

    async def collect_logs(
        self, device_id: str, destination: Path, duration_seconds: int = 5
    ) -> DeviceOperation:
        if not self.adb:
            return self._missing()
        destination.parent.mkdir(parents=True, exist_ok=True)
        result = await stream_command_to_file_for_duration(
            [self.adb, "-s", device_id, "logcat", "-v", "threadtime"],
            destination,
            duration_seconds=max(1, min(duration_seconds, 60)),
            max_bytes=self.settings.capture_segment_max_bytes,
            shutdown_timeout=10,
        )
        op = self._operation(result, "Logcat을 수집했습니다.")
        if result.ok and destination.is_file():
            op.file_path = str(destination)
        return op

    async def pull_file(
        self, device_id: str, remote_path: str, destination: Path
    ) -> DeviceOperation:
        if not self.adb:
            return self._missing()
        destination.parent.mkdir(parents=True, exist_ok=True)
        result = await self._adb(device_id, "pull", remote_path, str(destination), timeout=120)
        op = self._operation(result, "파일을 가져왔습니다.")
        if result.ok:
            op.file_path = str(destination)
        return op

    async def process_info(self, device_id: str, package_name: str) -> DeviceOperation:
        invalid = self._invalid_package(package_name)
        if invalid:
            return invalid
        if not self.adb:
            return self._missing()
        result = await self._adb(device_id, "shell", "pidof", package_name)
        op = self._operation(result, "앱 프로세스를 확인했습니다.")
        if result.ok:
            op.data["pids"] = [pid for pid in result.stdout.split() if pid.isdigit()]
        return op

    async def frida_status(self, device_id: str) -> DeviceOperation:
        if not self.adb:
            return self._missing()
        result = await self._adb(
            device_id, "shell", "ps", "-A"
        )
        if not result or not result.ok:
            return self._operation(result, "Frida Server 상태를 확인했습니다.")
        matches = [
            line for line in result.stdout.splitlines() if re.search(r"\bfrida(-server)?\b", line, re.I)
        ]
        return DeviceOperation(
            CapabilityStatus.AVAILABLE if matches else CapabilityStatus.NOT_CONFIGURED,
            "Frida Server가 실행 중입니다." if matches else "Frida Server 프로세스를 찾지 못했습니다.",
            command=result.display_command,
            output="\n".join(matches),
        )

    async def forward_port(
        self, device_id: str, local_port: int, remote_port: int
    ) -> DeviceOperation:
        if not self.adb:
            return self._missing()
        result = await self._adb(
            device_id, "forward", f"tcp:{local_port}", f"tcp:{remote_port}"
        )
        return self._operation(result, f"tcp:{local_port} → tcp:{remote_port} 포워딩을 설정했습니다.")

    async def validate_component_candidate(
        self,
        device_id: str,
        package_name: str,
        candidate: dict[str, object],
    ) -> DeviceOperation:
        invalid = self._invalid_package(package_name)
        if invalid:
            return invalid
        if not self.adb:
            return self._missing()
        kind = str(candidate.get("kind") or "")
        if kind == "deep_link":
            uri = str(candidate.get("uri") or "")
            result = await self._adb(
                device_id,
                "shell",
                "am",
                "start",
                "-W",
                "-a",
                "android.intent.action.VIEW",
                "-c",
                "android.intent.category.BROWSABLE",
                "-d",
                uri,
                package_name,
            )
            return self._operation(result, "승인된 딥링크 외부 진입을 검증했습니다.")
        component_type = str(candidate.get("component_type") or "")
        component_name = str(candidate.get("component_name") or "")
        if component_type not in {"activity", "activity-alias"}:
            return DeviceOperation(
                CapabilityStatus.MANUAL_REQUIRED,
                "Activity 이외 컴포넌트는 상태 변경 가능성이 있어 자동 호출하지 않습니다.",
            )
        if not _COMPONENT_NAME_PATTERN.fullmatch(component_name):
            return DeviceOperation(
                CapabilityStatus.FAILED,
                "정적 분석의 Android 컴포넌트 이름이 안전 형식과 일치하지 않습니다.",
            )
        result = await self._adb(
            device_id,
            "shell",
            "am",
            "start",
            "-W",
            "-n",
            f"{package_name}/{component_name}",
        )
        return self._operation(result, "승인된 외부 노출 Activity 진입을 검증했습니다.")
