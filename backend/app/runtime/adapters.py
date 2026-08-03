from __future__ import annotations

import shlex
from typing import Any

from backend.app.core.command import run_command
from backend.app.core.config import AppSettings, get_settings
from backend.app.core.status import CapabilityStatus

from .base import RuntimeOperation, RuntimeToolAdapter


class ObjectionRuntimeAdapter(RuntimeToolAdapter):
    name = "objection"
    actions = {
        "environment": ("low", "env"),
        "file_list": ("low", "ls"),
        "android_ssl_pinning_disable": ("high", "android sslpinning disable"),
        "ios_jailbreak_disable": ("high", "ios jailbreak disable"),
        "ios_ssl_pinning_disable": ("high", "ios sslpinning disable"),
        "ios_keychain_dump": ("medium", "ios keychain dump"),
    }

    def __init__(self, settings: AppSettings | None = None):
        self.settings = settings or get_settings()
        self.executable = self.settings.resolved_tool("objection")

    async def health(self) -> dict[str, Any]:
        if not self.executable:
            return {
                "name": self.name,
                "status": "not_configured",
                "integration": "subprocess",
                "install_hint": "py -m pip install objection",
                "actions": [
                    {"name": name, "risk": details[0]}
                    for name, details in self.actions.items()
                ],
            }
        version = await run_command([self.executable, "version"], timeout=15)
        return {
            "name": self.name,
            "status": "available",
            "integration": "subprocess",
            "path": self.executable,
            "version": (version.stdout or version.stderr).strip()[:200],
            "actions": [
                {"name": name, "risk": details[0]}
                for name, details in self.actions.items()
            ],
        }

    async def execute(
        self,
        *,
        device_id: str,
        target: str,
        action: str,
        arguments: dict[str, Any] | None = None,
        approved: bool = False,
    ) -> RuntimeOperation:
        if action not in self.actions:
            return RuntimeOperation(
                CapabilityStatus.UNSUPPORTED,
                self.name,
                action,
                "unknown",
                "지원하지 않는 objection 작업입니다.",
            )
        risk, objection_command = self.actions[action]
        if risk in {"medium", "high"} and not approved:
            return RuntimeOperation(
                CapabilityStatus.MANUAL_REQUIRED,
                self.name,
                action,
                risk,
                "민감정보 열람 또는 앱 동작 변경 작업은 사용자 승인이 필요합니다.",
            )
        if not self.executable:
            return RuntimeOperation(
                CapabilityStatus.NOT_CONFIGURED,
                self.name,
                action,
                risk,
                "objection 실행 파일을 찾을 수 없습니다.",
            )
        command = [
            self.executable,
            "-S",
            device_id,
            "-n",
            target,
            "run",
            objection_command,
        ]
        executed = await run_command(command, timeout=120)
        return RuntimeOperation(
            executed.status,
            self.name,
            action,
            risk,
            "objection 작업을 실행했습니다."
            if executed.ok
            else executed.error or executed.stderr.strip() or "objection 실행 실패",
            command=executed.display_command,
            output=executed.stdout or executed.stderr,
        )


class DrozerRuntimeAdapter(RuntimeToolAdapter):
    name = "drozer"
    actions = {
        "package_info": ("low", "app.package.info -a {target}"),
        "attack_surface": ("low", "app.package.attacksurface {target}"),
        "provider_info": ("low", "app.provider.info -a {target}"),
        "activity_start": (
            "high",
            "app.activity.start --component {target} {component}",
        ),
    }

    def __init__(self, settings: AppSettings | None = None):
        self.settings = settings or get_settings()
        self.executable = self.settings.resolved_tool("drozer")

    async def health(self) -> dict[str, Any]:
        if not self.executable:
            return {
                "name": self.name,
                "status": "not_configured",
                "integration": "subprocess",
                "install_hint": "pipx install drozer; 단말에 승인된 drozer Agent 설치",
                "agent_required": True,
                "actions": [
                    {"name": name, "risk": details[0]}
                    for name, details in self.actions.items()
                ],
            }
        version = await run_command([self.executable, "--version"], timeout=15)
        return {
            "name": self.name,
            "status": "available",
            "integration": "subprocess",
            "path": self.executable,
            "version": (version.stdout or version.stderr).strip()[:200],
            "agent_required": True,
            "actions": [
                {"name": name, "risk": details[0]}
                for name, details in self.actions.items()
            ],
        }

    async def execute(
        self,
        *,
        device_id: str,
        target: str,
        action: str,
        arguments: dict[str, Any] | None = None,
        approved: bool = False,
    ) -> RuntimeOperation:
        if action not in self.actions:
            return RuntimeOperation(
                CapabilityStatus.UNSUPPORTED,
                self.name,
                action,
                "unknown",
                "지원하지 않는 drozer 작업입니다.",
            )
        risk, template = self.actions[action]
        if risk == "high" and not approved:
            return RuntimeOperation(
                CapabilityStatus.MANUAL_REQUIRED,
                self.name,
                action,
                risk,
                "컴포넌트 호출은 앱 상태를 바꿀 수 있어 사용자 승인이 필요합니다.",
            )
        if not self.executable:
            return RuntimeOperation(
                CapabilityStatus.NOT_CONFIGURED,
                self.name,
                action,
                risk,
                "drozer 실행 파일을 찾을 수 없습니다.",
            )
        arguments = arguments or {}
        component = str(arguments.get("component") or "")
        if action == "activity_start" and not component:
            return RuntimeOperation(
                CapabilityStatus.MANUAL_REQUIRED,
                self.name,
                action,
                risk,
                "호출할 Activity 컴포넌트 이름을 입력하세요.",
            )
        module_command = template.format(
            target=shlex.quote(target),
            component=shlex.quote(component),
        )
        command = [
            self.executable,
            "console",
            "connect",
            "--command",
            f"run {module_command}",
        ]
        executed = await run_command(command, timeout=120)
        return RuntimeOperation(
            executed.status,
            self.name,
            action,
            risk,
            "drozer 작업을 실행했습니다."
            if executed.ok
            else executed.error or executed.stderr.strip() or "drozer 실행 실패",
            command=executed.display_command,
            output=executed.stdout or executed.stderr,
            data={"device_id": device_id, "agent_port": 31415},
        )
