from __future__ import annotations

import asyncio
import json
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from backend.app.core.command import run_command
from backend.app.core.config import AppSettings, get_settings
from backend.app.core.status import CapabilityStatus


@dataclass(slots=True)
class FridaExecution:
    status: CapabilityStatus
    message: str
    mode: str
    target: str
    script_name: str
    command: str | None = None
    messages: list[dict[str, Any]] = field(default_factory=list)
    stdout: str = ""
    stderr: str = ""
    synthetic: bool = False

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["status"] = self.status.value
        return value


class FridaManager:
    def __init__(self, settings: AppSettings | None = None):
        self.settings = settings or get_settings()

    async def check_syntax(self, script: str) -> tuple[CapabilityStatus, str]:
        node = self.settings.resolved_tool("node")
        if not node:
            # Lightweight checks are intentionally conservative; only Node can mark valid.
            if script.count("{") != script.count("}") or script.count("(") != script.count(")"):
                return CapabilityStatus.FAILED, "괄호 짝이 맞지 않습니다."
            return (
                CapabilityStatus.NOT_CONFIGURED,
                "Node.js가 없어 기본 괄호 검사만 수행했습니다. 실행 전 Node.js 구문 검사를 권장합니다.",
            )
        with tempfile.TemporaryDirectory(prefix="msw-frida-") as temp:
            path = Path(temp) / "candidate.js"
            path.write_text(script, encoding="utf-8")
            result = await run_command([node, "--check", str(path)], timeout=15)
        if result.ok:
            return CapabilityStatus.AVAILABLE, "JavaScript 구문 검사를 통과했습니다."
        return CapabilityStatus.FAILED, result.stderr.strip() or result.error or "구문 오류"

    async def execute(
        self,
        *,
        device_id: str,
        target: str,
        script_name: str,
        script_content: str,
        mode: str = "spawn",
        timeout_seconds: int = 12,
        mock: bool = False,
    ) -> FridaExecution:
        syntax_status, syntax_message = await self.check_syntax(script_content)
        if syntax_status != CapabilityStatus.AVAILABLE:
            return FridaExecution(
                syntax_status,
                f"스크립트 구문 검증을 완료할 수 없습니다: {syntax_message}",
                mode,
                target,
                script_name,
            )
        if mock:
            await asyncio.sleep(0.12)
            messages = [
                {
                    "type": "send",
                    "payload": {
                        "event": "script_loaded",
                        "script": script_name,
                        "target": target,
                    },
                },
                {
                    "type": "send",
                    "payload": {
                        "event": "security_control_observed",
                        "control": "certificate_pinning",
                        "action": "runtime hook installed in mock session",
                    },
                },
            ]
            return FridaExecution(
                CapabilityStatus.AVAILABLE,
                "Mock Frida 세션에서 스크립트를 실행했습니다.",
                mode,
                target,
                script_name,
                command=f"mock frida --{mode} {target} --script {script_name}",
                messages=messages,
                stdout="\n".join(json.dumps(item, ensure_ascii=False) for item in messages),
                synthetic=True,
            )

        frida = self.settings.resolved_tool("frida")
        if not frida:
            return FridaExecution(
                CapabilityStatus.NOT_CONFIGURED,
                "frida CLI를 찾을 수 없습니다. Python 환경에 frida-tools를 설치하거나 경로를 지정하세요.",
                mode,
                target,
                script_name,
            )
        with tempfile.TemporaryDirectory(prefix="msw-frida-run-") as temp:
            path = Path(temp) / "script.js"
            path.write_text(script_content, encoding="utf-8")
            args = [frida, "-D", device_id]
            if mode == "attach":
                args.extend(["-n", target])
            else:
                args.extend(["-f", target])
            args.extend(["-l", str(path), "-q"])
            result = await run_command(args, timeout=timeout_seconds)

        messages = []
        for line in result.stdout.splitlines():
            try:
                parsed = json.loads(line)
                if isinstance(parsed, dict):
                    messages.append(parsed)
            except json.JSONDecodeError:
                messages.append({"type": "console", "payload": line})
        # A live Frida session commonly reaches the collection timeout. Preserve output and
        # report it as a completed observation if messages were received.
        status = result.status
        message = result.error or result.stderr.strip()
        if messages and result.error and "안에 명령이 끝나지 않아" in result.error:
            status = CapabilityStatus.AVAILABLE
            message = "수집 시간 동안 Frida 메시지를 수신한 뒤 세션을 종료했습니다."
        elif result.ok:
            message = "Frida 스크립트 실행을 완료했습니다."
        return FridaExecution(
            status,
            message or "Frida 실행이 종료되었습니다.",
            mode,
            target,
            script_name,
            command=result.display_command,
            messages=messages,
            stdout=result.stdout,
            stderr=result.stderr,
        )
