from __future__ import annotations

import asyncio
import shlex
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping, Sequence

from backend.app.core.status import CapabilityStatus


@dataclass(slots=True)
class CommandResult:
    status: CapabilityStatus
    command: list[str]
    return_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    error: str | None = None
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at: datetime | None = None

    @property
    def display_command(self) -> str:
        return " ".join(shlex.quote(part) for part in self.command)

    @property
    def ok(self) -> bool:
        return self.status == CapabilityStatus.AVAILABLE and self.return_code == 0


async def run_command(
    args: Sequence[str],
    *,
    timeout: int = 30,
    cwd: Path | None = None,
    env: Mapping[str, str] | None = None,
    input_data: bytes | None = None,
) -> CommandResult:
    command = [str(part) for part in args]
    result = CommandResult(status=CapabilityStatus.FAILED, command=command)
    if not command or not command[0]:
        result.status = CapabilityStatus.NOT_CONFIGURED
        result.error = "실행 파일이 설정되지 않았습니다."
        result.finished_at = datetime.now(timezone.utc)
        return result

    try:
        process = await asyncio.create_subprocess_exec(
            *command,
            cwd=str(cwd) if cwd else None,
            env=dict(env) if env else None,
            stdin=asyncio.subprocess.PIPE if input_data is not None else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(
            process.communicate(input_data), timeout=timeout
        )
        result.return_code = process.returncode
        result.stdout = stdout.decode("utf-8", errors="replace")
        result.stderr = stderr.decode("utf-8", errors="replace")
        result.status = (
            CapabilityStatus.AVAILABLE
            if process.returncode == 0
            else CapabilityStatus.FAILED
        )
    except FileNotFoundError:
        result.status = CapabilityStatus.NOT_CONFIGURED
        result.error = f"실행 파일을 찾을 수 없습니다: {command[0]}"
    except asyncio.TimeoutError:
        result.status = CapabilityStatus.FAILED
        result.error = f"{timeout}초 안에 명령이 끝나지 않아 중단했습니다."
        if "process" in locals():
            process.kill()
            await process.wait()
    except OSError as exc:
        result.status = CapabilityStatus.FAILED
        result.error = str(exc)
    result.finished_at = datetime.now(timezone.utc)
    return result

