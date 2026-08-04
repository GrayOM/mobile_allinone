from __future__ import annotations

import asyncio
import shlex
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

from backend.app.core.status import CapabilityStatus
from backend.app.core.process import (
    subprocess_group_options,
    terminate_process_tree,
    watch_process_limits,
)


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
    memory_limit_mb: int | None = None,
    cpu_limit_seconds: int | None = None,
) -> CommandResult:
    command = [str(part) for part in args]
    result = CommandResult(status=CapabilityStatus.FAILED, command=command)
    communicate: asyncio.Task[tuple[bytes, bytes]] | None = None
    limits: asyncio.Task[str | None] | None = None
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
            **subprocess_group_options(),
        )
        communicate = asyncio.create_task(process.communicate(input_data))
        watched: set[asyncio.Task[Any]] = {communicate}
        if memory_limit_mb or cpu_limit_seconds:
            limits = asyncio.create_task(
                watch_process_limits(
                    process,
                    memory_limit_mb=memory_limit_mb,
                    cpu_limit_seconds=cpu_limit_seconds,
                )
            )
            watched.add(limits)
        done, _ = await asyncio.wait_for(
            asyncio.wait(watched, return_when=asyncio.FIRST_COMPLETED),
            timeout=timeout,
        )
        limit_error = limits.result() if limits is not None and limits in done else None
        if limit_error:
            await terminate_process_tree(process)
            stdout, stderr = await communicate
            result.return_code = process.returncode
            result.error = limit_error
            result.stdout = stdout.decode("utf-8", errors="replace")
            result.stderr = stderr.decode("utf-8", errors="replace")
            result.finished_at = datetime.now(timezone.utc)
            return result
        stdout, stderr = await communicate
        if limits is not None:
            limits.cancel()
            await asyncio.gather(limits, return_exceptions=True)
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
            await terminate_process_tree(process)
    except asyncio.CancelledError:
        if "process" in locals():
            await terminate_process_tree(process)
        raise
    except OSError as exc:
        result.status = CapabilityStatus.FAILED
        result.error = str(exc)
    finally:
        pending = [
            task
            for task in (communicate, limits)
            if task is not None and not task.done()
        ]
        for task in pending:
            task.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)
    result.finished_at = datetime.now(timezone.utc)
    return result
