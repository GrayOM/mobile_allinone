from __future__ import annotations

import asyncio
import os
import signal
import subprocess

import psutil


def subprocess_group_options() -> dict[str, object]:
    if os.name == "nt":
        return {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
    return {"start_new_session": True}


async def terminate_process_tree(
    process: asyncio.subprocess.Process, *, timeout: float = 5.0
) -> None:
    if process.returncode is not None:
        return
    try:
        parent = psutil.Process(process.pid)
        descendants = parent.children(recursive=True)
        for child in descendants:
            child.terminate()
        parent.terminate()
        _, alive = await asyncio.to_thread(
            psutil.wait_procs, [*descendants, parent], timeout=timeout
        )
        for item in alive:
            item.kill()
        await process.wait()
        return
    except (psutil.Error, ProcessLookupError):
        pass
    if os.name == "nt":
        killer = await asyncio.create_subprocess_exec(
            "taskkill",
            "/PID",
            str(process.pid),
            "/T",
            "/F",
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await killer.wait()
    else:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            return
    try:
        await asyncio.wait_for(process.wait(), timeout=timeout)
    except asyncio.TimeoutError:
        if os.name == "nt":
            process.kill()
        else:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        await process.wait()


async def watch_process_limits(
    process: asyncio.subprocess.Process,
    *,
    memory_limit_mb: int | None,
    cpu_limit_seconds: int | None,
) -> str | None:
    if not memory_limit_mb and not cpu_limit_seconds:
        return None
    memory_limit = (memory_limit_mb or 0) * 1024 * 1024
    while process.returncode is None:
        try:
            parent = psutil.Process(process.pid)
            processes = [parent, *parent.children(recursive=True)]
            memory = sum(item.memory_info().rss for item in processes if item.is_running())
            cpu = sum(
                item.cpu_times().user + item.cpu_times().system
                for item in processes
                if item.is_running()
            )
            if memory_limit and memory > memory_limit:
                return f"프로세스 트리 메모리가 {memory_limit_mb}MB 제한을 초과했습니다."
            if cpu_limit_seconds and cpu > cpu_limit_seconds:
                return f"프로세스 트리 CPU 시간이 {cpu_limit_seconds}초 제한을 초과했습니다."
        except (psutil.Error, ProcessLookupError):
            if process.returncode is not None:
                return None
        await asyncio.sleep(0.25)
    return None
