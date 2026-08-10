from __future__ import annotations

import asyncio
import base64
import importlib
import json
import queue
import threading
import time
from collections import deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from backend.app.core.config import AppSettings, get_settings
from backend.app.core.status import CapabilityStatus

from .manager import FridaManager
from .target import FridaTarget


@dataclass(slots=True)
class FridaSessionScript:
    script_id: str
    name: str
    content: str


@dataclass(slots=True)
class FridaSessionResult:
    status: CapabilityStatus
    message: str
    mode: str
    target: str
    command: str | None = None
    stdout: str = ""
    stderr: str = ""
    loaded_script_ids: list[str] = field(default_factory=list)
    failed_scripts: dict[str, str] = field(default_factory=dict)
    messages: list[dict[str, Any]] = field(default_factory=list)
    synthetic: bool = False
    transport: str | None = None
    device_id: str | None = None
    endpoint: str | None = None
    transcript_path: str | None = None
    stats: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["status"] = self.status.value
        return value


@dataclass(slots=True)
class _ActiveSession:
    run_id: str
    mode: str
    target: str
    frida_target: FridaTarget
    transcript_path: Path
    messages: deque[dict[str, Any]]
    transcript_queue: queue.Queue[bytes]
    device: Any = None
    session: Any = None
    scripts: dict[str, Any] = field(default_factory=dict)
    spawned_pid: int | None = None
    detached_reason: str | None = None
    synthetic: bool = False
    lock: threading.Lock = field(default_factory=threading.Lock)
    on_message: Callable[[dict[str, Any]], None] | None = None
    transcript_bytes: int = 0
    total_message_count: int = 0
    dropped_count: int = 0
    truncated_count: int = 0
    buffer_overwrite_count: int = 0
    stream_sampled_count: int = 0
    last_streamed_at: float = 0.0
    connected_device: dict[str, str | None] = field(default_factory=dict)
    transcript_pending_bytes: int = 0
    writer_stop: threading.Event = field(default_factory=threading.Event)
    writer_task: asyncio.Task[None] | None = None
    writer_error: str | None = None
    device_manager: Any = None


class FridaSessionManager:
    """Own one long-lived, bounded Frida session per diagnostic Run."""

    def __init__(self, settings: AppSettings | None = None):
        self.settings = settings or get_settings()
        self.syntax = FridaManager(self.settings)
        self._sessions: dict[str, _ActiveSession] = {}
        self._lock = asyncio.Lock()

    def is_active(self, run_id: str) -> bool:
        return run_id in self._sessions

    def is_healthy(self, run_id: str) -> bool:
        active = self._sessions.get(run_id)
        return bool(active and not active.detached_reason)

    def set_message_callback(
        self, run_id: str, callback: Callable[[dict[str, Any]], None]
    ) -> None:
        active = self._sessions.get(run_id)
        if active:
            active.on_message = callback

    def snapshot(
        self, run_id: str, *, limit: int | None = None
    ) -> list[dict[str, Any]]:
        active = self._sessions.get(run_id)
        if not active:
            return []
        with active.lock:
            values = list(active.messages)
        return values[-limit:] if limit is not None else values

    def health(self, run_id: str) -> dict[str, Any]:
        active = self._sessions.get(run_id)
        if not active:
            return {
                "active": False,
                "healthy": False,
                "run_id": run_id,
            }
        return self._health(active)

    def _health(self, active: _ActiveSession) -> dict[str, Any]:
        with active.lock:
            return {
                "active": True,
                "healthy": not bool(active.detached_reason),
                "run_id": active.run_id,
                "mode": active.mode,
                "app_target": active.target,
                "transport": active.frida_target.transport,
                "device_id": active.frida_target.device_id,
                "endpoint": active.frida_target.endpoint,
                "actual_device": dict(active.connected_device),
                "loaded_script_ids": list(active.scripts),
                "buffer_count": len(active.messages),
                "buffer_capacity": self.settings.frida_message_buffer_size,
                "total_message_count": active.total_message_count,
                "buffer_overwrite_count": active.buffer_overwrite_count,
                "dropped_count": active.dropped_count,
                "truncated_count": active.truncated_count,
                "stream_sampled_count": active.stream_sampled_count,
                "transcript_path": str(active.transcript_path),
                "transcript_bytes": active.transcript_bytes,
                "transcript_pending_bytes": active.transcript_pending_bytes,
                "transcript_queue_count": active.transcript_queue.qsize(),
                "transcript_queue_capacity": self.settings.frida_transcript_queue_size,
                "transcript_max_bytes": self.settings.frida_transcript_max_bytes,
                "message_max_bytes": self.settings.frida_message_max_bytes,
                "detached_reason": active.detached_reason,
                "writer_error": active.writer_error,
                "synthetic": active.synthetic,
            }

    @staticmethod
    def _transcript_writer(active: _ActiveSession) -> None:
        try:
            with active.transcript_path.open("ab") as stream:
                while (
                    not active.writer_stop.is_set()
                    or not active.transcript_queue.empty()
                ):
                    try:
                        line = active.transcript_queue.get(timeout=0.05)
                    except queue.Empty:
                        continue
                    try:
                        stream.write(line)
                        if active.transcript_queue.empty():
                            stream.flush()
                        with active.lock:
                            active.transcript_bytes += len(line)
                            active.transcript_pending_bytes = max(
                                0, active.transcript_pending_bytes - len(line)
                            )
                    except Exception as exc:
                        with active.lock:
                            active.writer_error = f"{type(exc).__name__}: {exc}"
                            active.dropped_count += 1
                            active.transcript_pending_bytes = max(
                                0, active.transcript_pending_bytes - len(line)
                            )
                    finally:
                        active.transcript_queue.task_done()
        except Exception as exc:
            with active.lock:
                active.writer_error = f"{type(exc).__name__}: {exc}"
            while True:
                try:
                    line = active.transcript_queue.get_nowait()
                except queue.Empty:
                    break
                with active.lock:
                    active.dropped_count += 1
                    active.transcript_pending_bytes = max(
                        0, active.transcript_pending_bytes - len(line)
                    )
                active.transcript_queue.task_done()

    async def flush_transcript(self, run_id: str) -> bool:
        active = self._sessions.get(run_id)
        if not active:
            return False
        try:
            await asyncio.wait_for(
                asyncio.to_thread(active.transcript_queue.join),
                timeout=self.settings.frida_transcript_flush_timeout_seconds,
            )
            return not bool(active.writer_error)
        except asyncio.TimeoutError:
            return False

    async def _stop_writer(self, active: _ActiveSession) -> bool:
        try:
            await asyncio.wait_for(
                asyncio.to_thread(active.transcript_queue.join),
                timeout=self.settings.frida_transcript_flush_timeout_seconds,
            )
            flushed = not bool(active.writer_error)
        except asyncio.TimeoutError:
            flushed = False
        active.writer_stop.set()
        if active.writer_task:
            try:
                await asyncio.wait_for(
                    asyncio.shield(active.writer_task),
                    timeout=self.settings.frida_transcript_flush_timeout_seconds,
                )
            except asyncio.TimeoutError:
                with active.lock:
                    active.writer_error = "transcript writer shutdown timeout"
                return False
        return flushed and not bool(active.writer_error)

    def _record(
        self,
        active: _ActiveSession,
        script_id: str,
        script_name: str,
        message: Any,
        data: Any,
    ) -> None:
        item = _serialize_message(
            script_id,
            script_name,
            message,
            data,
            max_bytes=self.settings.frida_message_max_bytes,
        )
        disk_item = {key: value for key, value in item.items() if key != "message"}
        line = _json_bytes(disk_item)
        if len(line) > self.settings.frida_message_max_bytes:
            item = _hard_limit_message(item)
            disk_item = {
                key: value for key, value in item.items() if key != "message"
            }
            line = _json_bytes(disk_item)
        line += b"\n"
        callback: Callable[[dict[str, Any]], None] | None = None
        with active.lock:
            active.total_message_count += 1
            if item["truncated"]:
                active.truncated_count += 1
            if len(active.messages) == active.messages.maxlen:
                active.buffer_overwrite_count += 1
            active.messages.append(item)
            if active.writer_error:
                active.dropped_count += 1
            elif (
                active.transcript_bytes + active.transcript_pending_bytes + len(line)
                <= self.settings.frida_transcript_max_bytes
            ):
                try:
                    active.transcript_queue.put_nowait(line)
                    active.transcript_pending_bytes += len(line)
                except queue.Full:
                    active.dropped_count += 1
            else:
                active.dropped_count += 1

            if active.on_message:
                now = time.monotonic()
                minimum_interval = 1 / self.settings.frida_stream_events_per_second
                if now - active.last_streamed_at >= minimum_interval:
                    active.last_streamed_at = now
                    callback = active.on_message
                else:
                    active.stream_sampled_count += 1
        if callback:
            try:
                callback(item)
            except Exception:
                # Streaming is observational and must never terminate the Frida session.
                pass

    async def start(
        self,
        *,
        run_id: str,
        target: str,
        scripts: list[FridaSessionScript],
        device_id: str | None = None,
        frida_target: FridaTarget | None = None,
        mode: str = "attach",
        mock: bool = False,
        on_message: Callable[[dict[str, Any]], None] | None = None,
    ) -> FridaSessionResult:
        if mode not in {"spawn", "attach"}:
            return FridaSessionResult(
                CapabilityStatus.FAILED,
                "Frida 세션 모드는 spawn 또는 attach여야 합니다.",
                mode,
                target,
            )
        if not scripts:
            return FridaSessionResult(
                CapabilityStatus.AVAILABLE,
                "선택된 Frida 스크립트가 없어 세션을 시작하지 않았습니다.",
                mode,
                target,
                synthetic=mock,
            )
        try:
            resolved_target = frida_target or FridaTarget.usb(str(device_id or ""))
        except ValueError as exc:
            return FridaSessionResult(
                CapabilityStatus.NOT_CONFIGURED,
                str(exc),
                mode,
                target,
                synthetic=mock,
            )
        for script in scripts:
            syntax_status, syntax_message = await self.syntax.check_syntax(script.content)
            if syntax_status != CapabilityStatus.AVAILABLE:
                return FridaSessionResult(
                    syntax_status,
                    f"{script.name} 구문 검증을 완료할 수 없습니다: {syntax_message}",
                    mode,
                    target,
                    failed_scripts={script.script_id: syntax_message},
                    transport=resolved_target.transport,
                    device_id=resolved_target.device_id,
                    endpoint=resolved_target.endpoint,
                )

        transcript_path = self.settings.evidence_dir / run_id / "frida-session.jsonl"
        transcript_path.parent.mkdir(parents=True, exist_ok=True)
        transcript_path.touch(exist_ok=True)
        async with self._lock:
            if run_id in self._sessions:
                return FridaSessionResult(
                    CapabilityStatus.FAILED,
                    "이 Run에는 이미 Frida 세션이 연결되어 있습니다.",
                    mode,
                    target,
                )
            active = _ActiveSession(
                run_id=run_id,
                mode=mode,
                target=target,
                frida_target=resolved_target,
                transcript_path=transcript_path,
                transcript_bytes=transcript_path.stat().st_size,
                messages=deque(maxlen=self.settings.frida_message_buffer_size),
                transcript_queue=queue.Queue(
                    maxsize=self.settings.frida_transcript_queue_size
                ),
                synthetic=mock,
                on_message=on_message,
            )
            active.writer_task = asyncio.create_task(
                asyncio.to_thread(self._transcript_writer, active),
                name=f"frida-transcript-{run_id}",
            )
            self._sessions[run_id] = active

        if mock:
            active.connected_device = {
                "id": resolved_target.display,
                "name": "Mock Frida Device",
                "type": "synthetic",
            }
            for script in scripts:
                self._record(
                    active,
                    script.script_id,
                    script.name,
                    {
                        "type": "send",
                        "payload": {
                            "event": "script_loaded",
                            "script": script.name,
                            "target": target,
                        },
                    },
                    None,
                )
                active.scripts[script.script_id] = None
            return self._result(
                active,
                CapabilityStatus.AVAILABLE,
                "Mock Frida 세션을 Run 종료까지 유지합니다.",
                command=(
                    f"mock frida-session {resolved_target.command_option} "
                    f"{resolved_target.display} --{mode} {target}"
                ),
                loaded_script_ids=[script.script_id for script in scripts],
            )

        try:
            frida_module = importlib.import_module("frida")
        except ImportError:
            stopped = await self.stop(run_id)
            return FridaSessionResult(
                CapabilityStatus.NOT_CONFIGURED,
                "Python frida 바인딩을 찾을 수 없습니다. frida-tools를 설치한 Python 환경으로 서버를 실행하세요.",
                mode,
                target,
                transport=resolved_target.transport,
                device_id=resolved_target.device_id,
                endpoint=resolved_target.endpoint,
                transcript_path=str(transcript_path),
                stats=stopped.stats if stopped else {},
            )

        def connect() -> None:
            if resolved_target.transport == "remote":
                active.device_manager = frida_module.get_device_manager()
                active.device = active.device_manager.add_remote_device(
                    str(resolved_target.endpoint)
                )
            else:
                active.device = frida_module.get_device(
                    str(resolved_target.device_id), timeout=5
                )
            active.connected_device = {
                "id": str(getattr(active.device, "id", resolved_target.display)),
                "name": str(getattr(active.device, "name", "")) or None,
                "type": str(getattr(active.device, "type", "")) or None,
            }
            if mode == "spawn":
                active.spawned_pid = active.device.spawn([target])
                active.session = active.device.attach(active.spawned_pid)
            else:
                active.session = active.device.attach(target)
            if hasattr(active.session, "on"):
                def detached(reason, crash=None) -> None:
                    active.detached_reason = str(reason)
                    self._record(
                        active,
                        "session",
                        "session",
                        {
                            "type": "detached",
                            "payload": {
                                "reason": str(reason),
                                "crash": str(crash or ""),
                            },
                        },
                        None,
                    )

                active.session.on("detached", detached)
            try:
                for script in scripts:
                    loaded = active.session.create_script(script.content, name=script.name)
                    loaded.on(
                        "message",
                        lambda message, data, script_id=script.script_id, script_name=script.name: self._record(
                            active, script_id, script_name, message, data
                        ),
                    )
                    loaded.load()
                    active.scripts[script.script_id] = loaded
                if active.spawned_pid is not None:
                    active.device.resume(active.spawned_pid)
            except Exception:
                if active.spawned_pid is not None:
                    try:
                        active.device.resume(active.spawned_pid)
                    except Exception:
                        pass
                raise

        try:
            await asyncio.to_thread(connect)
        except Exception as exc:
            stopped = await self.stop(run_id)
            return FridaSessionResult(
                CapabilityStatus.FAILED,
                f"Frida 세션 연결 실패: {type(exc).__name__}: {exc}",
                mode,
                target,
                transport=resolved_target.transport,
                device_id=resolved_target.device_id,
                endpoint=resolved_target.endpoint,
                transcript_path=str(transcript_path),
                stats=stopped.stats if stopped else {},
            )
        return self._result(
            active,
            CapabilityStatus.AVAILABLE,
            "Frida 세션과 모든 스크립트를 연결했으며 Run 종료까지 유지합니다.",
            command=(
                f"python-frida {resolved_target.command_option} {resolved_target.display} "
                f"--{mode} {target} --persistent"
            ),
            loaded_script_ids=list(active.scripts),
        )

    def _result(
        self,
        active: _ActiveSession,
        status: CapabilityStatus,
        message: str,
        *,
        command: str | None = None,
        loaded_script_ids: list[str] | None = None,
        failed_scripts: dict[str, str] | None = None,
    ) -> FridaSessionResult:
        with active.lock:
            messages = list(active.messages)[-20:]
        stats = self._health(active)
        return FridaSessionResult(
            status,
            message,
            active.mode,
            active.target,
            command=command,
            loaded_script_ids=loaded_script_ids or [],
            failed_scripts=failed_scripts or {},
            messages=messages,
            stdout=messages_as_text(messages),
            synthetic=active.synthetic,
            transport=active.frida_target.transport,
            device_id=active.frida_target.device_id,
            endpoint=active.frida_target.endpoint,
            transcript_path=str(active.transcript_path),
            stats=stats,
        )

    async def stop(self, run_id: str) -> FridaSessionResult | None:
        async with self._lock:
            active = self._sessions.pop(run_id, None)
        if not active:
            return None

        def detach() -> dict[str, str]:
            failures: dict[str, str] = {}
            for script_id, script in list(active.scripts.items())[::-1]:
                if script is None:
                    continue
                try:
                    script.unload()
                except Exception as exc:
                    failures[script_id] = f"{type(exc).__name__}: {exc}"
            if active.session is not None:
                try:
                    active.session.detach()
                except Exception as exc:
                    failures["session"] = f"{type(exc).__name__}: {exc}"
            if (
                active.frida_target.transport == "remote"
                and active.device_manager is not None
            ):
                try:
                    active.device_manager.remove_remote_device(
                        str(active.frida_target.endpoint)
                    )
                except Exception as exc:
                    failures["remote_device"] = f"{type(exc).__name__}: {exc}"
            return failures

        failures = {} if active.synthetic else await asyncio.to_thread(detach)
        writer_ok = await self._stop_writer(active)
        if not writer_ok:
            failures["transcript_writer"] = active.writer_error or "flush timeout"
        return self._result(
            active,
            CapabilityStatus.AVAILABLE if not failures else CapabilityStatus.FAILED,
            (
                "Frida 세션을 분리했습니다."
                if not failures
                else "Frida 세션 일부를 정리하지 못했습니다."
            ),
            loaded_script_ids=list(active.scripts),
            failed_scripts=failures,
        )

    async def load_script(
        self,
        run_id: str,
        script: FridaSessionScript,
    ) -> FridaSessionResult:
        active = self._sessions.get(run_id)
        if not active:
            return FridaSessionResult(
                CapabilityStatus.FAILED,
                "활성 Frida 세션이 없습니다.",
                "attach",
                "",
                failed_scripts={script.script_id: "session_not_active"},
            )
        if script.script_id in active.scripts:
            return self._result(
                active,
                CapabilityStatus.AVAILABLE,
                "스크립트가 이미 Run 수명 Frida 세션에 로드되어 있습니다.",
                loaded_script_ids=[script.script_id],
            )
        syntax_status, syntax_message = await self.syntax.check_syntax(script.content)
        if syntax_status != CapabilityStatus.AVAILABLE:
            return self._result(
                active,
                syntax_status,
                f"스크립트 구문 검증을 완료할 수 없습니다: {syntax_message}",
                failed_scripts={script.script_id: syntax_message},
            )

        if active.synthetic:
            active.scripts[script.script_id] = None
            self._record(
                active,
                script.script_id,
                script.name,
                {
                    "type": "send",
                    "payload": {"event": "script_loaded", "script": script.name},
                },
                None,
            )
        else:
            def load() -> None:
                loaded = active.session.create_script(script.content, name=script.name)
                loaded.on(
                    "message",
                    lambda message, data: self._record(
                        active, script.script_id, script.name, message, data
                    ),
                )
                loaded.load()
                active.scripts[script.script_id] = loaded

            try:
                await asyncio.to_thread(load)
            except Exception as exc:
                return self._result(
                    active,
                    CapabilityStatus.FAILED,
                    f"Frida 스크립트 추가 로드 실패: {type(exc).__name__}: {exc}",
                    failed_scripts={script.script_id: str(exc)},
                )
        return self._result(
            active,
            CapabilityStatus.AVAILABLE,
            "스크립트를 기존 Run 수명 Frida 세션에 추가했습니다.",
            command=f"python-frida --persistent-load {script.name}",
            loaded_script_ids=[script.script_id],
        )

    async def shutdown(self) -> None:
        await asyncio.gather(
            *(self.stop(run_id) for run_id in list(self._sessions)),
            return_exceptions=True,
        )


def _json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")


def _json_safe(value: Any) -> Any:
    try:
        return json.loads(_json_bytes(value))
    except (TypeError, ValueError):
        return str(value)


def _binary_data(value: bytes, preview_bytes: int | None = None) -> dict[str, Any]:
    selected = value if preview_bytes is None else value[:preview_bytes]
    result: dict[str, Any] = {
        "encoding": "base64",
        "size": len(value),
        "data": base64.b64encode(selected).decode("ascii"),
    }
    if len(selected) < len(value):
        result["truncated"] = True
    return result


def _serialize_message(
    script_id: str,
    script_name: str,
    message: Any,
    data: Any,
    *,
    max_bytes: int,
) -> dict[str, Any]:
    safe_message = _json_safe(message)
    if isinstance(safe_message, dict):
        message_type = str(safe_message.get("type") or "message")
        payload = safe_message.get("payload", safe_message)
    else:
        message_type = "message"
        payload = safe_message

    binary = bytes(data) if isinstance(data, (bytes, bytearray, memoryview)) else None
    safe_data = _json_safe(data) if data is not None and binary is None else None
    payload_bytes = _json_bytes(payload)
    if binary is not None:
        data_size = ((len(binary) + 2) // 3) * 4
    elif safe_data is not None:
        data_size = len(_json_bytes(safe_data))
    else:
        data_size = 0
    original_size = len(payload_bytes) + data_size + 256
    truncated = original_size > max_bytes

    if truncated:
        preview_size = max(24, min(256, max_bytes // 8))
        bounded_payload: Any = {
            "encoding": "json_utf8",
            "size": len(payload_bytes),
            "preview": payload_bytes[:preview_size].decode("utf-8", errors="replace"),
        }
        if binary is not None:
            bounded_data: Any = _binary_data(binary, preview_size)
        elif safe_data is not None:
            raw_data = _json_bytes(safe_data)
            bounded_data = {
                "encoding": "json_utf8",
                "size": len(raw_data),
                "data": raw_data[:preview_size].decode("utf-8", errors="replace"),
                "truncated": len(raw_data) > preview_size,
            }
        else:
            bounded_data = None
    else:
        bounded_payload = payload
        if binary is not None:
            bounded_data = _binary_data(binary)
        elif safe_data is not None:
            encoded = _json_bytes(safe_data)
            bounded_data = {
                "encoding": "json",
                "size": len(encoded),
                "data": safe_data,
            }
        else:
            bounded_data = None

    normalized_message = {"type": message_type, "payload": bounded_payload}
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "script_id": script_id,
        "script_name": script_name,
        "message_type": message_type,
        "payload": bounded_payload,
        "data": bounded_data,
        "truncated": truncated,
        "original_size": original_size,
        # Kept as a compatibility alias for existing API consumers. The JSONL
        # transcript omits this duplicate and uses the normalized fields above.
        "message": normalized_message,
    }


def _hard_limit_message(item: dict[str, Any]) -> dict[str, Any]:
    payload_size = len(_json_bytes(item.get("payload")))
    data = item.get("data")
    if isinstance(data, dict):
        bounded_data = {
            "encoding": data.get("encoding", "omitted"),
            "size": data.get("size", 0),
            "data": "",
            "truncated": True,
        }
    else:
        bounded_data = None
    payload = {
        "encoding": "omitted",
        "size": payload_size,
        "preview": "",
    }
    item.update(
        {
            "script_id": str(item.get("script_id", ""))[:64],
            "script_name": str(item.get("script_name", ""))[:64],
            "message_type": str(item.get("message_type", "message"))[:32],
            "payload": payload,
            "data": bounded_data,
            "truncated": True,
            "message": {
                "type": str(item.get("message_type", "message"))[:32],
                "payload": payload,
            },
        }
    )
    return item


def messages_as_text(messages: list[dict[str, Any]]) -> str:
    return "\n".join(json.dumps(item, ensure_ascii=False, default=str) for item in messages)
