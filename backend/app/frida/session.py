from __future__ import annotations

import asyncio
import importlib
import json
import threading
from dataclasses import asdict, dataclass, field
from typing import Any, Callable

from backend.app.core.config import AppSettings, get_settings
from backend.app.core.status import CapabilityStatus

from .manager import FridaManager


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

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["status"] = self.status.value
        return value


@dataclass(slots=True)
class _ActiveSession:
    run_id: str
    mode: str
    target: str
    device: Any = None
    session: Any = None
    scripts: dict[str, Any] = field(default_factory=dict)
    messages: list[dict[str, Any]] = field(default_factory=list)
    spawned_pid: int | None = None
    detached_reason: str | None = None
    synthetic: bool = False
    lock: threading.Lock = field(default_factory=threading.Lock)
    on_message: Callable[[dict[str, Any]], None] | None = None


class FridaSessionManager:
    """Own one long-lived Frida session per diagnostic Run."""

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

    def snapshot(self, run_id: str) -> list[dict[str, Any]]:
        active = self._sessions.get(run_id)
        if not active:
            return []
        with active.lock:
            return list(active.messages)

    async def start(
        self,
        *,
        run_id: str,
        device_id: str,
        target: str,
        scripts: list[FridaSessionScript],
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
        for script in scripts:
            syntax_status, syntax_message = await self.syntax.check_syntax(script.content)
            if syntax_status != CapabilityStatus.AVAILABLE:
                return FridaSessionResult(
                    syntax_status,
                    f"{script.name} 구문 검증을 완료할 수 없습니다: {syntax_message}",
                    mode,
                    target,
                    failed_scripts={script.script_id: syntax_message},
                )

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
                synthetic=mock,
                on_message=on_message,
            )
            self._sessions[run_id] = active

        def record(script_id: str, script_name: str, message: Any, data: Any) -> None:
            item = {
                "script_id": script_id,
                "script_name": script_name,
                "message": message if isinstance(message, dict) else {"type": "message", "payload": message},
                "data": data,
            }
            with active.lock:
                active.messages.append(item)
            if active.on_message:
                active.on_message(item)

        if mock:
            for script in scripts:
                record(
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
            return FridaSessionResult(
                CapabilityStatus.AVAILABLE,
                "Mock Frida 세션을 Run 종료까지 유지합니다.",
                mode,
                target,
                command=f"mock frida-session --{mode} {target}",
                loaded_script_ids=[script.script_id for script in scripts],
                messages=self.snapshot(run_id),
                stdout=messages_as_text(self.snapshot(run_id)),
                synthetic=True,
            )

        try:
            frida_module = importlib.import_module("frida")
        except ImportError:
            await self.stop(run_id)
            return FridaSessionResult(
                CapabilityStatus.NOT_CONFIGURED,
                "Python frida 바인딩을 찾을 수 없습니다. frida-tools를 설치한 Python 환경으로 서버를 실행하세요.",
                mode,
                target,
            )

        def connect() -> None:
            active.device = frida_module.get_device(device_id, timeout=5)
            if mode == "spawn":
                active.spawned_pid = active.device.spawn([target])
                active.session = active.device.attach(active.spawned_pid)
            else:
                active.session = active.device.attach(target)
            if hasattr(active.session, "on"):
                active.session.on(
                    "detached",
                    lambda reason, crash=None: (
                        setattr(active, "detached_reason", str(reason)),
                        record(
                            "session",
                            "session",
                            {
                                "type": "detached",
                                "payload": {"reason": str(reason), "crash": str(crash or "")},
                            },
                            None,
                        ),
                    ),
                )
            try:
                for script in scripts:
                    loaded = active.session.create_script(script.content, name=script.name)
                    loaded.on(
                        "message",
                        lambda message, data, script_id=script.script_id, script_name=script.name: record(
                            script_id, script_name, message, data
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
            await self.stop(run_id)
            return FridaSessionResult(
                CapabilityStatus.FAILED,
                f"Frida 세션 연결 실패: {type(exc).__name__}: {exc}",
                mode,
                target,
            )
        return FridaSessionResult(
            CapabilityStatus.AVAILABLE,
            "Frida 세션과 모든 스크립트를 연결했으며 Run 종료까지 유지합니다.",
            mode,
            target,
            command=f"python-frida -D {device_id} --{mode} {target} --persistent",
            loaded_script_ids=list(active.scripts),
            messages=self.snapshot(run_id),
            stdout=messages_as_text(self.snapshot(run_id)),
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
            return failures

        failures = {} if active.synthetic else await asyncio.to_thread(detach)
        messages = self.snapshot(run_id) if run_id in self._sessions else list(active.messages)
        status = CapabilityStatus.AVAILABLE if not failures else CapabilityStatus.FAILED
        return FridaSessionResult(
            status,
            "Frida 세션을 분리했습니다." if not failures else "Frida 세션 일부를 정리하지 못했습니다.",
            active.mode,
            active.target,
            loaded_script_ids=list(active.scripts),
            failed_scripts=failures,
            messages=messages,
            stdout=messages_as_text(messages),
            synthetic=active.synthetic,
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
            return FridaSessionResult(
                CapabilityStatus.AVAILABLE,
                "스크립트가 이미 Run 수명 Frida 세션에 로드되어 있습니다.",
                active.mode,
                active.target,
                loaded_script_ids=[script.script_id],
                messages=self.snapshot(run_id),
                synthetic=active.synthetic,
            )
        syntax_status, syntax_message = await self.syntax.check_syntax(script.content)
        if syntax_status != CapabilityStatus.AVAILABLE:
            return FridaSessionResult(
                syntax_status,
                f"스크립트 구문 검증을 완료할 수 없습니다: {syntax_message}",
                active.mode,
                active.target,
                failed_scripts={script.script_id: syntax_message},
            )

        def record(message: Any, data: Any) -> None:
            item = {
                "script_id": script.script_id,
                "script_name": script.name,
                "message": message if isinstance(message, dict) else {"type": "message", "payload": message},
                "data": data,
            }
            with active.lock:
                active.messages.append(item)
            if active.on_message:
                active.on_message(item)

        if active.synthetic:
            active.scripts[script.script_id] = None
            record(
                {
                    "type": "send",
                    "payload": {"event": "script_loaded", "script": script.name},
                },
                None,
            )
        else:
            def load() -> None:
                loaded = active.session.create_script(script.content, name=script.name)
                loaded.on("message", record)
                loaded.load()
                active.scripts[script.script_id] = loaded

            try:
                await asyncio.to_thread(load)
            except Exception as exc:
                return FridaSessionResult(
                    CapabilityStatus.FAILED,
                    f"Frida 스크립트 추가 로드 실패: {type(exc).__name__}: {exc}",
                    active.mode,
                    active.target,
                    failed_scripts={script.script_id: str(exc)},
                )
        messages = self.snapshot(run_id)
        return FridaSessionResult(
            CapabilityStatus.AVAILABLE,
            "스크립트를 기존 Run 수명 Frida 세션에 추가했습니다.",
            active.mode,
            active.target,
            command=f"python-frida --persistent-load {script.name}",
            loaded_script_ids=[script.script_id],
            messages=messages,
            stdout=messages_as_text(messages),
            synthetic=active.synthetic,
        )

    async def shutdown(self) -> None:
        await asyncio.gather(
            *(self.stop(run_id) for run_id in list(self._sessions)),
            return_exceptions=True,
        )


def messages_as_text(messages: list[dict[str, Any]]) -> str:
    return "\n".join(json.dumps(item, ensure_ascii=False, default=str) for item in messages)
