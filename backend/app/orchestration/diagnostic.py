from __future__ import annotations

import asyncio
import json
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.ai import AIProviderChain, MockAIProvider
from backend.app.ai.storage import save_ai_raw_response
from backend.app.core.config import AppSettings, get_settings
from backend.app.core.events import EventBus, event_bus
from backend.app.core.status import CapabilityStatus, RunMode, RunStatus
from backend.app.core.targets import (
    normalize_platform,
    platform_for_adapter,
    require_app_identifier,
)
from backend.app.database.models import (
    AIInvocation,
    AppArtifact,
    ControlTest,
    DiagnosticRun,
    Evidence,
    Finding,
    FindingSource,
    FridaScript,
    Project,
    ProxyFlow,
)
from backend.app.database.session import SessionLocal
from backend.app.devices import AndroidDeviceAdapter, IOSDeviceAdapter, MockDeviceAdapter
from backend.app.evidence import EvidenceService
from backend.app.frida import FridaManager
from backend.app.frida.policy import is_safe_automatic_script, script_applies_to_app
from backend.app.proxy import (
    BurpProxyAdapter,
    FiddlerProxyAdapter,
    MitmProxyAdapter,
    MockProxyAdapter,
)
from backend.app.runtime import DrozerRuntimeAdapter, ObjectionRuntimeAdapter
from backend.app.orchestration.resources import ResourceLeaseManager, allocate_available_port


class DiagnosticStopped(Exception):
    pass


class DiagnosticOrchestrator:
    def __init__(
        self,
        settings: AppSettings | None = None,
        events: EventBus | None = None,
    ):
        self.settings = settings or get_settings()
        self.events = events or event_bus
        self.evidence = EvidenceService(self.settings)
        self.frida = FridaManager(self.settings)
        self.ai_chain = AIProviderChain(settings=self.settings)
        self.mock_ai = MockAIProvider()
        self._tasks: dict[str, asyncio.Task[None]] = {}
        self._pause_events: dict[str, asyncio.Event] = {}
        self._stop_requested: set[str] = set()
        self._proxy_adapters: dict[str, Any] = {}
        self._leases = ResourceLeaseManager()
        self._proxy_start_lock = asyncio.Lock()
        self._state_lock = asyncio.Lock()
        self._safe_pause_waiting: set[str] = set()
        self._manual_active: set[str] = set()

    @property
    def leases(self) -> ResourceLeaseManager:
        return self._leases

    def proxy_adapter(self, run_id: str):
        return self._proxy_adapters.get(run_id)

    async def begin_manual_action(self, run_id: str) -> bool:
        async with self._state_lock:
            if run_id not in self._safe_pause_waiting or run_id in self._manual_active:
                return False
            self._manual_active.add(run_id)
            return True

    async def end_manual_action(self, run_id: str) -> None:
        async with self._state_lock:
            self._manual_active.discard(run_id)

    def launch(self, run_id: str) -> None:
        current = self._tasks.get(run_id)
        if current and not current.done():
            return
        pause_event = asyncio.Event()
        pause_event.set()
        self._pause_events[run_id] = pause_event
        self._tasks[run_id] = asyncio.create_task(
            self._execute(run_id), name=f"diagnostic-{run_id}"
        )

    async def pause(self, run_id: str, reason: str = "사용자가 일시정지했습니다.") -> bool:
        event = self._pause_events.get(run_id)
        if not event:
            return False
        async with self._state_lock:
            if run_id in self._safe_pause_waiting:
                return True
            event.clear()
        with SessionLocal() as db:
            run = db.get(DiagnosticRun, run_id)
            if run and run.status == RunStatus.RUNNING.value:
                run.status = RunStatus.PAUSE_REQUESTED.value
                db.commit()
            elif not run or run.status != RunStatus.PAUSE_REQUESTED.value:
                event.set()
                return False
        await self.events.publish(
            run_id,
            "run_status",
            {"status": RunStatus.PAUSE_REQUESTED.value, "message": reason},
        )
        return True

    async def resume(self, run_id: str) -> bool:
        event = self._pause_events.get(run_id)
        if not event:
            return False
        async with self._state_lock:
            if run_id not in self._safe_pause_waiting or run_id in self._manual_active:
                return False
            self._safe_pause_waiting.discard(run_id)
            event.set()
        with SessionLocal() as db:
            run = db.get(DiagnosticRun, run_id)
            if run and run.status in {
                RunStatus.SAFELY_PAUSED.value,
                RunStatus.PAUSED.value,
            }:
                run.status = RunStatus.RUNNING.value
                run.current_stage = "resuming"
                db.commit()
        await self.events.publish(
            run_id, "run_status", {"status": "running", "message": "진단을 재개했습니다."}
        )
        return True

    async def stop(self, run_id: str, *, wait: bool = True) -> bool:
        task = self._tasks.get(run_id)
        if not task or task.done():
            return False
        self._stop_requested.add(run_id)
        event = self._pause_events.get(run_id)
        if event:
            event.set()
        await self.events.publish(
            run_id, "run_status", {"status": "stopping", "message": "중지를 요청했습니다."}
        )
        if wait and task is not asyncio.current_task():
            try:
                await asyncio.wait_for(asyncio.shield(task), timeout=30)
            except asyncio.TimeoutError:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
        return True

    async def shutdown(self) -> None:
        run_ids = [run_id for run_id, task in self._tasks.items() if not task.done()]
        if run_ids:
            await asyncio.gather(
                *(self.stop(run_id, wait=True) for run_id in run_ids),
                return_exceptions=True,
            )

    async def _checkpoint(self, run_id: str) -> None:
        if run_id in self._stop_requested:
            raise DiagnosticStopped
        event = self._pause_events.get(run_id)
        if event and not event.is_set():
            async with self._state_lock:
                self._safe_pause_waiting.add(run_id)
            with SessionLocal() as db:
                run = db.get(DiagnosticRun, run_id)
                if run and run.status == RunStatus.PAUSE_REQUESTED.value:
                    run.status = RunStatus.SAFELY_PAUSED.value
                    db.commit()
            await self.events.publish(
                run_id,
                "run_status",
                {
                    "status": RunStatus.SAFELY_PAUSED.value,
                    "message": "현재 작업이 끝나 안전한 수동 조작 지점에 도달했습니다.",
                },
            )
            await event.wait()
        if run_id in self._stop_requested:
            raise DiagnosticStopped

    async def _stage(
        self, db: Session, run: DiagnosticRun, name: str, progress: int, message: str
    ) -> None:
        await self._checkpoint(run.id)
        run.status = RunStatus.RUNNING.value
        run.current_stage = name
        run.progress = progress
        db.commit()
        await self.events.publish(
            run.id,
            "stage",
            {
                "stage": name,
                "progress": progress,
                "message": message,
                "status": run.status,
            },
        )

    def _device(self, adapter: str):
        if adapter == "android_adb":
            return AndroidDeviceAdapter(self.settings)
        if adapter == "ios_windows":
            return IOSDeviceAdapter(self.settings)
        if adapter == "mock":
            return MockDeviceAdapter()
        raise ValueError(f"지원하지 않는 단말 Adapter입니다: {adapter}")

    def _proxy(self, run: DiagnosticRun):
        adapter = run.proxy_adapter
        if adapter == "mitmproxy":
            return MitmProxyAdapter(
                self.settings,
                host=str(run.options.get("proxy_listen_host") or self.settings.proxy_listen_host),
                port=int(run.options.get("proxy_port") or 8080),
                allowed_client_ip=str(run.options.get("proxy_allowed_client_ip") or "") or None,
            )
        if adapter == "fiddler":
            return FiddlerProxyAdapter(
                host=str(run.options.get("proxy_listen_host") or "127.0.0.1"),
                port=int(run.options.get("proxy_port") or 8080),
            )
        if adapter == "burp":
            return BurpProxyAdapter(
                host=str(run.options.get("proxy_listen_host") or "127.0.0.1"),
                port=int(run.options.get("proxy_port") or 8080),
            )
        if adapter == "mock":
            return MockProxyAdapter()
        raise ValueError(f"지원하지 않는 프록시 Adapter입니다: {adapter}")

    async def _start_proxy_with_retry(self, db: Session, run: DiagnosticRun, proxy):
        if run.proxy_adapter != "mitmproxy":
            return proxy, await proxy.start(run.id)
        attempted_ports: list[int] = []
        async with self._proxy_start_lock:
            for attempt in range(3):
                if attempt:
                    host = str(
                        run.options.get("proxy_listen_host")
                        or self.settings.proxy_listen_host
                    )
                    port = allocate_available_port(host)
                    for _ in range(10):
                        if port not in attempted_ports:
                            break
                        port = allocate_available_port(host)
                    if port in attempted_ports:
                        raise RuntimeError("새 프록시 포트를 고유하게 할당하지 못했습니다.")
                    await self._leases.replace_port(run.id, port)
                    options = dict(run.options)
                    options["proxy_port"] = port
                    run.options = options
                    db.commit()
                    proxy = self._proxy(run)
                    self._proxy_adapters[run.id] = proxy
                attempted_ports.append(int(run.options.get("proxy_port") or 0))
                capture = await proxy.start(run.id)
                if capture.status != CapabilityStatus.FAILED:
                    return proxy, capture
                await proxy.stop(run.id)
            capture.message += (
                f" 사용 가능한 포트로 3회 재시도했지만 시작하지 못했습니다: "
                f"{attempted_ports}"
            )
            return proxy, capture

    async def _emit_evidence(self, run_id: str, evidence: Evidence) -> None:
        await self.events.publish(
            run_id,
            "evidence",
            {
                "id": evidence.id,
                "type": evidence.evidence_type,
                "title": evidence.title,
                "sequence": evidence.sequence,
                "captured_at": evidence.captured_at.isoformat(),
            },
        )

    async def _record_operation(
        self,
        db: Session,
        run_id: str,
        title: str,
        operation,
        evidence_type: str = "command_log",
    ) -> Evidence:
        evidence = self.evidence.add(
            db,
            run_id=run_id,
            evidence_type=evidence_type,
            title=title,
            description=operation.message,
            command=operation.command,
            inline_data=operation.to_dict(),
            file_path=operation.file_path,
        )
        await self._emit_evidence(run_id, evidence)
        return evidence

    def _seed_run_controls(
        self, db: Session, run: DiagnosticRun, app: AppArtifact | None
    ) -> None:
        if not app:
            return
        if db.scalar(
            select(ControlTest.id).where(ControlTest.run_id == run.id).limit(1)
        ):
            return
        templates = db.scalars(
            select(ControlTest).where(
                ControlTest.app_id == app.id,
                ControlTest.run_id.is_(None),
            )
        ).all()
        for item in templates:
            db.add(
                ControlTest(
                    project_id=run.project_id,
                    app_id=app.id,
                    run_id=run.id,
                    mastg_id=item.mastg_id,
                    masvs_id=item.masvs_id,
                    platform=item.platform,
                    title=item.title,
                    automation=item.automation,
                    status=item.status,
                    result=item.result,
                    summary=item.summary,
                    replacement_ids=item.replacement_ids,
                    source_url=item.source_url,
                    evidence_ids=[],
                    synthetic=run.synthetic,
                )
            )
        db.commit()

    @staticmethod
    def _complete_controls(
        db: Session,
        run_id: str,
        mastg_ids: set[str],
        *,
        result: str,
        summary: str,
        evidence_ids: list[str],
    ) -> None:
        controls = db.scalars(
            select(ControlTest).where(
                ControlTest.run_id == run_id,
                ControlTest.mastg_id.in_(mastg_ids),
            )
        ).all()
        for control in controls:
            control.status = "completed"
            control.result = result
            control.summary = summary
            control.evidence_ids = sorted(
                set(control.evidence_ids + evidence_ids)
            )
        db.commit()

    async def _create_ai_script_candidate(
        self,
        db: Session,
        run: DiagnosticRun,
        project: Project,
        source_script: FridaScript,
        execution,
        platform: str,
    ) -> FridaScript | None:
        context = {
            "platform": platform,
            "category": source_script.category,
            "target_framework": source_script.target_framework,
            "failed_script": source_script.content,
            "failure_message": execution.message,
            "runtime_log": (execution.stderr or execution.stdout)[-12000:],
            "simulate_nvidia_failure": bool(
                run.options.get("simulate_nvidia_failure")
            ),
        }
        if run.run_mode == RunMode.MOCK.value:
            selected = await self.mock_ai.generate_frida_script(
                "실패한 Frida 스크립트 수정 후보 생성", context, masked=True
            )
            attempts = [selected]
        elif project.external_ai_allowed:
            selected, attempts = await self.ai_chain.generate_frida_script(
                "실패한 Frida 스크립트 수정 후보 생성",
                context,
                masked=self.settings.mask_external_ai_data,
            )
        else:
            await self.events.publish(
                run.id,
                "ai_status",
                {
                    "status": "manual_required",
                    "message": "외부 AI 전송이 꺼져 있어 Frida 수정 후보를 생성하지 않았습니다.",
                },
            )
            return None

        for attempt in attempts:
            raw_path = None
            raw_path = save_ai_raw_response(
                self.settings,
                f"{run.id}-{source_script.id}-{attempt.provider}-frida.json",
                attempt.raw_response,
            )
            db.add(
                AIInvocation(
                    project_id=project.id,
                    run_id=run.id,
                    provider=attempt.provider,
                    model=attempt.model,
                    task="frida_script_repair",
                    status=attempt.status.value,
                    masked=attempt.masked,
                    quality_score=attempt.quality_score,
                    raw_response_path=str(raw_path) if raw_path else None,
                    error=(
                        attempt.message
                        if attempt.status != CapabilityStatus.AVAILABLE
                        else None
                    ),
                    synthetic=run.synthetic,
                )
            )
        if selected.status != CapabilityStatus.AVAILABLE or not selected.candidate:
            db.commit()
            await self.events.publish(
                run.id, "ai_status", selected.to_dict()
            )
            return None

        candidate = selected.candidate
        syntax_status, syntax_message = await self.frida.check_syntax(
            candidate.content
        )
        generated = FridaScript(
            name=candidate.name,
            platform=platform,
            category=candidate.category,
            target_framework=candidate.target_framework,
            conditions=candidate.conditions,
            risk=candidate.risk,
            content=candidate.content,
            source=f"ai:{selected.provider}",
            approval_status="pending_approval",
            syntax_status=syntax_status.value,
        )
        db.add(generated)
        db.flush()
        evidence = self.evidence.add(
            db,
            run_id=run.id,
            evidence_type="ai_script_candidate",
            title=f"AI Frida 수정 후보 · {generated.name}",
            description=(
                f"{selected.provider}/{selected.model}; {syntax_message}; "
                "자동 실행하지 않았으며 사용자 승인이 필요합니다."
            ),
            inline_data={
                "source_script_id": source_script.id,
                "generated_script_id": generated.id,
                "provider": selected.provider,
                "model": selected.model,
                "candidate": candidate.model_dump(),
                "syntax_status": syntax_status.value,
                "execution_policy": "pending_user_approval",
            },
        )
        db.commit()
        await self._emit_evidence(run.id, evidence)
        await self.events.publish(
            run.id,
            "ai_status",
            {
                "status": "candidate_created",
                "provider": selected.provider,
                "model": selected.model,
                "script_id": generated.id,
                "approval_status": generated.approval_status,
                "syntax_status": generated.syntax_status,
            },
        )
        return generated

    async def _store_proxy_flows(
        self, db: Session, run: DiagnosticRun, proxy, flows
    ) -> None:
        for item in flows:
            row = ProxyFlow(
                run_id=run.id,
                method=item.method,
                url=item.url,
                request_headers=item.request_headers,
                request_body=item.request_body,
                status_code=item.status_code,
                response_headers=item.response_headers,
                response_body=item.response_body,
                sensitive_candidates=item.sensitive_candidates,
                source_ip=item.source_ip,
                synthetic=run.synthetic or item.synthetic,
                captured_at=item.captured_at,
            )
            db.add(row)
            await self.events.publish(run.id, "proxy_flow", item.to_dict())
        db.commit()
        packet_evidence = self.evidence.add_json(
            db,
            run_id=run.id,
            filename="proxy-flows.json",
            title="HTTP 요청·응답",
            evidence_type="network_capture",
            data=[item.to_dict() for item in flows],
            description="프록시 종료와 파일 Flush 후 수집한 최종 흐름입니다. 상태 변경 요청을 자동 재전송하지 않았습니다.",
        )
        await self._emit_evidence(run.id, packet_evidence)
        self._complete_controls(
            db,
            run.id,
            {"MASTG-TEST-0020", "MASTG-TEST-0022", "MASTG-TEST-0066", "MASTG-TEST-0068"},
            result="needs_review" if flows else "unknown",
            summary=f"최종 프록시 흐름 {len(flows)}개를 TLS·인증서 고정 검증 증적으로 연결했습니다.",
            evidence_ids=[packet_evidence.id],
        )

    async def _capture(
        self, db: Session, run: DiagnosticRun, device, filename: str, title: str, description: str
    ) -> Evidence | None:
        destination = self.evidence.run_dir(run.id) / filename
        operation = await device.screenshot(run.device_id, destination)
        if operation.status != CapabilityStatus.AVAILABLE:
            await self._record_operation(db, run.id, f"{title} 실패", operation)
            return None
        evidence = self.evidence.add(
            db,
            run_id=run.id,
            evidence_type="screenshot",
            title=title,
            description=description,
            command=operation.command,
            file_path=destination,
            mime_type="image/png",
        )
        await self._emit_evidence(run.id, evidence)
        await self.events.publish(
            run.id,
            "device_screen",
            {"evidence_id": evidence.id, "url": f"/api/evidence/{evidence.id}/download"},
        )
        return evidence

    async def _execute(self, run_id: str) -> None:
        proxy = None
        lease_acquired = False
        try:
            with SessionLocal() as db:
                run = db.get(DiagnosticRun, run_id)
                if not run:
                    return
                project = db.get(Project, run.project_id)
                app = db.get(AppArtifact, run.app_id) if run.app_id else None
                if not project:
                    raise RuntimeError("프로젝트를 찾을 수 없습니다.")
                device_platform = platform_for_adapter(
                    run.device_adapter, run.device_id
                )
                if app:
                    app_platform = normalize_platform(app.platform)
                    if app_platform != device_platform:
                        raise RuntimeError(
                            f"{app_platform} 앱과 {device_platform} 단말 Adapter가 일치하지 않습니다."
                        )
                    try:
                        package_name = require_app_identifier(
                            app.platform, app.package_name
                        )
                    except ValueError as exc:
                        if run.run_mode == RunMode.LIVE.value:
                            raise RuntimeError(
                                f"Live 진단 대상 식별자 확인이 필요합니다: {exc}"
                            ) from exc
                        package_name = "mock.synthetic.application"
                elif run.run_mode == RunMode.LIVE.value:
                    raise RuntimeError("Live 진단에는 대상 앱이 필요합니다.")
                else:
                    app_platform = device_platform
                    package_name = "mock.synthetic.application"
                run.started_at = datetime.now(timezone.utc)
                db.commit()
                proxy_port = (
                    int(run.options.get("proxy_port"))
                    if run.proxy_adapter == "mitmproxy" and run.options.get("proxy_port")
                    else None
                )
                await self._leases.acquire(run.id, run.device_id, proxy_port)
                lease_acquired = True
                device = self._device(run.device_adapter)
                proxy = self._proxy(run)
                self._proxy_adapters[run.id] = proxy
                self._seed_run_controls(db, run, app)

                await self._stage(db, run, "preflight", 4, "Adapter와 대상 정보를 확인합니다.")
                device_list = await device.discover()
                if not any(item.id == run.device_id for item in device_list):
                    raise RuntimeError(f"선택한 단말을 찾을 수 없습니다: {run.device_id}")
                preflight = self.evidence.add_json(
                    db,
                    run_id=run.id,
                    filename="preflight.json",
                    title="진단 전 상태",
                    evidence_type="device_state",
                    data={
                        "device": next(
                            item.to_dict() for item in device_list if item.id == run.device_id
                        ),
                        "app": {
                            "name": app.app_name if app else None,
                            "package": app.package_name if app else None,
                            "version": app.version if app else None,
                            "sha256": app.sha256 if app else None,
                        },
                        "options": run.options,
                    },
                )
                await self._emit_evidence(run.id, preflight)

                await self._stage(
                    db, run, "static_analysis", 12, "업로드된 정적 분석 결과를 실행에 연결합니다."
                )
                if app:
                    static_evidence = self.evidence.add_json(
                        db,
                        run_id=run.id,
                        filename="static-analysis.json",
                        title="정적 분석 결과",
                        evidence_type="static_analysis",
                        data=app.analysis_result,
                    )
                    await self._emit_evidence(run.id, static_evidence)

                proxy, proxy_capture = await self._start_proxy_with_retry(
                    db, run, proxy
                )
                await self.events.publish(
                    run.id, "proxy_status", proxy_capture.to_dict()
                )
                if proxy_capture.status in {
                    CapabilityStatus.NOT_CONFIGURED,
                    CapabilityStatus.FAILED,
                    CapabilityStatus.UNSUPPORTED,
                }:
                    raise RuntimeError(proxy_capture.message)
                if proxy_capture.status == CapabilityStatus.MANUAL_REQUIRED:
                    if run.proxy_adapter not in {"burp", "fiddler"}:
                        raise RuntimeError(proxy_capture.message)
                    options = dict(run.options)
                    options.update(
                        {
                            "manual_proxy_imported": False,
                            "manual_proxy_instructions": proxy_capture.instructions,
                        }
                    )
                    run.options = options
                    run.current_stage = "proxy_manual_setup"
                    db.commit()
                    await self.events.publish(
                        run.id,
                        "stage",
                        {
                            "stage": "proxy_manual_setup",
                            "progress": run.progress,
                            "message": proxy_capture.message,
                            "status": RunStatus.PAUSE_REQUESTED.value,
                        },
                    )
                    await self.pause(
                        run.id,
                        "Burp/Fiddler 설정 후 HAR를 가져오면 진단을 재개할 수 있습니다.",
                    )
                    await self._checkpoint(run.id)
                    db.refresh(run)
                    if not bool(run.options.get("manual_proxy_imported")):
                        raise RuntimeError("HAR Import 확인 없이 수동 프록시 진단을 재개할 수 없습니다.")

                if app:
                    await self._stage(db, run, "install", 22, "대상 앱을 단말에 설치합니다.")
                    install = await device.install_app(run.device_id, Path(app.stored_path))
                    await self._record_operation(db, run.id, "앱 설치", install)
                    if install.status not in {
                        CapabilityStatus.AVAILABLE,
                        CapabilityStatus.MANUAL_REQUIRED,
                    }:
                        raise RuntimeError(install.message)

                await self._stage(db, run, "launch_baseline", 32, "원본 상태에서 앱을 실행합니다.")
                launch = await device.start_app(run.device_id, package_name)
                await self._record_operation(db, run.id, "원본 상태 앱 실행", launch)
                await self._capture(
                    db,
                    run,
                    device,
                    "01-app-launched.png",
                    "앱 실행 직후",
                    "보안통제 적용 전 원본 실행 상태입니다.",
                )

                await self._stage(
                    db,
                    run,
                    "security_control_validation",
                    44,
                    "종료·탐지 메시지와 런타임 로그를 수집합니다.",
                )
                log_path = self.evidence.run_dir(run.id) / "baseline-logcat.txt"
                logs = await device.collect_logs(run.device_id, log_path)
                baseline_evidence = await self._record_operation(
                    db, run.id, "원본 상태 단말 로그", logs, "device_log"
                )
                self._complete_controls(
                    db,
                    run.id,
                    {
                        "MASTG-TEST-0045",
                        "MASTG-TEST-0046",
                        "MASTG-TEST-0088",
                        "MASTG-TEST-0089",
                    },
                    result="needs_review",
                    summary="원본 실행 로그를 수집했습니다. 탐지 메시지와 종료 동작을 검토하세요.",
                    evidence_ids=[baseline_evidence.id],
                )
                await self._capture(
                    db,
                    run,
                    device,
                    "02-before-frida.png",
                    "우회 적용 전",
                    "등록된 Frida 스크립트를 적용하기 직전 상태입니다.",
                )

                await self._stage(
                    db, run, "frida", 56, "승인된 Frida 스크립트를 선택하고 실행합니다."
                )
                selected_ids = list(run.options.get("frida_script_ids", []))
                if selected_ids:
                    query = select(FridaScript).where(
                        FridaScript.id.in_(selected_ids),
                        FridaScript.approval_status == "approved",
                        FridaScript.platform == app_platform,
                    )
                    scripts = db.scalars(query).all()
                elif bool(run.options.get("auto_select_frida")):
                    query = select(FridaScript).where(
                        FridaScript.approval_status == "approved",
                        FridaScript.platform == app_platform,
                        FridaScript.source == "builtin",
                        FridaScript.risk == "low",
                    )
                    scripts = db.scalars(query).all()
                else:
                    scripts = []
                if app:
                    scripts = [
                        script
                        for script in scripts
                        if is_safe_automatic_script(script)
                        and script_applies_to_app(script, app)[0]
                    ]
                else:
                    scripts = []
                db.commit()
                for script in scripts:
                    content_sha256 = hashlib.sha256(script.content.encode("utf-8")).hexdigest()
                    if (
                        script.syntax_status != CapabilityStatus.AVAILABLE.value
                        or not script.approved_sha256
                        or script.approved_sha256 != content_sha256
                    ):
                        script.approval_status = "pending_approval"
                        script.approved_by = None
                        script.approved_at = None
                        script.approved_sha256 = None
                        db.commit()
                        continue
                    execution = await self.frida.execute(
                        device_id=run.device_id,
                        target=package_name,
                        script_name=script.name,
                        script_content=script.content,
                        mode=str(run.options.get("frida_mode", "spawn")),
                        mock=run.device_adapter == "mock",
                    )
                    if not run.synthetic and execution.status == CapabilityStatus.AVAILABLE:
                        script.success_count += 1
                    elif not run.synthetic:
                        script.failure_count += 1
                    db.commit()
                    script_evidence = self.evidence.add(
                        db,
                        run_id=run.id,
                        evidence_type="frida_script",
                        title=f"Frida 스크립트 · {script.name}",
                        description=execution.message,
                        command=execution.command,
                        inline_data={
                            "script_id": script.id,
                            "risk": script.risk,
                            "content": script.content,
                            "result": execution.to_dict(),
                        },
                    )
                    await self._emit_evidence(run.id, script_evidence)
                    await self.events.publish(
                        run.id, "frida_log", execution.to_dict()
                    )
                    self._complete_controls(
                        db,
                        run.id,
                        {"MASTG-TEST-0048", "MASTG-TEST-0091"},
                        result=(
                            "needs_review"
                            if execution.status == CapabilityStatus.AVAILABLE
                            else "unknown"
                        ),
                        summary=f"승인된 Frida 스크립트 실행 상태: {execution.status.value}",
                        evidence_ids=[script_evidence.id],
                    )
                    if (
                        execution.status == CapabilityStatus.FAILED
                        and project.ai_enabled
                        and bool(run.options.get("auto_ai_script_candidate"))
                    ):
                        await self._create_ai_script_candidate(
                            db,
                            run,
                            project,
                            script,
                            execution,
                            app_platform,
                        )

                runtime_tool = str(run.options.get("runtime_tool") or "none")
                if runtime_tool in {"objection", "drozer"}:
                    runtime_adapter = (
                        ObjectionRuntimeAdapter(self.settings)
                        if runtime_tool == "objection"
                        else DrozerRuntimeAdapter(self.settings)
                    )
                    runtime_result = await runtime_adapter.execute(
                        device_id=run.device_id,
                        target=package_name,
                        action=(
                            "environment"
                            if runtime_tool == "objection"
                            else "attack_surface"
                        ),
                        approved=False,
                    )
                    runtime_evidence = self.evidence.add(
                        db,
                        run_id=run.id,
                        evidence_type="runtime_tool",
                        title=f"{runtime_tool} 읽기 전용 탐색",
                        description=runtime_result.message,
                        command=runtime_result.command,
                        inline_data=runtime_result.to_dict(),
                    )
                    await self._emit_evidence(run.id, runtime_evidence)
                    await self.events.publish(
                        run.id, "runtime_tool", runtime_result.to_dict()
                    )
                await self._capture(
                    db,
                    run,
                    device,
                    "03-after-frida.png",
                    "우회 적용 후",
                    "Frida 스크립트 적용 후 앱 상태입니다. 성공 여부는 로그와 함께 검토합니다.",
                )

                if run.options.get("pause_for_login"):
                    run.current_stage = "manual_interaction"
                    db.commit()
                    await self.pause(
                        run.id, "로그인을 직접 수행한 뒤 ‘재개’를 누르세요."
                    )
                    await self._checkpoint(run.id)
                    await self._capture(
                        db,
                        run,
                        device,
                        "04-after-login.png",
                        "로그인 완료 후",
                        "사용자 수동 로그인 완료 후의 화면입니다.",
                    )

                await self._stage(
                    db, run, "network_dynamic", 70, "프록시 패킷과 동적 증적을 수집합니다."
                )
                await asyncio.sleep(0.1)
                flows = []

                await self._capture(
                    db,
                    run,
                    device,
                    "05-test-after.png",
                    "테스트 동작 후",
                    "동적·네트워크 테스트 종료 시점의 화면입니다.",
                )
                dynamic_log_path = self.evidence.run_dir(run.id) / "dynamic-logcat.txt"
                dynamic_logs = await device.collect_logs(run.device_id, dynamic_log_path)
                dynamic_evidence = await self._record_operation(
                    db, run.id, "동적 분석 단말 로그", dynamic_logs, "device_log"
                )
                self._complete_controls(
                    db,
                    run.id,
                    {"MASTG-TEST-0003", "MASTG-TEST-0053"},
                    result="needs_review",
                    summary="동적 단말 로그를 수집해 민감정보 노출 검토 대상으로 연결했습니다.",
                    evidence_ids=[dynamic_evidence.id],
                )

                stop_proxy = await asyncio.shield(proxy.stop(run.id))
                await self.events.publish(run.id, "proxy_status", stop_proxy.to_dict())
                await asyncio.sleep(0.1)
                flows = await proxy.read_flows(run.id)
                await self._store_proxy_flows(db, run, proxy, flows)

                await self._stage(db, run, "ai_analysis", 84, "증적 후보를 분류합니다.")
                evidence_rows = db.scalars(
                    select(Evidence).where(Evidence.run_id == run.id)
                ).all()
                evidence_ids = [item.id for item in evidence_rows]
                evidence_catalog = [
                    {
                        "id": item.id,
                        "type": item.evidence_type,
                        "title": item.title,
                        "sequence": item.sequence,
                    }
                    for item in evidence_rows
                ]
                db.commit()
                proxy_summaries = [
                    {
                        "method": item.method,
                        "url": item.url,
                        "status_code": item.status_code,
                        "request_header_names": sorted(item.request_headers),
                        "response_header_names": sorted(item.response_headers),
                        "sensitive_candidates": item.sensitive_candidates,
                    }
                    for item in flows[:12]
                ]
                ai_context = {
                    "platform": app_platform,
                    "static_signals": (app.analysis_result if app else {}).get("signals", {}),
                    "runtime_log": dynamic_logs.output[-2000:],
                    "proxy_flows": proxy_summaries,
                    "evidence_ids": evidence_ids,
                    "evidence_catalog": evidence_catalog,
                    "simulate_nvidia_failure": bool(
                        run.options.get("simulate_nvidia_failure")
                    ),
                }
                ai_result = None
                attempts = []
                if project.ai_enabled:
                    if run.run_mode == RunMode.MOCK.value:
                        ai_result = await self.mock_ai.analyze(
                            "모바일 진단 증적 분류", ai_context, masked=True
                        )
                        attempts = [ai_result]
                    elif project.external_ai_allowed:
                        ai_result, attempts = await self.ai_chain.analyze(
                            "모바일 진단 증적 분류",
                            ai_context,
                            masked=self.settings.mask_external_ai_data,
                        )
                    else:
                        await self.events.publish(
                            run.id,
                            "ai_status",
                            {
                                "status": "not_configured",
                                "message": "프로젝트에서 외부 AI 전송이 비활성화되었습니다.",
                            },
                        )
                for attempt in attempts:
                    raw_path = save_ai_raw_response(
                        self.settings,
                        f"{run.id}-{attempt.provider}.txt",
                        attempt.raw_response,
                    )
                    db.add(
                        AIInvocation(
                            project_id=project.id,
                            run_id=run.id,
                            provider=attempt.provider,
                            model=attempt.model,
                            task="evidence_analysis",
                            status=attempt.status.value,
                            masked=attempt.masked,
                            quality_score=attempt.quality_score,
                            raw_response_path=str(raw_path) if raw_path else None,
                            error=attempt.message
                            if attempt.status != CapabilityStatus.AVAILABLE
                            else None,
                            synthetic=run.synthetic,
                        )
                    )
                    await self.events.publish(
                        run.id, "ai_status", attempt.to_dict()
                    )
                db.commit()

                created_findings: list[Finding] = []
                if ai_result and ai_result.analysis:
                    valid_evidence = {
                        item.id: item
                        for item in db.scalars(
                            select(Evidence).where(Evidence.run_id == run.id)
                        ).all()
                    }
                    for analysis in ai_result.analysis.findings:
                        linked_ids = list(dict.fromkeys(
                            evidence_id
                            for evidence_id in analysis.evidence_ids
                            if evidence_id in valid_evidence
                        ))
                        requested_verdict = analysis.verdict.value
                        is_candidate = (
                            analysis.confidence < self.settings.ai_min_quality
                            or not linked_ids
                        )
                        if is_candidate or (
                            requested_verdict == "confirmed" and not linked_ids
                        ):
                            verdict = "needs_review"
                        else:
                            verdict = requested_verdict
                        finding = Finding(
                            project_id=project.id,
                            run_id=run.id,
                            title=analysis.title,
                            category=analysis.category,
                            platform=app_platform,
                            severity=analysis.severity,
                            location=analysis.location,
                            verdict=verdict,
                            confidence=analysis.confidence,
                            rationale=analysis.rationale,
                            reproduction=analysis.reproduction,
                            false_positive_risk=analysis.false_positive_risk,
                            additional_checks=analysis.additional_checks,
                            source=(
                                f"ai_candidate:{ai_result.provider}"
                                if is_candidate
                                else f"ai:{ai_result.provider}"
                            ),
                            synthetic=run.synthetic,
                        )
                        db.add(finding)
                        db.flush()
                        fingerprint = hashlib.sha256(
                            analysis.model_dump_json().encode("utf-8")
                        ).hexdigest()
                        db.add(
                            FindingSource(
                                finding_id=finding.id,
                                raw_finding_id=None,
                                source_tool=f"ai:{ai_result.provider}",
                                source_rule_id="ai.evidence_analysis",
                                fingerprint=fingerprint,
                                evidence_ids=linked_ids,
                            )
                        )
                        created_findings.append(finding)
                        await self.events.publish(
                            run.id,
                            "finding",
                            {
                                "id": finding.id,
                                "title": finding.title,
                                "severity": finding.severity,
                                "confidence": finding.confidence,
                                "verdict": finding.verdict,
                                "evidence_ids": linked_ids,
                            },
                        )
                    db.commit()

                await self._stage(
                    db, run, "finalize", 96, "증적 인덱스를 검증하고 캡처를 종료합니다."
                )
                run.status = RunStatus.COMPLETED.value
                run.current_stage = "completed"
                run.progress = 100
                run.finished_at = datetime.now(timezone.utc)
                db.commit()
                await self.events.publish(
                    run.id,
                    "run_status",
                    {
                        "status": "completed",
                        "progress": 100,
                        "message": "진단과 증적 연결을 완료했습니다.",
                        "finding_ids": [item.id for item in created_findings],
                    },
                )
        except DiagnosticStopped:
            with SessionLocal() as db:
                run = db.get(DiagnosticRun, run_id)
                if run:
                    run.status = RunStatus.STOPPED.value
                    run.current_stage = "stopped"
                    run.finished_at = datetime.now(timezone.utc)
                    db.commit()
            await self.events.publish(
                run_id, "run_status", {"status": "stopped", "message": "진단을 중지했습니다."}
            )
        except asyncio.CancelledError:
            with SessionLocal() as db:
                run = db.get(DiagnosticRun, run_id)
                if run:
                    run.status = RunStatus.INTERRUPTED.value
                    run.current_stage = "interrupted"
                    run.error = "진단 Task가 종료되어 안전하게 중단되었습니다."
                    run.finished_at = datetime.now(timezone.utc)
                    db.commit()
            raise
        except Exception as exc:
            with SessionLocal() as db:
                run = db.get(DiagnosticRun, run_id)
                if run:
                    run.status = RunStatus.FAILED.value
                    run.current_stage = "failed"
                    run.error = f"{type(exc).__name__}: {exc}"
                    run.finished_at = datetime.now(timezone.utc)
                    db.commit()
            await self.events.publish(
                run_id,
                "run_status",
                {"status": "failed", "message": f"{type(exc).__name__}: {exc}"},
            )
        finally:
            if proxy is not None:
                try:
                    await asyncio.shield(proxy.stop(run_id))
                except Exception:
                    pass
            if lease_acquired:
                await self._leases.release(run_id)
            self._stop_requested.discard(run_id)
            async with self._state_lock:
                self._safe_pause_waiting.discard(run_id)
                self._manual_active.discard(run_id)
            self._pause_events.pop(run_id, None)
            self._proxy_adapters.pop(run_id, None)
            self._tasks.pop(run_id, None)
