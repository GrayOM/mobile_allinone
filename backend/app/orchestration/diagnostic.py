from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.ai import AIProviderChain, MockAIProvider
from backend.app.core.config import AppSettings, get_settings
from backend.app.core.events import EventBus, event_bus
from backend.app.core.status import CapabilityStatus, RunStatus
from backend.app.database.models import (
    AIInvocation,
    AppArtifact,
    ControlTest,
    DiagnosticRun,
    Evidence,
    Finding,
    FridaScript,
    Project,
    ProxyFlow,
)
from backend.app.database.session import SessionLocal
from backend.app.devices import AndroidDeviceAdapter, IOSDeviceAdapter, MockDeviceAdapter
from backend.app.evidence import EvidenceService
from backend.app.frida import FridaManager
from backend.app.proxy import (
    BurpProxyAdapter,
    FiddlerProxyAdapter,
    MitmProxyAdapter,
    MockProxyAdapter,
)
from backend.app.runtime import DrozerRuntimeAdapter, ObjectionRuntimeAdapter


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
        event.clear()
        with SessionLocal() as db:
            run = db.get(DiagnosticRun, run_id)
            if run and run.status == RunStatus.RUNNING.value:
                run.status = RunStatus.PAUSED.value
                run.current_stage = "manual_interaction"
                db.commit()
        await self.events.publish(
            run_id, "run_status", {"status": "paused", "message": reason}
        )
        return True

    async def resume(self, run_id: str) -> bool:
        event = self._pause_events.get(run_id)
        if not event:
            return False
        with SessionLocal() as db:
            run = db.get(DiagnosticRun, run_id)
            if run and run.status == RunStatus.PAUSED.value:
                run.status = RunStatus.RUNNING.value
                run.current_stage = "resuming"
                db.commit()
        event.set()
        await self.events.publish(
            run_id, "run_status", {"status": "running", "message": "진단을 재개했습니다."}
        )
        return True

    async def stop(self, run_id: str) -> bool:
        if run_id not in self._tasks:
            return False
        self._stop_requested.add(run_id)
        event = self._pause_events.get(run_id)
        if event:
            event.set()
        await self.events.publish(
            run_id, "run_status", {"status": "stopping", "message": "중지를 요청했습니다."}
        )
        return True

    async def _checkpoint(self, run_id: str) -> None:
        if run_id in self._stop_requested:
            raise DiagnosticStopped
        event = self._pause_events.get(run_id)
        if event:
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
        return MockDeviceAdapter()

    def _proxy(self, adapter: str):
        if adapter == "mitmproxy":
            return MitmProxyAdapter(self.settings)
        if adapter == "fiddler":
            return FiddlerProxyAdapter()
        if adapter == "burp":
            return BurpProxyAdapter()
        return MockProxyAdapter()

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
        if project.mock_mode:
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
            if attempt.raw_response:
                raw_path = self.settings.ai_raw_dir / (
                    f"{run.id}-{source_script.id}-{attempt.provider}-frida.json"
                )
                raw_path.write_text(attempt.raw_response, encoding="utf-8")
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
            platform=candidate.platform,
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
        try:
            with SessionLocal() as db:
                run = db.get(DiagnosticRun, run_id)
                if not run:
                    return
                project = db.get(Project, run.project_id)
                app = db.get(AppArtifact, run.app_id) if run.app_id else None
                if not project:
                    raise RuntimeError("프로젝트를 찾을 수 없습니다.")
                run.started_at = datetime.now(timezone.utc)
                db.commit()
                device = self._device(run.device_adapter)
                proxy = self._proxy(run.proxy_adapter)
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

                proxy_capture = await proxy.start(run.id)
                await self.events.publish(
                    run.id, "proxy_status", proxy_capture.to_dict()
                )

                package_name = (
                    app.package_name if app and app.package_name else "com.example.demo"
                )
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
                query = select(FridaScript).where(
                    FridaScript.approval_status == "approved"
                )
                if selected_ids:
                    query = query.where(FridaScript.id.in_(selected_ids))
                else:
                    query = query.where(FridaScript.platform == (app.platform if app else "android")).limit(1)
                scripts = db.scalars(query).all()
                for script in scripts:
                    execution = await self.frida.execute(
                        device_id=run.device_id,
                        target=package_name,
                        script_name=script.name,
                        script_content=script.content,
                        mode=str(run.options.get("frida_mode", "spawn")),
                        mock=run.device_adapter == "mock",
                    )
                    if execution.status == CapabilityStatus.AVAILABLE:
                        script.success_count += 1
                    else:
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
                            app.platform if app else "android",
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
                flows = await proxy.read_flows(run.id)
                flow_ids: list[str] = []
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
                        captured_at=item.captured_at,
                    )
                    db.add(row)
                    db.flush()
                    flow_ids.append(row.id)
                    await self.events.publish(run.id, "proxy_flow", item.to_dict())
                db.commit()
                packet_evidence = self.evidence.add_json(
                    db,
                    run_id=run.id,
                    filename="proxy-flows.json",
                    title="HTTP 요청·응답",
                    evidence_type="network_capture",
                    data=[item.to_dict() for item in flows],
                    description="수집한 흐름의 원문입니다. 상태 변경 요청을 자동 재전송하지 않았습니다.",
                )
                await self._emit_evidence(run.id, packet_evidence)
                self._complete_controls(
                    db,
                    run.id,
                    {
                        "MASTG-TEST-0020",
                        "MASTG-TEST-0022",
                        "MASTG-TEST-0066",
                        "MASTG-TEST-0068",
                    },
                    result="needs_review" if flows else "unknown",
                    summary=(
                        f"프록시 흐름 {len(flows)}개를 TLS·인증서 고정 "
                        "검증 증적으로 연결했습니다."
                    ),
                    evidence_ids=[packet_evidence.id],
                )

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

                await self._stage(db, run, "ai_analysis", 84, "증적 후보를 분류합니다.")
                evidence_ids = [
                    item.id
                    for item in db.scalars(
                        select(Evidence).where(Evidence.run_id == run.id)
                    ).all()
                ]
                ai_context = {
                    "platform": app.platform if app else "android",
                    "static_signals": (app.analysis_result if app else {}).get("signals", {}),
                    "runtime_log": dynamic_logs.output[-8000:],
                    "proxy_flows": [item.to_dict() for item in flows[:12]],
                    "evidence_ids": evidence_ids,
                    "simulate_nvidia_failure": bool(
                        run.options.get("simulate_nvidia_failure")
                    ),
                }
                ai_result = None
                attempts = []
                if project.ai_enabled:
                    if project.mock_mode:
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
                    raw_path = None
                    if attempt.raw_response:
                        raw_path = self.settings.ai_raw_dir / f"{run.id}-{attempt.provider}.txt"
                        raw_path.write_text(attempt.raw_response, encoding="utf-8")
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
                        )
                    )
                    await self.events.publish(
                        run.id, "ai_status", attempt.to_dict()
                    )
                db.commit()

                finding = None
                if ai_result and ai_result.analysis:
                    analysis = ai_result.analysis
                    finding = Finding(
                        project_id=project.id,
                        run_id=run.id,
                        title=analysis.title,
                        category=analysis.category,
                        platform=analysis.platform,
                        severity="medium",
                        location=analysis.location,
                        verdict=analysis.verdict,
                        confidence=analysis.confidence,
                        rationale=analysis.rationale,
                        reproduction=analysis.reproduction,
                        false_positive_risk=analysis.false_positive_risk,
                        additional_checks=analysis.additional_checks,
                        source=f"ai:{ai_result.provider}",
                    )
                    db.add(finding)
                    db.commit()
                    db.refresh(finding)
                    for evidence in db.scalars(
                        select(Evidence).where(Evidence.run_id == run.id)
                    ):
                        evidence.finding_id = finding.id
                    db.commit()
                    await self.events.publish(
                        run.id,
                        "finding",
                        {
                            "id": finding.id,
                            "title": finding.title,
                            "severity": finding.severity,
                            "confidence": finding.confidence,
                            "verdict": finding.verdict,
                        },
                    )

                await self._stage(
                    db, run, "finalize", 96, "증적 인덱스를 검증하고 캡처를 종료합니다."
                )
                stop_proxy = await proxy.stop(run.id)
                await self.events.publish(run.id, "proxy_status", stop_proxy.to_dict())
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
                        "finding_id": finding.id if finding else None,
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
            self._stop_requested.discard(run_id)
            self._pause_events.pop(run_id, None)
            self._proxy_adapters.pop(run_id, None)
