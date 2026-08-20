from __future__ import annotations

import asyncio
import json
import hashlib
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.ai import AIProviderChain, MockAIProvider
from backend.app.ai.storage import save_ai_raw_response
from backend.app.ai.masking import mask_context
from backend.app.assessment import evaluate_standard_controls
from backend.app.core.config import AppSettings, get_settings
from backend.app.core.events import EventBus, event_bus
from backend.app.core.status import CapabilityStatus, Platform, RunMode, RunStatus
from backend.app.core.targets import (
    normalize_platform,
    platform_for_adapter,
    require_app_identifier,
)
from backend.app.control_validation import (
    ControlScopeError,
    active_control_scope,
    evaluate_network_scope,
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
    IOSDeviceProfile,
    Project,
    ProxyFlow,
)
from backend.app.database.session import SessionLocal
from backend.app.devices import AndroidDeviceAdapter, IOSDeviceAdapter, MockDeviceAdapter
from backend.app.evidence import EvidencePolicyEngine, EvidenceService
from backend.app.frida import (
    FridaManager,
    FridaSessionManager,
    FridaSessionResult,
    FridaSessionScript,
    FridaTarget,
)
from backend.app.frida.policy import is_safe_automatic_script, script_applies_to_app
from backend.app.navigation import (
    AndroidADBUIDriver,
    MockAndroidUIDriver,
    NavigationEngine,
    NavigationHooks,
    NavigationLimits,
    NavigationResult,
    approval_eligible,
)
from backend.app.network_testing import (
    MockNetworkTestExecutor,
    NetworkCandidateEngine,
    NetworkExecution,
    classify_proxy_flow,
)
from backend.app.orchestration.resources import (
    ResourceLeaseManager,
    allocate_available_port,
)
from backend.app.proxy import (
    BurpProxyAdapter,
    FiddlerProxyAdapter,
    MitmProxyAdapter,
    MockProxyAdapter,
)
from backend.app.runtime import DrozerRuntimeAdapter, ObjectionRuntimeAdapter
from backend.app.storage import (
    AndroidStorageCollector,
    MockAndroidStorageCollector,
    StorageCapture,
    diff_snapshots,
)


def _frida_evidence_integrity(health: dict[str, Any]) -> tuple[bool, str]:
    dropped = max(0, int(health.get("dropped_count") or 0))
    truncated = max(0, int(health.get("truncated_count") or 0))
    if dropped:
        return (
            False,
            f"Frida transcript에서 {dropped}개 메시지가 유실되었습니다. "
            "Run 증적은 불완전하며 재검증이 필요합니다.",
        )
    return (
        True,
        f"Frida 메시지 유실이 없습니다. 크기 제한으로 축약된 메시지는 {truncated}개입니다.",
    )


class DiagnosticStopped(Exception):
    pass


class ManualActionInProgress(Exception):
    pass


class DiagnosticManualRequired(Exception):
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
        self.evidence_policy = EvidencePolicyEngine()
        self.frida = FridaManager(self.settings)
        self.frida_sessions = FridaSessionManager(self.settings)
        self.ai_chain = AIProviderChain(settings=self.settings)
        self.mock_ai = MockAIProvider()
        self._tasks: dict[str, asyncio.Task[None]] = {}
        self._pause_events: dict[str, asyncio.Event] = {}
        self._stop_requested: set[str] = set()
        self._proxy_adapters: dict[str, Any] = {}
        self._ui_drivers: dict[str, Any] = {}
        self._leases = ResourceLeaseManager()
        self._proxy_start_lock = asyncio.Lock()
        self._state_lock = asyncio.Lock()
        self._safe_pause_waiting: set[str] = set()
        self._manual_active: set[str] = set()
        self._manual_tasks: dict[str, asyncio.Task[Any]] = {}

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
            current = asyncio.current_task()
            if current is not None:
                self._manual_tasks[run_id] = current
        self._set_manual_option(run_id, True)
        return True

    async def end_manual_action(self, run_id: str) -> None:
        async with self._state_lock:
            self._manual_active.discard(run_id)
            self._manual_tasks.pop(run_id, None)
        self._set_manual_option(run_id, False)

    def _set_manual_option(self, run_id: str, active: bool) -> None:
        with SessionLocal() as db:
            run = db.get(DiagnosticRun, run_id)
            if not run:
                return
            options = dict(run.options)
            options["manual_action_active"] = active
            run.options = options
            db.commit()

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
        async with self._state_lock:
            task = self._tasks.get(run_id)
            if not task or task.done():
                return False
            if run_id in self._manual_active:
                raise ManualActionInProgress(
                    "수동 단말·Frida·Runtime 작업이 끝난 뒤 진단을 중지하세요."
                )
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
        manual_tasks = [
            task
            for task in self._manual_tasks.values()
            if not task.done() and task is not asyncio.current_task()
        ]
        for task in manual_tasks:
            task.cancel()
        if manual_tasks:
            await asyncio.gather(*manual_tasks, return_exceptions=True)
        run_ids = [run_id for run_id, task in self._tasks.items() if not task.done()]
        if run_ids:
            await asyncio.gather(
                *(self.stop(run_id, wait=True) for run_id in run_ids),
                return_exceptions=True,
            )
        await self.frida_sessions.shutdown()

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
        """Resolve adapters that do not need run-scoped profile metadata.

        Keep this narrow resolver as a compatibility seam for tests and local
        deployments that replace a hardware adapter with an explicit fixture.
        Run-aware iOS SSH profiles are resolved by :meth:`device_for_run`.
        """
        if adapter == "android_adb":
            return AndroidDeviceAdapter(self.settings)
        if adapter == "ios_windows":
            return IOSDeviceAdapter(self.settings)
        if adapter == "mock":
            return MockDeviceAdapter()
        raise ValueError(f"지원하지 않는 단말 Adapter입니다: {adapter}")

    def device_for_run(self, db: Session, run: DiagnosticRun):
        adapter = run.device_adapter
        if adapter == "ios_windows":
            if run.device_id.startswith("ios-ssh:"):
                profiles = db.scalars(select(IOSDeviceProfile)).all()
                profile = next(
                    (
                        item
                        for item in profiles
                        if IOSDeviceAdapter.ssh_device_id(item.host, item.ssh_port)
                        == run.device_id
                    ),
                    None,
                )
                if profile:
                    return IOSDeviceAdapter(
                        self.settings,
                        host=profile.host,
                        port=profile.ssh_port,
                        username=profile.username,
                        frida_endpoint=profile.frida_endpoint,
                        profile_id=profile.id,
                        profile_name=profile.name,
                        include_usb=False,
                    )
                ssh_host = os.getenv("MSW_IOS_SSH_HOST")
                ssh_port = int(os.getenv("MSW_IOS_SSH_PORT", "22"))
                if (
                    ssh_host
                    and IOSDeviceAdapter.ssh_device_id(ssh_host, ssh_port)
                    == run.device_id
                ):
                    return IOSDeviceAdapter(
                        self.settings,
                        host=ssh_host,
                        port=ssh_port,
                        username=os.getenv("MSW_IOS_SSH_USER", "root"),
                        frida_endpoint=os.getenv("MSW_IOS_FRIDA_ENDPOINT"),
                        profile_name="environment",
                        include_usb=False,
                    )
                raise ValueError("등록된 iOS SSH 단말 프로필을 찾을 수 없습니다.")
            return self._device(adapter)
        if adapter == "mock":
            device = self._device(adapter)
            if type(device) is MockDeviceAdapter:
                device.platform = (
                    Platform.MOCK_IOS
                    if "ios" in run.device_id.lower()
                    else Platform.MOCK_ANDROID
                )
            return device
        return self._device(adapter)

    @staticmethod
    def frida_target_for_device(device, device_id: str) -> FridaTarget:
        resolver = getattr(device, "frida_target", None)
        if callable(resolver):
            return resolver(device_id)
        return FridaTarget.usb(device_id)

    def ui_driver_for_run(
        self, run: DiagnosticRun, device, package_name: str
    ):
        current = self._ui_drivers.get(run.id)
        if current is not None:
            return current
        if run.device_adapter == "mock" and "ios" not in run.device_id.lower():
            driver = MockAndroidUIDriver(
                run.device_id,
                package_name=package_name,
                device_adapter=device,
            )
            self._ui_drivers[run.id] = driver
            return driver
        if run.device_adapter == "android_adb":
            driver = AndroidADBUIDriver(
                run.device_id,
                settings=self.settings,
                device_adapter=(
                    device if isinstance(device, AndroidDeviceAdapter) else None
                ),
            )
            self._ui_drivers[run.id] = driver
            return driver
        return None

    def storage_collector_for_run(
        self,
        run: DiagnosticRun,
        package_name: str,
        *,
        privileged: bool | None,
    ):
        if run.device_adapter == "mock" and "ios" not in run.device_id.lower():
            return MockAndroidStorageCollector(package_name)
        if run.device_adapter == "android_adb":
            return AndroidStorageCollector(
                run.device_id,
                package_name,
                privileged=privileged,
                settings=self.settings,
            )
        return None

    def _proxy(self, run: DiagnosticRun):
        adapter = run.proxy_adapter
        if adapter == "mitmproxy":
            control_scope = run.options.get("control_validation")
            allowed_destination_hosts = (
                list(control_scope.get("allowed_network_hosts", []))
                if isinstance(control_scope, dict)
                and control_scope.get("enabled") is True
                else []
            )
            return MitmProxyAdapter(
                self.settings,
                host=str(run.options.get("proxy_listen_host") or self.settings.proxy_listen_host),
                port=int(run.options.get("proxy_port") or 8080),
                allowed_client_ip=str(run.options.get("proxy_allowed_client_ip") or "") or None,
                allowed_destination_hosts=allowed_destination_hosts,
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

    async def _run_navigation(
        self,
        db: Session,
        run: DiagnosticRun,
        device,
        package_name: str,
    ) -> tuple[NavigationResult, Evidence]:
        driver = self.ui_driver_for_run(run, device, package_name)
        if driver is None:
            result = NavigationResult(
                status=CapabilityStatus.UNSUPPORTED.value,
                message="현재 플랫폼에는 자동 UI 탐색 Driver가 없습니다.",
                termination_reason="unsupported",
                states=[],
                actions=[],
                pending_approval=[],
                limits=NavigationLimits.from_options(
                    run.options.get("navigation_limits")
                ),
                started_at=datetime.now(timezone.utc).isoformat(),
                finished_at=datetime.now(timezone.utc).isoformat(),
                synthetic=run.synthetic,
            )
            graph = self.evidence.add_json(
                db,
                run_id=run.id,
                filename="navigation-graph.json",
                title="자동 UI 탐색 그래프",
                evidence_type="navigation_graph",
                data=result.to_dict(),
                description=result.message,
            )
            await self._emit_evidence(run.id, graph)
            return result, graph

        async def before_action(sequence, state, candidate):
            evidence_ids: list[str] = []
            screen_path = self.evidence.run_dir(run.id) / (
                f"navigation-{sequence:03d}-before.png"
            )
            screenshot = await driver.screenshot(screen_path)
            screen_evidence = await self._record_operation(
                db,
                run.id,
                f"UI 동작 {sequence:03d} · Before Screenshot",
                screenshot,
                "screenshot",
            )
            evidence_ids.append(screen_evidence.id)
            tree = self.evidence.add_json(
                db,
                run_id=run.id,
                filename=f"navigation-{sequence:03d}-before-ui.json",
                title=f"UI 동작 {sequence:03d} · Before UI Tree",
                evidence_type="ui_tree",
                data={
                    "phase": "before",
                    "candidate": candidate.to_dict(),
                    "state": state.to_dict(),
                    "raw_xml": state.raw_xml,
                },
            )
            await self._emit_evidence(run.id, tree)
            evidence_ids.append(tree.id)
            return evidence_ids

        async def after_action(
            sequence, state, candidate, operation, after_state, before_ids
        ):
            del before_ids
            evidence_ids: list[str] = []
            action_evidence = await self._record_operation(
                db,
                run.id,
                f"UI 동작 {sequence:03d} · {candidate.label}",
                operation,
                "navigation_action",
            )
            evidence_ids.append(action_evidence.id)
            screen_path = self.evidence.run_dir(run.id) / (
                f"navigation-{sequence:03d}-after.png"
            )
            screenshot = await driver.screenshot(screen_path)
            screen_evidence = await self._record_operation(
                db,
                run.id,
                f"UI 동작 {sequence:03d} · After Screenshot",
                screenshot,
                "screenshot",
            )
            evidence_ids.append(screen_evidence.id)
            if after_state is not None:
                triggers = self.evidence_policy.transition_triggers(
                    state, after_state
                )
                tree = self.evidence.add_json(
                    db,
                    run_id=run.id,
                    filename=f"navigation-{sequence:03d}-after-ui.json",
                    title=f"UI 동작 {sequence:03d} · After UI Tree",
                    evidence_type="ui_tree",
                    data={
                        "phase": "after",
                        "candidate": candidate.to_dict(),
                        "state": after_state.to_dict(),
                        "evidence_triggers": triggers,
                        "raw_xml": after_state.raw_xml,
                    },
                )
                await self._emit_evidence(run.id, tree)
                evidence_ids.append(tree.id)
            return evidence_ids

        async def navigation_update(data: dict[str, object]) -> None:
            candidate = data.get("candidate")
            state = data.get("state")
            if (
                data.get("event") == "pending"
                and isinstance(candidate, dict)
                and isinstance(state, dict)
            ):
                options = dict(run.options)
                navigation = dict(options.get("navigation") or {})
                pending = [
                    item
                    for item in navigation.get("pending_approval", [])
                    if isinstance(item, dict)
                ]
                if not any(item.get("id") == candidate.get("id") for item in pending):
                    pending.append(candidate)
                states = [
                    item
                    for item in navigation.get("states", [])
                    if isinstance(item, dict)
                ]
                if not any(
                    item.get("fingerprint") == state.get("fingerprint")
                    for item in states
                ):
                    states.append(state)
                actions = [
                    item
                    for item in navigation.get("actions", [])
                    if isinstance(item, dict)
                ]
                navigation.update(
                    {
                        "status": CapabilityStatus.AVAILABLE.value,
                        "message": "승인 대기 UI 후보를 현재 화면에 고정했습니다.",
                        "termination_reason": "approval_checkpoint",
                        "states": states,
                        "actions": actions,
                        "pending_approval": pending,
                        "state_count": int(data.get("state_count") or len(states)),
                        "action_count": int(data.get("action_count") or len(actions)),
                        "synthetic": run.synthetic,
                    }
                )
                options["navigation"] = navigation
                options["pending_navigation_actions"] = pending
                run.options = options
                db.commit()
                if (
                    run.options.get("pause_for_approval_candidates")
                    and approval_eligible(candidate)
                ):
                    await self.events.publish(run.id, "navigation", data)
                    await self.pause(
                        run.id,
                        "현재 화면의 중위험 UI 후보가 1회 승인 검토를 기다립니다.",
                    )
                    await self._checkpoint(run.id)
                    db.refresh(run)
                    return
            await self.events.publish(run.id, "navigation", data)

        engine = NavigationEngine(
            driver,
            target_package=package_name,
            limits=NavigationLimits.from_options(
                run.options.get("navigation_limits")
            ),
            hooks=NavigationHooks(
                before_action=before_action,
                after_action=after_action,
                on_update=navigation_update,
            ),
            synthetic=run.synthetic,
        )
        result = await engine.run()
        graph = self.evidence.add_json(
            db,
            run_id=run.id,
            filename="navigation-graph.json",
            title="자동 UI 탐색 그래프",
            evidence_type="navigation_graph",
            data=result.to_dict(include_elements=True),
            description=result.message,
        )
        await self._emit_evidence(run.id, graph)
        return result, graph

    async def _record_storage_capture(
        self,
        db: Session,
        run: DiagnosticRun,
        phase: str,
        capture: StorageCapture,
    ) -> list[Evidence]:
        recorded: list[Evidence] = []
        snapshot = capture.snapshot
        if capture.archive_path:
            archive_evidence = self.evidence.add(
                db,
                run_id=run.id,
                evidence_type="storage_archive",
                title=f"앱 전용 저장소 원본 · {phase}",
                description=capture.message,
                file_path=capture.archive_path,
                mime_type="application/x-tar",
                command=capture.command,
                inline_data={
                    "phase": phase,
                    "status": capture.status,
                    "package": snapshot.package_name if snapshot else None,
                    "root": snapshot.root if snapshot else None,
                    "file_count": len(snapshot.files) if snapshot else 0,
                    "synthetic": capture.synthetic,
                },
            )
            await self._emit_evidence(run.id, archive_evidence)
            recorded.append(archive_evidence)
        metadata = self.evidence.add_json(
            db,
            run_id=run.id,
            filename=f"storage-{phase}.json",
            title=f"앱 전용 저장소 구조 · {phase}",
            evidence_type="storage_snapshot",
            data=capture.to_dict(),
            description=capture.message,
            command=capture.command,
        )
        await self._emit_evidence(run.id, metadata)
        recorded.append(metadata)
        return recorded

    async def _run_network_testing(
        self,
        db: Session,
        run: DiagnosticRun,
        flows,
        flow_rows: list[ProxyFlow],
    ) -> tuple[dict[str, Any], Evidence]:
        analyses = []
        candidates = []
        executions: list[NetworkExecution] = []
        engine = NetworkCandidateEngine()
        mock_executor = MockNetworkTestExecutor()
        source_by_id = {}
        bounded_pairs = list(zip(flows, flow_rows))[
            : self.settings.network_analysis_max_flows
        ]
        for flow, row in bounded_pairs:
            analysis = classify_proxy_flow(flow, source_flow_id=row.id)
            analyses.append(analysis)
            source_by_id[row.id] = flow
            remaining = self.settings.network_candidate_max_count - len(candidates)
            if remaining <= 0:
                break
            candidates.extend(engine.generate(analysis)[:remaining])

        for candidate in candidates:
            source = source_by_id[candidate.source_flow_id]
            if candidate.requires_approval or not candidate.auto_executable:
                candidate.status = "pending_approval"
                continue
            if run.run_mode == RunMode.MOCK.value:
                execution = await mock_executor.execute(candidate, source)
            elif candidate.test_type == "passive_metadata":
                execution = NetworkExecution(
                    candidate_id=candidate.id,
                    status=CapabilityStatus.AVAILABLE.value,
                    message="외부 전송 없이 캡처된 Flow metadata를 로컬 분류했습니다.",
                    synthetic=False,
                )
            else:
                candidate.status = "pending_approval"
                continue
            executions.append(execution)
            candidate.status = (
                "executed"
                if execution.status == CapabilityStatus.AVAILABLE.value
                else execution.status
            )

        pending = [item for item in candidates if item.requires_approval]
        payload = {
            "status": CapabilityStatus.AVAILABLE.value,
            "message": (
                f"Flow {len(analyses)}건에서 Candidate {len(candidates)}건을 만들고 "
                f"로컬·Mock 안전 작업 {len(executions)}건을 실행했습니다."
            ),
            "flow_count": len(analyses),
            "candidate_count": len(candidates),
            "executed_count": len(executions),
            "pending_count": len(pending),
            "analyses": [item.to_dict() for item in analyses],
            "candidates": [item.to_dict() for item in candidates],
            "executions": [item.to_dict() for item in executions],
            "pending_approval": [item.to_dict() for item in pending],
            "synthetic": run.synthetic,
            "truncated": (
                len(flows) > len(analyses)
                or len(candidates) >= self.settings.network_candidate_max_count
            ),
        }
        evidence = self.evidence.add_json(
            db,
            run_id=run.id,
            filename="network-testing.json",
            title="API 진단 Candidate와 응답 비교",
            evidence_type="network_test",
            data=payload,
            description=(
                "상태 변경 요청과 Object 경계 후보는 실행하지 않고 승인 대기로 분리했습니다."
            ),
        )
        await self._emit_evidence(run.id, evidence)
        for execution in executions:
            execution.evidence_ids.append(evidence.id)
        payload["executions"] = [item.to_dict() for item in executions]
        await self.events.publish(
            run.id,
            "network_testing",
            {
                "status": payload["status"],
                "flow_count": payload["flow_count"],
                "candidate_count": payload["candidate_count"],
                "executed_count": payload["executed_count"],
                "pending_count": payload["pending_count"],
                "evidence_id": evidence.id,
            },
        )
        return payload, evidence

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
                    standard=item.standard,
                    criteria=item.criteria,
                    evidence_requirements=item.evidence_requirements,
                    finding_categories=item.finding_categories,
                    finding_ids=[],
                    risk=item.risk,
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
    ) -> list[ProxyFlow]:
        rows: list[ProxyFlow] = []
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
            db.flush()
            rows.append(row)
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
        return rows

    async def _record_control_scope_enforcement(
        self,
        db: Session,
        run: DiagnosticRun,
        flows,
        flow_rows: list[ProxyFlow],
        control_scope: dict[str, Any],
    ) -> tuple[dict[str, Any], Evidence]:
        summary = evaluate_network_scope(
            flows,
            [row.id for row in flow_rows],
            list(control_scope["allowed_network_hosts"]),
        )
        evidence = self.evidence.add_json(
            db,
            run_id=run.id,
            filename="control-scope-enforcement.json",
            title="승인 범위 네트워크 집행 결과",
            evidence_type="control_scope_enforcement",
            data=summary,
            description=(
                f"허용 서버 밖 목적지 {summary['violation_count']}건을 식별해 자동 실행을 중단했습니다."
                if summary["violation_count"]
                else f"프록시 흐름 {summary['evaluated_flow_count']}건이 승인된 서버 범위 안에 있습니다."
            ),
        )
        summary["evidence_id"] = evidence.id
        options = dict(run.options)
        options["control_scope_enforcement"] = summary
        run.options = options
        db.commit()
        await self._emit_evidence(run.id, evidence)
        return summary, evidence

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

    @staticmethod
    def _process_running(operation, package_name: str) -> bool:
        return operation.status == CapabilityStatus.AVAILABLE and bool(
            operation.data.get("running")
            or operation.data.get("pids")
            or package_name in operation.output
        )

    async def _wait_for_process_state(
        self,
        device,
        device_id: str,
        package_name: str,
        *,
        expected_running: bool,
        attempts: int = 5,
    ):
        latest = None
        for attempt in range(attempts):
            latest = await device.process_info(device_id, package_name)
            if latest.status != CapabilityStatus.AVAILABLE:
                break
            if self._process_running(latest, package_name) is expected_running:
                break
            if attempt + 1 < attempts:
                await asyncio.sleep(0.25)
        return latest

    async def _execute(self, run_id: str) -> None:
        proxy = None
        lease_acquired = False
        frida_session_started = False
        frida_script_rows: list[FridaScript] = []
        control_scope: dict[str, Any] | None = None
        quality_checks: dict[str, dict[str, Any]] = {}
        quality_gaps: list[dict[str, str]] = []

        def record_check(
            name: str,
            passed: bool,
            message: str,
            *,
            required: bool = True,
        ) -> None:
            quality_checks[name] = {
                "passed": passed,
                "required": required,
                "message": message,
            }
            if passed:
                quality_gaps[:] = [
                    item for item in quality_gaps if item["stage"] != name
                ]
            if required and not passed:
                quality_gaps[:] = [
                    item for item in quality_gaps if item["stage"] != name
                ]
                quality_gaps.append({"stage": name, "message": message})

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
                try:
                    control_scope = active_control_scope(run.options, run.device_id)
                except ControlScopeError as exc:
                    record_check("control_scope", False, str(exc))
                    raise DiagnosticManualRequired(str(exc)) from exc
                if control_scope:
                    record_check(
                        "control_scope",
                        True,
                        "승인 기간·단말·허용 서버 범위를 실행 시점에 다시 확인했습니다.",
                    )
                run.started_at = datetime.now(timezone.utc)
                options = dict(run.options)
                options.update(
                    {
                        "completion_checks": {},
                        "quality_gaps": [],
                        "manual_action_active": False,
                    }
                )
                run.options = options
                db.commit()
                proxy_port = (
                    int(run.options.get("proxy_port"))
                    if run.proxy_adapter == "mitmproxy" and run.options.get("proxy_port")
                    else None
                )
                await self._leases.acquire(run.id, run.device_id, proxy_port)
                lease_acquired = True
                device = self.device_for_run(db, run)
                proxy = self._proxy(run)
                self._proxy_adapters[run.id] = proxy
                self._seed_run_controls(db, run, app)

                await self._stage(db, run, "preflight", 4, "Adapter와 대상 정보를 확인합니다.")
                device_list = await device.discover()
                if not any(item.id == run.device_id for item in device_list):
                    raise RuntimeError(f"선택한 단말을 찾을 수 없습니다: {run.device_id}")
                selected_device_info = next(
                    item for item in device_list if item.id == run.device_id
                )
                preflight_options = {
                    key: value
                    for key, value in run.options.items()
                    if key != "control_validation"
                }
                if control_scope:
                    preflight_options["control_validation"] = {
                        "enabled": True,
                        "scope_recorded_locally": True,
                        "external_ai_excluded": True,
                    }
                preflight = self.evidence.add_json(
                    db,
                    run_id=run.id,
                    filename="preflight.json",
                    title="진단 전 상태",
                    evidence_type="device_state",
                    data={
                        "device": selected_device_info.to_dict(),
                        "app": {
                            "name": app.app_name if app else None,
                            "package": app.package_name if app else None,
                            "version": app.version if app else None,
                            "sha256": app.sha256 if app else None,
                        },
                        "options": preflight_options,
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
                            "manual_proxy_setup_confirmed": False,
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
                        "Burp/Fiddler Listener와 단말 프록시 설정을 확인한 뒤 재개하세요.",
                    )
                    await self._checkpoint(run.id)
                    db.refresh(run)
                    if not bool(run.options.get("manual_proxy_setup_confirmed")):
                        raise DiagnosticManualRequired(
                            "수동 프록시 설정 확인 없이 진단을 재개할 수 없습니다."
                        )

                if app:
                    await self._stage(db, run, "install", 22, "대상 앱을 단말에 설치합니다.")
                    install = await device.install_app(run.device_id, Path(app.stored_path))
                    await self._record_operation(db, run.id, "앱 설치", install)
                    if install.status == CapabilityStatus.MANUAL_REQUIRED:
                        raise DiagnosticManualRequired(install.message)
                    if install.status != CapabilityStatus.AVAILABLE:
                        raise RuntimeError(install.message)

                if bool(run.options.get("pause_for_security_bypass")):
                    run.current_stage = "security_bypass_preparation"
                    db.commit()
                    await self.events.publish(
                        run.id,
                        "stage",
                        {
                            "stage": "security_bypass_preparation",
                            "progress": run.progress,
                            "message": (
                                "첫 앱 실행 전에 승인된 루팅·탈옥 탐지 우회 "
                                "Frida 스크립트를 검토하고 실행하세요."
                            ),
                            "status": RunStatus.PAUSE_REQUESTED.value,
                        },
                    )
                    await self.pause(
                        run.id,
                        "Frida 라이브러리에서 대상 코드와 SHA-256을 검토해 1회 승인 실행한 뒤 재개하세요.",
                    )
                    await self._checkpoint(run.id)
                    db.refresh(run)

                bypass_session_active = self.frida_sessions.is_active(run.id)
                await self._stage(
                    db,
                    run,
                    "launch_baseline",
                    32,
                    (
                        "승인된 Frida 우회가 적용된 상태로 앱 실행을 확인합니다."
                        if bypass_session_active
                        else "원본 상태에서 앱을 실행합니다."
                    ),
                )
                launch = await device.start_app(run.device_id, package_name)
                await self._record_operation(
                    db,
                    run.id,
                    (
                        "승인된 Frida 우회 상태 앱 실행"
                        if bypass_session_active
                        else "원본 상태 앱 실행"
                    ),
                    launch,
                )
                if launch.status == CapabilityStatus.MANUAL_REQUIRED:
                    record_check("app_launch", False, launch.message)
                    raise DiagnosticManualRequired(launch.message)
                if launch.status != CapabilityStatus.AVAILABLE:
                    record_check("app_launch", False, launch.message)
                    raise RuntimeError(f"앱 실행 실패: {launch.message}")
                record_check("app_launch", True, launch.message)
                process = await device.process_info(run.device_id, package_name)
                await self._record_operation(db, run.id, "앱 프로세스 실행 확인", process)
                process_running = (
                    process.status == CapabilityStatus.AVAILABLE
                    and bool(
                        process.data.get("running")
                        or process.data.get("pids")
                        or package_name in process.output
                    )
                )
                record_check(
                    "app_process",
                    process_running,
                    process.message if process_running else "앱 프로세스 실행을 확인하지 못했습니다.",
                )
                if process.status == CapabilityStatus.MANUAL_REQUIRED:
                    raise DiagnosticManualRequired(process.message)
                baseline_screen = await self._capture(
                    db,
                    run,
                    device,
                    "01-app-launched.png",
                    (
                        "승인된 Frida 우회 적용 후 앱 실행"
                        if bypass_session_active
                        else "앱 실행 직후"
                    ),
                    (
                        "승인된 루팅·탈옥 탐지 우회가 적용된 앱 실행 상태입니다."
                        if bypass_session_active
                        else "보안통제 적용 전 원본 실행 상태입니다."
                    ),
                )
                record_check(
                    "screenshot",
                    baseline_screen is not None,
                    "필수 화면 증적을 수집했습니다."
                    if baseline_screen
                    else "필수 화면 증적을 수집하지 못했습니다.",
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
                record_check(
                    "device_log",
                    logs.status == CapabilityStatus.AVAILABLE,
                    logs.message,
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
                before_frida_screen = await self._capture(
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
                frida_mode = str(run.options.get("frida_mode", "attach"))
                if frida_mode not in {"spawn", "attach"}:
                    raise RuntimeError("Frida 연결 방식은 spawn 또는 attach여야 합니다.")
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
                eligible_scripts: list[FridaScript] = []
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
                    eligible_scripts.append(script)
                scripts = eligible_scripts
                frida_script_rows = list(scripts)
                after_frida_screen = None
                if scripts:
                    event_loop = asyncio.get_running_loop()

                    def publish_frida_message(item: dict[str, Any]) -> None:
                        masked_json, _ = mask_context(
                            {"message": item}, self.settings.ai_sensitive_keys
                        )
                        masked_item = json.loads(masked_json)["message"]

                        def schedule() -> None:
                            asyncio.create_task(
                                self.events.publish(
                                    run.id,
                                    "frida_log",
                                    {
                                        "status": CapabilityStatus.AVAILABLE.value,
                                        "persistent": True,
                                        "messages": [masked_item],
                                        "masked": True,
                                        "health": self.frida_sessions.health(run.id),
                                    },
                                )
                            )

                        event_loop.call_soon_threadsafe(schedule)

                    session_scripts = [
                        FridaSessionScript(
                            script_id=script.id,
                            name=script.name,
                            content=script.content,
                        )
                        for script in scripts
                    ]
                    lifecycle_evidence_ids = (
                        [before_frida_screen.id] if before_frida_screen else []
                    )
                    frida_target = None
                    session_was_active = self.frida_sessions.is_active(run.id)
                    if not session_was_active:
                        try:
                            frida_target = self.frida_target_for_device(
                                device, run.device_id
                            )
                        except ValueError as exc:
                            record_check("frida_session", False, str(exc))
                            raise DiagnosticManualRequired(str(exc)) from exc

                        if frida_mode == "spawn":
                            stop_operation = await device.stop_app(
                                run.device_id, package_name
                            )
                            stop_evidence = await self._record_operation(
                                db,
                                run.id,
                                "Frida Spawn 전 앱 정상 종료",
                                stop_operation,
                            )
                            lifecycle_evidence_ids.append(stop_evidence.id)
                            if stop_operation.status == CapabilityStatus.MANUAL_REQUIRED:
                                raise DiagnosticManualRequired(stop_operation.message)
                            if stop_operation.status != CapabilityStatus.AVAILABLE:
                                raise RuntimeError(
                                    f"Frida Spawn 전 앱 종료 실패: {stop_operation.message}"
                                )
                            stopped_process = await self._wait_for_process_state(
                                device,
                                run.device_id,
                                package_name,
                                expected_running=False,
                            )
                            stopped_evidence = await self._record_operation(
                                db,
                                run.id,
                                "Frida Spawn 전 프로세스 종료 확인",
                                stopped_process,
                            )
                            lifecycle_evidence_ids.append(stopped_evidence.id)
                            if stopped_process.status == CapabilityStatus.MANUAL_REQUIRED:
                                raise DiagnosticManualRequired(stopped_process.message)
                            if stopped_process.status != CapabilityStatus.AVAILABLE:
                                raise RuntimeError(
                                    "Frida Spawn 전 프로세스 종료 여부를 확인하지 못했습니다: "
                                    f"{stopped_process.message}"
                                )
                            if self._process_running(stopped_process, package_name):
                                raise RuntimeError(
                                    "Frida Spawn 전 대상 앱 프로세스가 아직 실행 중입니다."
                                )
                        else:
                            attach_process = await self._wait_for_process_state(
                                device,
                                run.device_id,
                                package_name,
                                expected_running=True,
                            )
                            attach_evidence = await self._record_operation(
                                db,
                                run.id,
                                "Frida Attach 대상 프로세스 확인",
                                attach_process,
                            )
                            lifecycle_evidence_ids.append(attach_evidence.id)
                            if attach_process.status == CapabilityStatus.MANUAL_REQUIRED:
                                raise DiagnosticManualRequired(attach_process.message)
                            if not self._process_running(attach_process, package_name):
                                raise RuntimeError(
                                    "Frida Attach 직전 대상 앱 프로세스 실행을 확인하지 못했습니다."
                                )
                    if session_was_active:
                        self.frida_sessions.set_message_callback(
                            run.id, publish_frida_message
                        )
                        load_results = [
                            await self.frida_sessions.load_script(run.id, script)
                            for script in session_scripts
                        ]
                        loaded_ids = [
                            script_id
                            for item in load_results
                            for script_id in item.loaded_script_ids
                        ]
                        failed_scripts = {
                            script_id: message
                            for item in load_results
                            for script_id, message in item.failed_scripts.items()
                        }
                        active_health = self.frida_sessions.health(run.id)
                        execution = FridaSessionResult(
                            (
                                CapabilityStatus.AVAILABLE
                                if len(set(loaded_ids)) == len(session_scripts)
                                else CapabilityStatus.FAILED
                            ),
                            "기존 Run 수명 Frida 세션에 자동 스크립트를 추가했습니다.",
                            str(
                                active_health.get("mode", frida_mode)
                            ),
                            package_name,
                            command="python-frida --persistent-load",
                            loaded_script_ids=list(dict.fromkeys(loaded_ids)),
                            failed_scripts=failed_scripts,
                            messages=self.frida_sessions.snapshot(run.id, limit=20),
                            transport=str(active_health.get("transport") or ""),
                            device_id=active_health.get("device_id"),
                            endpoint=active_health.get("endpoint"),
                            transcript_path=active_health.get("transcript_path"),
                            stats=active_health,
                        )
                    else:
                        execution = await self.frida_sessions.start(
                            run_id=run.id,
                            frida_target=frida_target,
                            target=package_name,
                            scripts=session_scripts,
                            mode=frida_mode,
                            mock=run.device_adapter == "mock",
                            on_message=publish_frida_message,
                        )
                    frida_session_started = self.frida_sessions.is_active(run.id)
                    loaded = set(execution.loaded_script_ids)
                    frida_ok = (
                        execution.status == CapabilityStatus.AVAILABLE
                        and all(script.id in loaded for script in scripts)
                    )
                    record_check(
                        "frida_session",
                        frida_ok,
                        execution.message,
                    )
                    if frida_ok and not session_was_active:
                        if frida_mode == "spawn":
                            note_resume = getattr(
                                device, "note_frida_spawn_resumed", None
                            )
                            if callable(note_resume):
                                note_resume(package_name)
                        resumed_process = await self._wait_for_process_state(
                            device,
                            run.device_id,
                            package_name,
                            expected_running=True,
                        )
                        resumed_evidence = await self._record_operation(
                            db,
                            run.id,
                            (
                                "Frida Spawn 후 프로세스 실행 확인"
                                if frida_mode == "spawn"
                                else "Frida Attach 후 프로세스 유지 확인"
                            ),
                            resumed_process,
                        )
                        lifecycle_evidence_ids.append(resumed_evidence.id)
                        process_resumed = self._process_running(
                            resumed_process, package_name
                        )
                        if not process_resumed:
                            frida_ok = False
                            record_check(
                                "frida_session",
                                False,
                                (
                                    "Frida Spawn/Attach 후 대상 앱 프로세스 실행을 "
                                    "확인하지 못했습니다."
                                ),
                            )
                    after_frida_screen = await self._capture(
                        db,
                        run,
                        device,
                        "03-after-frida.png",
                        "우회 적용 후",
                        "Frida 연결 후 앱 실행 상태입니다. 성공 여부는 프로세스와 로그 증적을 함께 검토합니다.",
                    )
                    if after_frida_screen:
                        lifecycle_evidence_ids.append(after_frida_screen.id)
                    health = self.frida_sessions.health(run.id)
                    options = dict(run.options)
                    options["frida_health"] = health
                    run.options = options
                    for script in scripts:
                        script_loaded = script.id in loaded
                        if not run.synthetic and script_loaded:
                            script.success_count += 1
                        elif not run.synthetic:
                            script.failure_count += 1
                        script_evidence = self.evidence.add(
                            db,
                            run_id=run.id,
                            evidence_type="frida_script",
                            title=f"Frida 세션 스크립트 · {script.name}",
                            description=execution.message,
                            command=execution.command,
                            inline_data={
                                "script_id": script.id,
                                "risk": script.risk,
                                "content": script.content,
                                "persistent_until_run_end": True,
                                "loaded": script_loaded,
                                "lifecycle_evidence_ids": lifecycle_evidence_ids,
                                "transport": {
                                    "type": execution.transport,
                                    "device_id": execution.device_id,
                                    "endpoint": execution.endpoint,
                                },
                                "result": execution.to_dict(),
                            },
                        )
                        await self._emit_evidence(run.id, script_evidence)
                        self._complete_controls(
                            db,
                            run.id,
                            {"MASTG-TEST-0048", "MASTG-TEST-0091"},
                            result="needs_review" if script_loaded else "unknown",
                            summary=(
                                "승인된 Frida 스크립트를 Run 수명 세션에 로드했습니다."
                                if script_loaded
                                else "Frida 스크립트를 세션에 로드하지 못했습니다."
                            ),
                            evidence_ids=[script_evidence.id],
                        )
                        if (
                            not script_loaded
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
                    db.commit()
                    execution_event = execution.to_dict()
                    # Individual messages are already emitted by the persistent
                    # session callback; do not replay the full snapshot here.
                    execution_event["messages"] = []
                    await self.events.publish(run.id, "frida_log", execution_event)
                    await self.events.publish(run.id, "frida_health", health)
                    if not frida_ok:
                        raise RuntimeError(
                            f"Frida {frida_mode} lifecycle 검증 실패: {execution.message}"
                        )
                else:
                    if self.frida_sessions.is_active(run.id):
                        frida_session_started = True
                        health = self.frida_sessions.health(run.id)
                        record_check(
                            "frida_session",
                            self.frida_sessions.is_healthy(run.id),
                            "승인된 직접 Frida 스크립트가 Run 수명 세션에서 실행 중입니다.",
                            required=False,
                        )
                        await self.events.publish(run.id, "frida_health", health)
                        after_frida_screen = await self._capture(
                            db,
                            run,
                            device,
                            "03-after-approved-bypass.png",
                            "승인된 보안통제 우회 적용 후",
                            "검토·승인된 직접 Frida 스크립트를 적용한 대상 앱 실행 상태입니다.",
                        )
                    else:
                        record_check(
                            "frida_session",
                            True,
                            "선택된 Frida 스크립트가 없어 실행하지 않았습니다.",
                            required=False,
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
                if after_frida_screen is None:
                    await self._capture(
                        db,
                        run,
                        device,
                        "03-after-frida.png",
                        "Frida 미적용 상태",
                        "선택된 Frida 스크립트가 없는 앱 실행 상태입니다.",
                    )

                storage_enabled = bool(run.options.get("dynamic_storage"))
                storage_collector = None
                storage_before: StorageCapture | None = None
                storage_evidence_ids: list[str] = []
                if storage_enabled and app_platform == "android":
                    await self._stage(
                        db,
                        run,
                        "dynamic_storage_before",
                        61,
                        "대상 package 범위의 조작 전 저장소 Snapshot을 수집합니다.",
                    )
                    storage_collector = self.storage_collector_for_run(
                        run,
                        package_name,
                        privileged=selected_device_info.privileged,
                    )
                    if storage_collector is not None:
                        storage_before = await storage_collector.capture(
                            "before_interaction",
                            self.evidence.run_dir(run.id)
                            / "storage-before-interaction.tar",
                        )
                        before_records = await self._record_storage_capture(
                            db, run, "before_interaction", storage_before
                        )
                        storage_evidence_ids.extend(
                            item.id for item in before_records
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
                    record_check(
                        "app_interaction",
                        True,
                        "사용자가 로그인 완료를 확인했습니다.",
                    )

                navigation_enabled = run.options.get("auto_navigation")
                if navigation_enabled is None:
                    navigation_enabled = (
                        run.run_mode == RunMode.MOCK.value
                        and app_platform == "android"
                    )
                if navigation_enabled and app_platform == "android":
                    await self._stage(
                        db,
                        run,
                        "navigation",
                        64,
                        "UI Tree에서 저위험 화면 이동 후보를 자동 탐색합니다.",
                    )
                    navigation_result, navigation_graph = await self._run_navigation(
                        db, run, device, package_name
                    )
                    navigation_summary = navigation_result.to_dict()
                    navigation_summary["graph_evidence_id"] = navigation_graph.id
                    previous_navigation = run.options.get("navigation")
                    approved_actions = (
                        list(previous_navigation.get("approved_actions") or [])
                        if isinstance(previous_navigation, dict)
                        else []
                    )
                    approved_ids = {
                        str(item.get("id") or "")
                        for item in approved_actions
                        if isinstance(item, dict)
                    }
                    navigation_summary["pending_approval"] = [
                        item
                        for item in navigation_summary["pending_approval"]
                        if str(item.get("id") or "") not in approved_ids
                    ]
                    navigation_summary["approved_actions"] = approved_actions
                    options = dict(run.options)
                    options["navigation"] = navigation_summary
                    options["pending_navigation_actions"] = (
                        navigation_summary["pending_approval"]
                    )
                    run.options = options
                    db.commit()
                    navigation_ok = (
                        navigation_result.status == CapabilityStatus.AVAILABLE.value
                        and bool(navigation_result.states)
                    )
                    record_check(
                        "navigation",
                        navigation_ok,
                        navigation_result.message,
                    )
                    if navigation_result.actions:
                        record_check(
                            "app_interaction",
                            True,
                            (
                                f"위험 정책을 통과한 UI 동작 "
                                f"{len(navigation_result.actions)}건을 실행했습니다."
                            ),
                        )
                    elif not run.options.get("pause_for_login"):
                        record_check(
                            "app_interaction",
                            False,
                            "자동 실행 가능한 저위험 UI 동작을 찾지 못했습니다.",
                        )
                    await self.events.publish(
                        run.id,
                        "navigation_complete",
                        navigation_summary,
                    )
                elif run.run_mode == RunMode.LIVE.value and not run.options.get(
                    "pause_for_login"
                ):
                    record_check(
                        "app_interaction",
                        False,
                        "자동 화면 탐색이나 사용자 기능 조작 확인이 없어 동적 진단 범위가 제한됩니다.",
                    )
                elif run.run_mode == RunMode.MOCK.value and app_platform != "android":
                    record_check(
                        "app_interaction",
                        True,
                        "Mock iOS 합성 동작을 수행했습니다. iOS 자동 탐색은 아직 지원하지 않습니다.",
                    )

                if storage_enabled and app_platform == "android":
                    await self._stage(
                        db,
                        run,
                        "dynamic_storage",
                        68,
                        "대상 package의 조작 후 저장소와 SQLite 구조 변화를 비교합니다.",
                    )
                    storage_after = (
                        await storage_collector.capture(
                            "after_interaction",
                            self.evidence.run_dir(run.id)
                            / "storage-after-interaction.tar",
                        )
                        if storage_collector is not None
                        else StorageCapture(
                            CapabilityStatus.UNSUPPORTED.value,
                            "현재 단말에는 앱 전용 저장소 Collector가 없습니다.",
                        )
                    )
                    after_records = await self._record_storage_capture(
                        db, run, "after_interaction", storage_after
                    )
                    storage_evidence_ids.extend(item.id for item in after_records)
                    changes = []
                    diff_evidence = None
                    if (
                        storage_before
                        and storage_before.snapshot
                        and storage_after.snapshot
                    ):
                        changes = diff_snapshots(
                            storage_before.snapshot, storage_after.snapshot
                        )
                        diff_evidence = self.evidence.add_json(
                            db,
                            run_id=run.id,
                            filename="storage-diff.json",
                            title="앱 전용 저장소 Before/After Diff",
                            evidence_type="storage_diff",
                            data={
                                "package_name": package_name,
                                "before_phase": storage_before.snapshot.phase,
                                "after_phase": storage_after.snapshot.phase,
                                "changes": [item.to_dict() for item in changes],
                                "synthetic": run.synthetic,
                            },
                            description=(
                                f"created/modified/deleted 파일 변화 {len(changes)}건을 식별했습니다."
                            ),
                        )
                        await self._emit_evidence(run.id, diff_evidence)
                        storage_evidence_ids.append(diff_evidence.id)
                    storage_ok = (
                        storage_before is not None
                        and storage_before.status
                        == CapabilityStatus.AVAILABLE.value
                        and storage_after.status
                        == CapabilityStatus.AVAILABLE.value
                    )
                    record_check(
                        "dynamic_storage",
                        storage_ok,
                        (
                            f"앱 전용 저장소 변화 {len(changes)}건을 비교했습니다."
                            if storage_ok
                            else storage_after.message
                            or (storage_before.message if storage_before else "저장소 수집 실패")
                        ),
                    )
                    after_snapshot = storage_after.snapshot
                    options = dict(run.options)
                    options["storage"] = {
                        "status": (
                            CapabilityStatus.AVAILABLE.value
                            if storage_ok
                            else storage_after.status
                        ),
                        "message": storage_after.message,
                        "before_file_count": (
                            len(storage_before.snapshot.files)
                            if storage_before and storage_before.snapshot
                            else 0
                        ),
                        "after_file_count": (
                            len(after_snapshot.files) if after_snapshot else 0
                        ),
                        "change_count": len(changes),
                        "changes": [item.to_dict() for item in changes[:500]],
                        "databases": (
                            [item.to_dict() for item in after_snapshot.databases[:50]]
                            if after_snapshot
                            else []
                        ),
                        "clipboard": (
                            after_snapshot.clipboard if after_snapshot else {}
                        ),
                        "evidence_ids": storage_evidence_ids,
                        "synthetic": run.synthetic,
                    }
                    run.options = options
                    db.commit()
                    if storage_evidence_ids:
                        self._complete_controls(
                            db,
                            run.id,
                            {"MASTG-TEST-0001"},
                            result="needs_review" if storage_ok else "unknown",
                            summary=(
                                "앱 package 전용 저장소와 마스킹된 SQLite 구조를 비교했습니다."
                                if storage_ok
                                else "앱 전용 저장소 자동 수집을 완료하지 못했습니다."
                            ),
                            evidence_ids=storage_evidence_ids,
                        )

                await self._stage(
                    db, run, "network_dynamic", 70, "프록시 패킷과 동적 증적을 수집합니다."
                )
                await asyncio.sleep(0.1)
                flows = []

                dynamic_screen = await self._capture(
                    db,
                    run,
                    device,
                    "05-test-after.png",
                    "테스트 동작 후",
                    "동적·네트워크 테스트 종료 시점의 화면입니다.",
                )
                record_check(
                    "screenshot",
                    baseline_screen is not None or dynamic_screen is not None,
                    (
                        "필수 화면 증적을 1개 이상 수집했습니다."
                        if baseline_screen is not None or dynamic_screen is not None
                        else "필수 화면 증적을 수집하지 못했습니다."
                    ),
                )
                dynamic_log_path = self.evidence.run_dir(run.id) / "dynamic-logcat.txt"
                dynamic_logs = await device.collect_logs(run.device_id, dynamic_log_path)
                dynamic_evidence = await self._record_operation(
                    db, run.id, "동적 분석 단말 로그", dynamic_logs, "device_log"
                )
                record_check(
                    "device_log",
                    logs.status == CapabilityStatus.AVAILABLE
                    or dynamic_logs.status == CapabilityStatus.AVAILABLE,
                    (
                        "원본 또는 동적 단계에서 단말 로그를 수집했습니다."
                        if logs.status == CapabilityStatus.AVAILABLE
                        or dynamic_logs.status == CapabilityStatus.AVAILABLE
                        else "원본과 동적 단계 모두 단말 로그 수집에 실패했습니다."
                    ),
                )
                final_process = await device.process_info(run.device_id, package_name)
                await self._record_operation(
                    db, run.id, "동적 진단 종료 시 앱 프로세스 확인", final_process
                )
                final_process_running = (
                    final_process.status == CapabilityStatus.AVAILABLE
                    and bool(
                        final_process.data.get("running")
                        or final_process.data.get("pids")
                        or package_name in final_process.output
                    )
                )
                record_check(
                    "app_process",
                    final_process_running,
                    final_process.message
                    if final_process_running
                    else "동적 진단 종료 시 앱 프로세스 실행을 확인하지 못했습니다.",
                )
                self._complete_controls(
                    db,
                    run.id,
                    {"MASTG-TEST-0003", "MASTG-TEST-0053"},
                    result="needs_review",
                    summary="동적 단말 로그를 수집해 민감정보 노출 검토 대상으로 연결했습니다.",
                    evidence_ids=[dynamic_evidence.id],
                )

                if run.proxy_adapter in {"burp", "fiddler"}:
                    run.current_stage = "proxy_capture_import"
                    run.progress = 78
                    db.commit()
                    await self.events.publish(
                        run.id,
                        "stage",
                        {
                            "stage": "proxy_capture_import",
                            "progress": 78,
                            "message": "앱 조작이 끝났습니다. Burp/Fiddler 캡처를 종료하고 최종 HAR/JSON을 가져오세요.",
                            "status": RunStatus.PAUSE_REQUESTED.value,
                        },
                    )
                    await self.pause(
                        run.id,
                        "Burp/Fiddler 캡처 종료 후 최종 HAR/JSON을 가져오세요.",
                    )
                    await self._checkpoint(run.id)
                    db.refresh(run)
                    if not bool(run.options.get("manual_proxy_imported")):
                        raise DiagnosticManualRequired(
                            "최종 HAR Import 확인 없이 수동 프록시 진단을 완료할 수 없습니다."
                        )

                stop_proxy = await asyncio.shield(proxy.stop(run.id))
                await self.events.publish(run.id, "proxy_status", stop_proxy.to_dict())
                await asyncio.sleep(0.1)
                flows = await proxy.read_flows(run.id)
                flow_rows = await self._store_proxy_flows(db, run, proxy, flows)
                record_check(
                    "proxy_capture",
                    bool(flows),
                    f"최종 프록시 흐름 {len(flows)}개를 저장했습니다."
                    if flows
                    else "프록시 흐름이 0개여서 네트워크 진단 범위를 확인할 수 없습니다.",
                )
                if control_scope:
                    try:
                        control_scope = active_control_scope(
                            run.options,
                            run.device_id,
                        )
                    except ControlScopeError as exc:
                        record_check("control_scope_enforcement", False, str(exc))
                        raise DiagnosticManualRequired(str(exc)) from exc
                    await self._stage(
                        db,
                        run,
                        "control_scope_enforcement",
                        79,
                        "캡처 목적지를 승인된 테스트 서버 범위와 대조합니다.",
                    )
                    scope_summary, _ = await self._record_control_scope_enforcement(
                        db,
                        run,
                        flows,
                        flow_rows,
                        control_scope,
                    )
                    violation_count = int(scope_summary["violation_count"])
                    record_check(
                        "control_scope_enforcement",
                        violation_count == 0,
                        (
                            "모든 프록시 목적지가 승인된 테스트 서버 범위 안에 있습니다."
                            if violation_count == 0
                            else f"승인 범위 밖 네트워크 목적지 {violation_count}건을 식별했습니다."
                        ),
                    )
                    if violation_count:
                        blocked_count = sum(
                            1
                            for item in scope_summary["violations"]
                            if item["blocked_before_upstream"]
                        )
                        raise DiagnosticManualRequired(
                            "승인 범위 밖 네트워크 목적지를 식별해 자동 진단을 중단했습니다. "
                            f"총 {violation_count}건 중 upstream 전 차단 {blocked_count}건입니다. "
                            "허용 서버 목록과 고객사 승인 범위를 검토하세요."
                        )
                await self._stage(
                    db,
                    run,
                    "network_testing",
                    80,
                    "ProxyFlow를 구조화하고 API 검증 Candidate의 승인 경계를 판정합니다.",
                )
                network_summary, network_evidence = await self._run_network_testing(
                    db, run, flows, flow_rows
                )
                options = dict(run.options)
                options["network_testing"] = network_summary
                options["pending_network_tests"] = network_summary[
                    "pending_approval"
                ]
                options["network_testing_evidence_id"] = network_evidence.id
                run.options = options
                db.commit()
                if (
                    run.options.get("pause_for_approval_candidates")
                    and any(
                        isinstance(item, dict)
                        and item.get("test_type") == "read_only_replay"
                        and item.get("method") in {"GET", "HEAD"}
                        for item in network_summary["pending_approval"]
                    )
                ):
                    await self.pause(
                        run.id,
                        "승인 가능한 GET/HEAD API Candidate가 있어 1회 승인 검토를 기다립니다.",
                    )
                    await self._checkpoint(run.id)
                    db.refresh(run)
                record_check(
                    "network_testing",
                    bool(network_summary["flow_count"]),
                    str(network_summary["message"]),
                )
                if self.frida_sessions.is_active(run.id) and not frida_session_started:
                    frida_session_started = True
                    record_check(
                        "frida_session",
                        self.frida_sessions.is_healthy(run.id),
                        "수동 승인 Frida 스크립트를 Run 종료까지 유지했습니다.",
                    )
                if frida_session_started:
                    session_healthy = self.frida_sessions.is_healthy(run.id)
                    if not session_healthy:
                        record_check(
                            "frida_session",
                            False,
                            "동적·네트워크 진단이 끝나기 전에 Frida 세션이 분리되었습니다.",
                        )
                    stop_result = await asyncio.shield(
                        self.frida_sessions.stop(run.id)
                    )
                    frida_session_started = False
                    if stop_result:
                        final_health = dict(stop_result.stats)
                        final_health.update(
                            {
                                "active": False,
                                "healthy": (
                                    session_healthy
                                    and stop_result.status
                                    == CapabilityStatus.AVAILABLE
                                ),
                                "cleanup_status": stop_result.status.value,
                            }
                        )
                        integrity_ok, integrity_message = _frida_evidence_integrity(
                            final_health
                        )
                        record_check(
                            "frida_evidence_integrity",
                            integrity_ok,
                            integrity_message,
                        )
                        options = dict(run.options)
                        options["frida_health"] = final_health
                        run.options = options
                        db.commit()
                        await self.events.publish(
                            run.id, "frida_health", final_health
                        )
                        transcript_path = Path(
                            str(stop_result.transcript_path or "")
                        )
                        if transcript_path.is_file():
                            transcript = self.evidence.add(
                                db,
                                run_id=run.id,
                                title="Run 수명 Frida JSONL transcript",
                                evidence_type="frida_session",
                                file_path=transcript_path,
                                mime_type="application/x-ndjson",
                                description=(
                                    "앱 조작과 프록시 캡처가 끝날 때까지 append 방식으로 "
                                    "보존한 제한형 Frida 원문 transcript입니다."
                                ),
                                command=stop_result.command,
                                inline_data={"health": final_health},
                            )
                            await self._emit_evidence(run.id, transcript)
                        if stop_result.status != CapabilityStatus.AVAILABLE:
                            record_check(
                                "frida_session",
                                False,
                                stop_result.message,
                            )

                await self._stage(db, run, "ai_analysis", 84, "증적 후보를 분류합니다.")
                evidence_rows = db.scalars(
                    select(Evidence).where(Evidence.run_id == run.id)
                ).all()
                ai_evidence_rows = [
                    item
                    for item in evidence_rows
                    if item.evidence_type
                    not in {
                        "approval_record",
                        "control_scope_enforcement",
                        "approved_ui_action_scope",
                        "approved_network_replay_scope",
                        "assessment_attestation",
                        "manual_assessment_attachment",
                        "assessment_ledger",
                        "assessment_ledger_amendment",
                        "vulnerability_assessment",
                    }
                ]
                evidence_ids = [item.id for item in ai_evidence_rows]
                evidence_catalog = [
                    {
                        "id": item.id,
                        "type": item.evidence_type,
                        "title": item.title,
                        "sequence": item.sequence,
                    }
                    for item in ai_evidence_rows
                ]
                assessment_controls = [
                    {
                        "control_id": item.mastg_id,
                        "title": item.title,
                        "criteria": item.criteria,
                        "finding_categories": item.finding_categories,
                        "evidence_requirements": item.evidence_requirements,
                        "risk": item.risk,
                    }
                    for item in db.scalars(
                        select(ControlTest)
                        .where(
                            ControlTest.run_id == run.id,
                            ControlTest.standard
                            == str(run.options.get("assessment_profile")),
                        )
                        .order_by(ControlTest.mastg_id)
                    ).all()
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
                    "assessment_profile": run.options.get("assessment_profile"),
                    "assessment_controls": assessment_controls,
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
                finding_policy_decisions: list[dict[str, Any]] = []
                ai_assessment_recommendations: list[dict[str, Any]] = []
                if ai_result and ai_result.analysis:
                    valid_control_ids = {
                        str(item["control_id"])
                        for item in assessment_controls
                    }
                    valid_evidence = {
                        item.id: item
                        for item in db.scalars(
                            select(Evidence).where(Evidence.run_id == run.id)
                        ).all()
                    }
                    for analysis in ai_result.analysis.findings:
                        proposed_ids = list(dict.fromkeys(
                            evidence_id
                            for evidence_id in analysis.evidence_ids
                            if evidence_id in valid_evidence
                        ))
                        requested_verdict = analysis.verdict.value
                        policy_decision = self.evidence_policy.decide_finding(
                            category=analysis.category,
                            requested_verdict=requested_verdict,
                            confidence=analysis.confidence,
                            proposed_ids=proposed_ids,
                            evidence_by_id=valid_evidence,
                            minimum_quality=self.settings.ai_min_quality,
                        )
                        linked_ids = policy_decision.selected_ids
                        verdict = policy_decision.effective_verdict
                        is_candidate = (
                            verdict == "candidate"
                            or analysis.confidence < self.settings.ai_min_quality
                            or not linked_ids
                        )
                        missing_checks = [
                            "confirmed 증적 필요: " + " 또는 ".join(group)
                            for group in policy_decision.missing_requirements
                        ]
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
                            rationale=(
                                f"{analysis.rationale}\n\nEvidence policy: "
                                f"{policy_decision.explanation}"
                            ),
                            reproduction=analysis.reproduction,
                            false_positive_risk=analysis.false_positive_risk,
                            additional_checks=list(
                                dict.fromkeys(
                                    analysis.additional_checks + missing_checks
                                )
                            ),
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
                                source_rule_id="ai.evidence_policy_v2",
                                fingerprint=fingerprint,
                                evidence_ids=linked_ids,
                            )
                        )
                        created_findings.append(finding)
                        mapped_control_ids = [
                            item
                            for item in dict.fromkeys(analysis.control_ids)
                            if item in valid_control_ids
                        ]
                        if mapped_control_ids:
                            ai_assessment_recommendations.append(
                                {
                                    "finding_id": finding.id,
                                    "control_ids": mapped_control_ids,
                                    "provider": ai_result.provider,
                                    "model": ai_result.model,
                                    "confidence": analysis.confidence,
                                    "effective_verdict": verdict,
                                    "evidence_ids": linked_ids,
                                }
                            )
                        finding_policy_decisions.append(
                            {
                                "finding_id": finding.id,
                                "category": analysis.category,
                                "requested_verdict": requested_verdict,
                                "effective_verdict": verdict,
                                "proposed_evidence_ids": proposed_ids,
                                "selected_evidence_ids": linked_ids,
                                "control_ids": mapped_control_ids,
                                "missing_requirements": (
                                    policy_decision.missing_requirements
                                ),
                                "explanation": policy_decision.explanation,
                            }
                        )
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
                    policy_evidence = self.evidence.add_json(
                        db,
                        run_id=run.id,
                        filename="finding-evidence-policy.json",
                        title="Finding 증적 선택 정책",
                        evidence_type="evidence_policy",
                        data={
                            "decisions": finding_policy_decisions,
                            "synthetic": run.synthetic,
                        },
                        description="모든 Run 증적이 아니라 Finding 유형별 관련 증적만 선택했습니다.",
                    )
                    await self._emit_evidence(run.id, policy_evidence)

                if attempts:
                    options = dict(run.options)
                    options["ai_assessment_recommendations"] = (
                        ai_assessment_recommendations
                    )
                    run.options = options
                    db.commit()

                if app:
                    assessment_summary = evaluate_standard_controls(db, run, app)
                    options = dict(run.options)
                    options["assessment_summary"] = {
                        key: value
                        for key, value in assessment_summary.items()
                        if key != "controls"
                    }
                    if assessment_summary["confirmed"]:
                        vulnerability_evidence = self.evidence.add_json(
                            db,
                            run_id=run.id,
                            filename="confirmed-vulnerabilities.json",
                            title="국내 기준 취약점 확정 증적 원장",
                            evidence_type="vulnerability_assessment",
                            data={
                                "profile": assessment_summary["profile"],
                                "confirmed": assessment_summary["confirmed"],
                                "controls": [
                                    item
                                    for item in assessment_summary["controls"]
                                    if item["result"] == "confirmed"
                                ],
                            },
                            description="취약 판정이 확정된 항목과 연결 원본 증적만 기록했습니다.",
                        )
                        await self._emit_evidence(run.id, vulnerability_evidence)
                        options["assessment_summary"][
                            "vulnerability_evidence_id"
                        ] = vulnerability_evidence.id
                    run.options = options
                    if (
                        run.run_mode == RunMode.LIVE.value
                        and assessment_summary["unresolved"]
                    ):
                        quality_gaps.append(
                            {
                                "stage": "domestic_assessment",
                                "message": (
                                    f"{assessment_summary['profile']} 기준 "
                                    f"{assessment_summary['unresolved']}개 항목의 "
                                    "점검이 완료되지 않았습니다."
                                ),
                            }
                        )
                    db.commit()

                await self._stage(
                    db, run, "finalize", 96, "증적 인덱스를 검증하고 캡처를 종료합니다."
                )
                unique_gaps = list(
                    {
                        (item["stage"], item["message"]): item
                        for item in quality_gaps
                    }.values()
                )
                options = dict(run.options)
                options["completion_checks"] = quality_checks
                options["quality_gaps"] = unique_gaps
                options["failed_required_stages"] = [
                    item["stage"] for item in unique_gaps
                ]
                run.options = options
                final_status = (
                    RunStatus.COMPLETED_WITH_GAPS
                    if unique_gaps
                    else RunStatus.COMPLETED
                )
                run.status = final_status.value
                run.current_stage = final_status.value
                run.progress = 100
                run.finished_at = datetime.now(timezone.utc)
                db.commit()
                await self.events.publish(
                    run.id,
                    "run_status",
                    {
                        "status": final_status.value,
                        "progress": 100,
                        "message": (
                            f"파이프라인은 종료됐지만 필수 범위 {len(unique_gaps)}개가 부족합니다."
                            if unique_gaps
                            else "필수 실행·증적 조건을 충족해 진단을 완료했습니다."
                        ),
                        "finding_ids": [item.id for item in created_findings],
                        "quality_gaps": unique_gaps,
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
        except DiagnosticManualRequired as exc:
            with SessionLocal() as db:
                run = db.get(DiagnosticRun, run_id)
                if run:
                    options = dict(run.options)
                    options["completion_checks"] = quality_checks
                    options["quality_gaps"] = quality_gaps
                    options["failed_required_stages"] = [
                        item["stage"] for item in quality_gaps
                    ]
                    run.options = options
                    run.status = RunStatus.MANUAL_REQUIRED.value
                    run.current_stage = RunStatus.MANUAL_REQUIRED.value
                    run.error = str(exc)
                    run.finished_at = datetime.now(timezone.utc)
                    db.commit()
            await self.events.publish(
                run_id,
                "run_status",
                {"status": RunStatus.MANUAL_REQUIRED.value, "message": str(exc)},
            )
        except Exception as exc:
            with SessionLocal() as db:
                run = db.get(DiagnosticRun, run_id)
                if run:
                    options = dict(run.options)
                    options["completion_checks"] = quality_checks
                    options["quality_gaps"] = quality_gaps
                    options["failed_required_stages"] = [
                        item["stage"] for item in quality_gaps
                    ]
                    run.options = options
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
            if frida_session_started or self.frida_sessions.is_active(run_id):
                try:
                    await asyncio.shield(self.frida_sessions.stop(run_id))
                except Exception:
                    pass
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
                if run_id not in self._manual_tasks:
                    self._manual_active.discard(run_id)
            self._pause_events.pop(run_id, None)
            self._proxy_adapters.pop(run_id, None)
            self._ui_drivers.pop(run_id, None)
            self._tasks.pop(run_id, None)
