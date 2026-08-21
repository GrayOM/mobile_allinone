from __future__ import annotations

import asyncio
import hashlib
import shutil
import time
import zipfile
from pathlib import Path

from sqlalchemy import select

from backend.app.core.config import AppSettings
from backend.app.core.status import CapabilityStatus, Platform
from backend.app.database.base import utcnow
from backend.app.database.models import CaptureJob
from backend.app.database.session import SessionLocal
from backend.app.devices import AndroidDeviceAdapter, IOSDeviceAdapter, MockDeviceAdapter


ACTIVE_CAPTURE_STATUSES = {"queued", "running", "stop_requested"}


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


class CaptureJobManager:
    def __init__(self, settings: AppSettings):
        self.settings = settings
        self._tasks: dict[str, asyncio.Task[None]] = {}
        self._stop_events: dict[str, asyncio.Event] = {}
        self._lock = asyncio.Lock()

    def recover_interrupted(self) -> None:
        with SessionLocal() as db:
            jobs = db.scalars(
                select(CaptureJob).where(CaptureJob.status.in_(ACTIVE_CAPTURE_STATUSES))
            ).all()
            for job in jobs:
                job.status = "interrupted"
                job.error = "서버 재시작으로 이전 장시간 캡처를 중단 상태로 복구했습니다."
                job.finished_at = utcnow()
            db.commit()

    def adapter(self, adapter_name: str, device_id: str):
        if adapter_name == "mock":
            return MockDeviceAdapter(
                Platform.MOCK_IOS if "ios" in device_id.lower() else Platform.MOCK_ANDROID
            )
        if adapter_name == "android_adb":
            return AndroidDeviceAdapter(self.settings)
        if adapter_name == "ios_windows":
            return IOSDeviceAdapter(self.settings)
        raise ValueError("지원하지 않는 단말 Adapter입니다.")

    async def start(
        self,
        *,
        project_id: str,
        run_id: str | None,
        device_id: str,
        device_adapter: str,
        kind: str,
        max_duration_seconds: int,
        started_by: str,
        synthetic: bool,
        adapter=None,
    ) -> CaptureJob:
        if kind not in {"device_logs", "screen_record"}:
            raise ValueError("캡처 종류는 device_logs 또는 screen_record여야 합니다.")
        if not 10 <= max_duration_seconds <= 3_600:
            raise ValueError("장시간 캡처는 10~3,600초 범위여야 합니다.")
        selected = adapter or self.adapter(device_adapter, device_id)
        devices = await selected.discover()
        device = next((item for item in devices if item.id == device_id), None)
        if not device or device.availability != CapabilityStatus.AVAILABLE:
            raise LookupError("현재 사용 가능한 대상 단말을 다시 확인할 수 없습니다.")
        capability = "logs" if kind == "device_logs" else "screen_record"
        if capability not in device.capabilities:
            raise RuntimeError("대상 단말 Adapter가 선택한 장시간 캡처를 지원하지 않습니다.")

        async with self._lock:
            with SessionLocal() as db:
                duplicate = db.scalar(
                    select(CaptureJob.id).where(
                        CaptureJob.device_id == device_id,
                        CaptureJob.kind == kind,
                        CaptureJob.status.in_(ACTIVE_CAPTURE_STATUSES),
                    )
                )
                if duplicate:
                    raise FileExistsError("같은 단말과 종류의 장시간 캡처가 이미 실행 중입니다.")
                job = CaptureJob(
                    project_id=project_id,
                    run_id=run_id,
                    device_id=device_id,
                    device_adapter=device_adapter,
                    kind=kind,
                    status="queued",
                    max_duration_seconds=max_duration_seconds,
                    started_by=started_by[:64],
                    synthetic=synthetic,
                )
                db.add(job)
                db.commit()
                db.refresh(job)
                job_id = job.id
            stop_event = asyncio.Event()
            self._stop_events[job_id] = stop_event
            self._tasks[job_id] = asyncio.create_task(
                self._run(job_id, selected, stop_event),
                name=f"capture-{job_id}",
            )
        with SessionLocal() as db:
            result = db.get(CaptureJob, job_id)
            db.expunge(result)
            return result

    async def stop(self, job_id: str) -> CaptureJob:
        async with self._lock:
            with SessionLocal() as db:
                job = db.get(CaptureJob, job_id)
                if not job:
                    raise LookupError("캡처 Job을 찾을 수 없습니다.")
                if job.status not in ACTIVE_CAPTURE_STATUSES:
                    db.expunge(job)
                    return job
                job.status = "stop_requested"
                db.commit()
            event = self._stop_events.get(job_id)
            if event:
                event.set()
        with SessionLocal() as db:
            result = db.get(CaptureJob, job_id)
            db.expunge(result)
            return result

    async def shutdown(self) -> None:
        events = list(self._stop_events.values())
        tasks = list(self._tasks.values())
        for event in events:
            event.set()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _run(self, job_id: str, adapter, stop_event: asyncio.Event) -> None:
        capture_root = self.settings.captures_dir / job_id
        capture_root.mkdir(parents=True, exist_ok=True)
        with SessionLocal() as db:
            job = db.get(CaptureJob, job_id)
            if not job:
                return
            job.status = "running"
            job.started_at = utcnow()
            db.commit()
            kind = job.kind
            device_id = job.device_id
            duration = job.max_duration_seconds
        started = time.monotonic()
        segments: list[Path] = []
        manual_message: str | None = None
        try:
            while time.monotonic() - started < duration and not stop_event.is_set():
                remaining = max(1, int(duration - (time.monotonic() - started)))
                segment_duration = min(15, remaining)
                index = len(segments) + 1
                destination = capture_root / (
                    f"segment-{index:04d}.log"
                    if kind == "device_logs"
                    else f"segment-{index:04d}.mp4"
                )
                segment_started = time.monotonic()
                if kind == "device_logs":
                    operation = await adapter.collect_logs(
                        device_id, destination, duration_seconds=segment_duration
                    )
                else:
                    operation = await adapter.start_screen_recording(
                        device_id, destination, duration_seconds=segment_duration
                    )
                if operation.status == CapabilityStatus.MANUAL_REQUIRED:
                    manual_message = operation.message
                    break
                if operation.status != CapabilityStatus.AVAILABLE or not destination.is_file():
                    raise RuntimeError(operation.message or "캡처 세그먼트를 생성하지 못했습니다.")
                segment_size = destination.stat().st_size
                if segment_size > self.settings.capture_segment_max_bytes:
                    destination.unlink(missing_ok=True)
                    raise RuntimeError("캡처 세그먼트가 설정된 개별 크기 제한을 초과했습니다.")
                if sum(item.stat().st_size for item in segments) + segment_size > self.settings.capture_total_max_bytes:
                    destination.unlink(missing_ok=True)
                    raise RuntimeError("장시간 캡처가 설정된 전체 크기 제한을 초과했습니다.")
                segments.append(destination)
                elapsed = time.monotonic() - segment_started
                wait_seconds = min(max(0.0, segment_duration - elapsed), max(0.0, duration - (time.monotonic() - started)))
                if wait_seconds:
                    try:
                        await asyncio.wait_for(stop_event.wait(), timeout=wait_seconds)
                    except asyncio.TimeoutError:
                        pass

            output: Path | None = None
            mime_type: str | None = None
            if segments and kind == "device_logs":
                output = capture_root / "device-logs.txt"
                with output.open("wb") as stream:
                    for index, segment in enumerate(segments, start=1):
                        stream.write(f"\n===== CAPTURE SEGMENT {index:04d} =====\n".encode("utf-8"))
                        with segment.open("rb") as source:
                            shutil.copyfileobj(source, stream, length=1024 * 1024)
                mime_type = "text/plain; charset=utf-8"
            elif segments:
                output = capture_root / "screen-record-segments.zip"

                def build_zip() -> None:
                    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
                        for segment in segments:
                            archive.write(segment, arcname=segment.name)

                await asyncio.to_thread(build_zip)
                mime_type = "application/zip"

            with SessionLocal() as db:
                job = db.get(CaptureJob, job_id)
                if not job:
                    return
                if manual_message:
                    job.status = "manual_required"
                    job.error = manual_message
                elif output is None:
                    job.status = "stopped" if stop_event.is_set() else "failed"
                    job.error = "저장된 캡처 세그먼트가 없습니다."
                else:
                    job.status = "stopped" if stop_event.is_set() else "completed"
                    job.output_path = str(output)
                    job.mime_type = mime_type
                    job.size_bytes = output.stat().st_size
                    job.sha256 = await asyncio.to_thread(_file_sha256, output)
                job.finished_at = utcnow()
                db.commit()
        except asyncio.CancelledError:
            with SessionLocal() as db:
                job = db.get(CaptureJob, job_id)
                if job:
                    job.status = "interrupted"
                    job.error = "서버 종료로 캡처 Task가 취소되었습니다."
                    job.finished_at = utcnow()
                    db.commit()
            raise
        except Exception as exc:
            with SessionLocal() as db:
                job = db.get(CaptureJob, job_id)
                if job:
                    job.status = "failed"
                    job.error = f"{type(exc).__name__}: {exc}"
                    job.finished_at = utcnow()
                    db.commit()
        finally:
            async with self._lock:
                self._tasks.pop(job_id, None)
                self._stop_events.pop(job_id, None)
