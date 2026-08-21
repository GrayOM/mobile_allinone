import { FormEvent, useEffect, useMemo, useState } from "react";
import { api, downloadAuthenticatedFile, post } from "../api";
import { EmptyState, SectionHeading, StatusChip, formatBytes, formatDate } from "../components/UI";
import type { CaptureJob, Device, Project } from "../types";

const activeStatuses = new Set(["queued", "running", "stop_requested"]);

export default function CapturesPage() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [projectId, setProjectId] = useState(() => localStorage.getItem("msw.project") ?? "");
  const [devices, setDevices] = useState<Device[]>([]);
  const [deviceId, setDeviceId] = useState("");
  const [kind, setKind] = useState<CaptureJob["kind"]>("device_logs");
  const [duration, setDuration] = useState(300);
  const [runId, setRunId] = useState("");
  const [jobs, setJobs] = useState<CaptureJob[]>([]);
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");

  const project = useMemo(() => projects.find((item) => item.id === projectId) ?? null, [projects, projectId]);
  const eligibleDevices = useMemo(() => devices.filter((device) => {
    if (device.availability !== "available") return false;
    if (project?.run_mode === "mock" && device.adapter !== "mock") return false;
    if (project?.run_mode === "live" && device.adapter === "mock") return false;
    return device.capabilities.includes(kind === "device_logs" ? "logs" : "screen_record");
  }), [devices, kind, project]);
  const selectedDevice = eligibleDevices.find((item) => item.id === deviceId) ?? null;

  function loadJobs(selectedProject: string) {
    void api<CaptureJob[]>(`/capture-jobs?project_id=${encodeURIComponent(selectedProject)}`)
      .then(setJobs)
      .catch((reason: Error) => setError(reason.message));
  }

  useEffect(() => {
    void Promise.all([
      api<Project[]>("/projects"),
      api<{ devices: Device[] }>("/devices"),
    ]).then(([projectRows, deviceRows]) => {
      setProjects(projectRows);
      setDevices(deviceRows.devices);
      const selected = projectRows.some((item) => item.id === projectId) ? projectId : projectRows[0]?.id ?? "";
      setProjectId(selected);
      if (selected) localStorage.setItem("msw.project", selected);
    }).catch((reason: Error) => setError(reason.message));
  }, []);

  useEffect(() => {
    setDeviceId(eligibleDevices.some((item) => item.id === deviceId) ? deviceId : eligibleDevices[0]?.id ?? "");
  }, [eligibleDevices]);

  useEffect(() => {
    if (!projectId) return;
    loadJobs(projectId);
    const timer = window.setInterval(() => loadJobs(projectId), 2_000);
    return () => window.clearInterval(timer);
  }, [projectId]);

  async function start(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!project || !selectedDevice) return;
    setBusy("start");
    setError("");
    setMessage("");
    try {
      const created = await post<CaptureJob>("/capture-jobs", {
        project_id: project.id,
        run_id: runId.trim() || null,
        device_id: selectedDevice.id,
        device_adapter: selectedDevice.adapter,
        kind,
        max_duration_seconds: duration,
      });
      setJobs((items) => [created, ...items]);
      setMessage("백그라운드 캡처를 시작했습니다. 이 화면을 닫아도 서버 Job은 계속 실행됩니다.");
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "장시간 캡처 시작 실패");
    } finally {
      setBusy("");
    }
  }

  async function stop(job: CaptureJob) {
    setBusy(job.id);
    try {
      const updated = await post<CaptureJob>(`/capture-jobs/${job.id}/stop`);
      setJobs((items) => items.map((item) => item.id === updated.id ? updated : item));
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "캡처 중지 실패");
    } finally {
      setBusy("");
    }
  }

  return (
    <div className="stack stack--lg captures-page">
      <SectionHeading eyebrow="BACKGROUND CAPTURE OPERATIONS" title="로그와 화면을 장시간 수집합니다" description="단말 작업을 백그라운드 Job으로 분리합니다. Android 화면 녹화는 플랫폼 제한에 맞춰 세그먼트 ZIP으로 보존하고, 서버 재시작·중지 상태를 원장에 남깁니다." />
      {message && <div className="inline-alert inline-alert--ok">{message}</div>}
      {error && <div className="inline-alert">{error}</div>}

      <section className="panel capture-command">
        <form onSubmit={start}>
          <div className="field"><label htmlFor="capture-project">프로젝트</label><select id="capture-project" value={projectId} onChange={(event) => { setProjectId(event.target.value); localStorage.setItem("msw.project", event.target.value); }}><option value="">선택</option>{projects.map((item) => <option key={item.id} value={item.id}>{item.name} · {item.run_mode}</option>)}</select></div>
          <div className="field"><label htmlFor="capture-device">단말</label><select id="capture-device" value={deviceId} onChange={(event) => setDeviceId(event.target.value)}><option value="">사용 가능한 단말 없음</option>{eligibleDevices.map((item) => <option key={`${item.adapter}:${item.id}`} value={item.id}>{item.model} · {item.id}</option>)}</select></div>
          <div className="field"><label htmlFor="capture-kind">수집 종류</label><select id="capture-kind" value={kind} onChange={(event) => setKind(event.target.value as CaptureJob["kind"])}><option value="device_logs">단말 로그</option><option value="screen_record">화면 녹화</option></select></div>
          <div className="field"><label htmlFor="capture-duration">최대 시간</label><select id="capture-duration" value={duration} onChange={(event) => setDuration(Number(event.target.value))}><option value={60}>1분</option><option value={300}>5분</option><option value={900}>15분</option><option value={1800}>30분</option><option value={3600}>60분</option></select></div>
          <div className="field"><label htmlFor="capture-run">Run ID (선택)</label><input id="capture-run" value={runId} onChange={(event) => setRunId(event.target.value)} placeholder="iOS SSH 프로필은 Run 연결 권장" /></div>
          <button className="button button--signal" disabled={!project || !selectedDevice || busy === "start"}>{busy === "start" ? "시작 중…" : "백그라운드 수집 시작"}</button>
        </form>
        <div className="capture-command__boundary"><span>RAW BOUNDARY</span><strong>{project?.raw_access_enabled ? "DOWNLOAD ENABLED" : "DOWNLOAD LOCKED"}</strong><small>원본 내려받기는 프로젝트의 Raw 열람 정책을 따릅니다.</small></div>
      </section>

      <section className="capture-stream">
        <div className="capture-stream__head"><div><span className="eyebrow">CAPTURE JOB REGISTER</span><h2>수집 실행 원장</h2></div><small>{jobs.filter((item) => activeStatuses.has(item.status)).length} active / {jobs.length} total</small></div>
        {jobs.length ? jobs.map((job) => (
          <article className={`capture-row ${activeStatuses.has(job.status) ? "capture-row--active" : ""}`} key={job.id}>
            <div className="capture-row__trace"><span /><span /><span /></div>
            <div className="capture-row__identity"><strong>{job.kind === "device_logs" ? "DEVICE LOG STREAM" : "SCREEN RECORD SEGMENTS"}</strong><code>{job.id}</code><small>{job.device_id} · {job.device_adapter}</small></div>
            <div><span>STATUS</span><StatusChip value={job.status} /><small>{job.error ?? `${job.max_duration_seconds}s ceiling`}</small></div>
            <div><span>OUTPUT</span><strong>{formatBytes(job.size_bytes)}</strong><small>{job.sha256 ? `sha256 ${job.sha256.slice(0, 12)}…` : "finalizing"}</small></div>
            <div><span>STARTED</span><strong>{formatDate(job.started_at ?? job.created_at)}</strong><small>{job.started_by}{job.synthetic ? " · SYNTHETIC" : ""}</small></div>
            <div className="capture-row__actions">
              {activeStatuses.has(job.status) && <button className="button button--small button--danger" disabled={busy === job.id} onClick={() => void stop(job)}>중지</button>}
              {job.download_available && <button className="button button--small button--primary" onClick={() => void downloadAuthenticatedFile(`/capture-jobs/${job.id}/download`, `msw-${job.kind}-${job.id}.${job.kind === "device_logs" ? "txt" : "zip"}`).catch((reason: Error) => setError(reason.message))}>원본 받기</button>}
            </div>
          </article>
        )) : <EmptyState title="장시간 캡처 없음" description="프로젝트와 단말을 선택해 로그 또는 화면 녹화 Job을 시작하세요." />}
      </section>
    </div>
  );
}
