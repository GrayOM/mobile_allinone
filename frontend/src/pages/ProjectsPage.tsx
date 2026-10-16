import { FormEvent, useEffect, useMemo, useState } from "react";
import { api, post, remove, upload } from "../api";
import type {
  AnalysisOverview,
  AppArtifact,
  Device,
  Project,
  SecuritySolutionAnalysis,
} from "../types";
import { AssessmentScopePanel } from "../components/AssessmentScopePanel";
import { IpaResignPanel } from "../components/IpaResignPanel";
import {
  EmptyState,
  SectionHeading,
  StatusChip,
  formatBytes,
  formatDate,
} from "../components/UI";

const PROFILE_LABELS: Record<Project["assessment_profile"], string> = {
  critical_infrastructure: "주요정보통신기반시설",
  electronic_financial: "전자금융기반시설",
  free_assessment: "전체 진단 (ALL)",
};

export default function ProjectsPage() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [selected, setSelected] = useState<string>(
    () => localStorage.getItem("msw.project") ?? "",
  );
  const [apps, setApps] = useState<AppArtifact[]>([]);
  const [creating, setCreating] = useState(false);
  const [showCreate, setShowCreate] = useState(false);
  const [uploading, setUploading] = useState(0);
  const [selectedApp, setSelectedApp] = useState<AppArtifact | null>(null);
  const [overview, setOverview] = useState<AnalysisOverview | null>(null);
  const [reanalyzing, setReanalyzing] = useState(false);
  const [registerInstalledOpen, setRegisterInstalledOpen] = useState(false);
  const [registerDevices, setRegisterDevices] = useState<Device[]>([]);
  const [registerDeviceId, setRegisterDeviceId] = useState("");
  const [installedPackages, setInstalledPackages] = useState<string[]>([]);
  const [installedPackage, setInstalledPackage] = useState("");
  const [registeringInstalled, setRegisteringInstalled] = useState(false);
  const [error, setError] = useState("");

  const project = useMemo(
    () => projects.find((item) => item.id === selected),
    [projects, selected],
  );

  function loadProjects() {
    api<Project[]>("/projects")
      .then((items) => {
        setProjects(items);
        if (!selected && items[0]) selectProject(items[0].id);
      })
      .catch((reason: Error) => setError(reason.message));
  }

  function loadApps(projectId: string) {
    api<AppArtifact[]>(`/projects/${projectId}/apps`)
      .then((items) => {
        setApps(items);
        if (items[0]) setSelectedApp(items[0]);
      })
      .catch((reason: Error) => setError(reason.message));
  }

  function selectProject(projectId: string) {
    setSelected(projectId);
    localStorage.setItem("msw.project", projectId);
  }

  useEffect(loadProjects, []);
  useEffect(() => {
    if (selected) loadApps(selected);
    else setApps([]);
  }, [selected]);
  useEffect(() => {
    if (!selectedApp) {
      setOverview(null);
      return;
    }
    void api<AnalysisOverview>(`/apps/${selectedApp.id}/analysis/overview`)
      .then(setOverview)
      .catch((reason: Error) => setError(reason.message));
  }, [selectedApp]);

  async function createProject(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    setCreating(true);
    setError("");
    try {
      const created = await post<Project>("/projects", {
        name: data.get("name"),
        description: data.get("description"),
        ai_enabled: data.get("ai_enabled") === "on",
        external_ai_allowed: data.get("external_ai_allowed") === "on",
        external_analyzer_allowed: data.get("external_analyzer_allowed") === "on",
        run_mode: data.get("run_mode"),
        assessment_profile: data.get("assessment_profile"),
      });
      setProjects((items) => [created, ...items]);
      selectProject(created.id);
      setShowCreate(false);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "프로젝트 생성 실패");
    } finally {
      setCreating(false);
    }
  }

  async function uploadFile(file?: File) {
    if (!file || !selected) return;
    setError("");
    try {
      const result = await upload<AppArtifact>(
        `/projects/${selected}/apps/upload`,
        file,
        setUploading,
      );
      setApps((items) => [result, ...items]);
      setSelectedApp(result);
      localStorage.setItem("msw.app", result.id);
      setUploading(0);
    } catch (reason) {
      setUploading(0);
      setError(reason instanceof Error ? reason.message : "업로드 실패");
    }
  }

  async function openInstalledRegistry() {
    setRegisterInstalledOpen(true);
    setInstalledPackages([]);
    setInstalledPackage("");
    setError("");
    try {
      const result = await api<{ devices: Device[] }>("/devices");
      const available = result.devices.filter(
        (item) => item.adapter !== "mock" && item.availability === "available",
      );
      setRegisterDevices(available);
      setRegisterDeviceId(available[0]?.id ?? "");
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "단말 목록을 불러오지 못했습니다.");
    }
  }

  async function loadInstalledPackages() {
    const device = registerDevices.find((item) => item.id === registerDeviceId);
    if (!device) return;
    setRegisteringInstalled(true);
    setError("");
    try {
      const result = await post<{ data?: { packages?: string[] } }>("/devices/action", {
        adapter: device.adapter,
        device_id: device.id,
        action: "list_packages",
      });
      const packages = [...(result.data?.packages ?? [])].sort();
      setInstalledPackages(packages);
      setInstalledPackage(packages[0] ?? "");
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "설치 앱 목록을 읽지 못했습니다.");
    } finally {
      setRegisteringInstalled(false);
    }
  }

  async function registerInstalledApp() {
    const device = registerDevices.find((item) => item.id === registerDeviceId);
    if (!project || !device || !installedPackage) return;
    setRegisteringInstalled(true);
    setError("");
    try {
      const created = await post<AppArtifact>(
        `/projects/${project.id}/apps/register-installed`,
        {
          device_adapter: device.adapter,
          device_id: device.id,
          package_name: installedPackage,
        },
      );
      setApps((items) => [created, ...items]);
      setSelectedApp(created);
      localStorage.setItem("msw.app", created.id);
      setRegisterInstalledOpen(false);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "설치 앱 등록에 실패했습니다.");
    } finally {
      setRegisteringInstalled(false);
    }
  }

  async function refreshSelectedApp(appId: string) {
    try {
      const items = await api<AppArtifact[]>(`/projects/${selected}/apps`);
      setApps(items);
      setSelectedApp(items.find((item) => item.id === appId) ?? null);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "앱 정보를 새로 고치지 못했습니다.");
    }
  }

  async function deleteCurrentProject() {
    if (!project) return;
    const approved = window.confirm(
      `"${project.name}" 프로젝트와 업로드·분석·증적 원본을 모두 삭제할까요? 이 작업은 복구할 수 없습니다.`,
    );
    if (!approved) return;
    setError("");
    try {
      await remove(`/projects/${project.id}`);
      const remaining = projects.filter((item) => item.id !== project.id);
      setProjects(remaining);
      setApps([]);
      setSelectedApp(null);
      selectProject(remaining[0]?.id ?? "");
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "프로젝트 삭제 실패");
    }
  }

  async function reanalyzeCurrentApp(includeMobSF = false) {
    if (!selectedApp || !project) return;
    if (includeMobSF) {
      if (!project.external_analyzer_allowed || !project.external_analyzer_destination) {
        setError("프로젝트의 MobSF 목적지 승인이 필요합니다.");
        return;
      }
      const approved = window.confirm(
        `다음 앱 원본을 MobSF로 전송할까요?\n\n목적지: ${project.external_analyzer_destination}\nAPK/IPA SHA-256: ${selectedApp.sha256}\n\n현재 목적지·DNS·TLS 인증서와 해시가 모두 일치할 때만 전송됩니다.`,
      );
      if (!approved) return;
    }
    setReanalyzing(true);
    setError("");
    try {
      const refreshed = await post<AppArtifact>(
        `/apps/${selectedApp.id}/reanalyze`,
        includeMobSF ? {
          confirm_external_analyzer: true,
          expected_destination: project.external_analyzer_destination,
          expected_sha256: selectedApp.sha256,
        } : {},
      );
      const refreshedOverview = await api<AnalysisOverview>(
        `/apps/${selectedApp.id}/analysis/overview`,
      );
      setSelectedApp(refreshed);
      setApps((items) =>
        items.map((item) => item.id === refreshed.id ? refreshed : item),
      );
      setOverview(refreshedOverview);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "재분석 실패");
    } finally {
      setReanalyzing(false);
    }
  }

  return (
    <div className="stack stack--lg">
      <SectionHeading
        eyebrow="PROJECT REGISTRY"
        title="진단 대상을 한곳에 정리합니다"
        description="프로젝트별 AI 전송 정책과 앱 분석 이력을 분리해 관리합니다."
        action={
          <button className="button button--primary" onClick={() => setShowCreate(true)}>
            프로젝트 만들기
          </button>
        }
      />
      {error && <div className="inline-alert">{error}</div>}

      {showCreate && (
        <section className="panel panel--accent">
          <form className="form-grid" onSubmit={createProject}>
            <div className="field field--wide">
              <label htmlFor="project-name">프로젝트 이름</label>
              <input id="project-name" name="name" required placeholder="예: Android 결제앱 7월 진단" />
            </div>
            <div className="field field--wide">
              <label htmlFor="project-description">설명</label>
              <textarea id="project-description" name="description" rows={2} placeholder="진단 범위와 권한 정보를 기록하세요." />
            </div>
            <fieldset className="assessment-profile-picker field--wide">
              <legend>국내 취약점 진단 기준</legend>
              <label>
                <input type="radio" name="assessment_profile" value="critical_infrastructure" defaultChecked />
                <span><strong>1 · 주요정보통신기반시설</strong><small>모바일·웹/API 공통 27개 항목</small></span>
              </label>
              <label>
                <input type="radio" name="assessment_profile" value="electronic_financial" />
                <span><strong>2 · 전자금융기반시설</strong><small>거래·인증·모바일·TLS 56개 항목</small></span>
              </label>
              <label>
                <input type="radio" name="assessment_profile" value="free_assessment" />
                <span><strong>3 · 전체 진단 (ALL)</strong><small>고정 항목 없음 · 발견항목을 증적으로 확정해 보고</small></span>
              </label>
              <p>앱 등록 후에는 기준을 변경할 수 없습니다. Run은 선택한 항목만 판정 원장에 생성합니다.</p>
            </fieldset>
            <label className="check-card">
              <input type="checkbox" name="ai_enabled" defaultChecked />
              <span><strong>AI 진단 보조 사용</strong><small>증적 분류·국내 기준 매핑과 승인형 Frida 후보 분석에 사용합니다.</small></span>
            </label>
            <label className="check-card">
              <input type="checkbox" name="external_ai_allowed" />
              <span><strong>외부 AI 전송 허용</strong><small>선택한 최소 증적을 마스킹한 뒤 NVIDIA 우선·Claude 대체 순서로 전송합니다.</small></span>
            </label>
            <label className="check-card">
              <input type="checkbox" name="external_analyzer_allowed" />
              <span><strong>MobSF 앱 전송 허용</strong><small>허용된 MobSF 서버로 APK·IPA 원본을 전송하고 이력을 남깁니다.</small></span>
            </label>
            <div className="field">
              <label htmlFor="project-run-mode">실행 모드</label>
              <select id="project-run-mode" name="run_mode" defaultValue="live">
                <option value="live">Live · 실제 단말과 실제 결과</option>
                <option value="mock">Mock · 합성 데이터 데모</option>
              </select>
              <small>앱이나 진단 이력이 생기면 실행 모드는 변경할 수 없습니다.</small>
            </div>
            <div className="form-actions field--wide">
              <button type="button" className="button button--quiet" onClick={() => setShowCreate(false)}>취소</button>
              <button className="button button--primary" disabled={creating}>{creating ? "생성 중…" : "프로젝트 저장"}</button>
            </div>
          </form>
        </section>
      )}

      <div className="project-layout">
        <aside className="project-index panel">
          <div className="panel-label">프로젝트 {projects.length}</div>
          {projects.length ? projects.map((item) => (
            <button
              key={item.id}
              className={`project-tab ${selected === item.id ? "project-tab--active" : ""}`}
              onClick={() => selectProject(item.id)}
            >
              <strong>{item.name}</strong>
              <small>{formatDate(item.updated_at)}</small>
              <span>{item.run_mode.toUpperCase()} · {item.assessment_profile === "electronic_financial" ? "EFI" : item.assessment_profile === "free_assessment" ? "ALL" : "CII"}</span>
            </button>
          )) : (
            <EmptyState title="프로젝트가 없습니다" description="첫 진단 범위를 만들어 시작하세요." />
          )}
        </aside>

        <section className="project-detail panel">
          {project ? (
            <>
              <div className="project-detail__head">
                <div>
                  <span className="eyebrow">ACTIVE PROJECT</span>
                  <h2>{project.name}</h2>
                  <p>{project.description || "프로젝트 설명이 없습니다."}</p>
                </div>
                <div className="chip-row">
                  <StatusChip value={project.run_mode === "mock" ? "manual_required" : "available"} label={project.run_mode === "mock" ? "Mock · 합성 데이터" : "Live · 실제 결과"} />
                  <StatusChip value="available" label={PROFILE_LABELS[project.assessment_profile]} />
                  <StatusChip value={project.external_ai_allowed ? "available" : "not_configured"} label={project.external_ai_allowed ? "외부 AI 허용" : "외부 AI 차단"} />
                  <StatusChip value={project.external_analyzer_allowed ? "available" : "not_configured"} label={project.external_analyzer_allowed ? "MobSF 전송 허용" : "MobSF 전송 차단"} />
                  <button className="button button--danger button--small" onClick={() => void deleteCurrentProject()}>프로젝트 삭제</button>
                </div>
                {project.external_analyzer_allowed && project.external_analyzer_destination && (
                  <div className="summary-block">
                    <span>승인된 MobSF 목적지</span>
                    <code>{project.external_analyzer_destination}</code>
                    <small>{project.external_analyzer_addresses.join(", ")} · TLS {project.external_analyzer_certificate_sha256?.slice(0, 16) ?? "HTTP"}…</small>
                  </div>
                )}
              </div>

              <label className={`drop-zone ${uploading ? "drop-zone--busy" : ""}`}>
                <input
                  type="file"
                  accept=".apk,.ipa"
                  onChange={(event) => void uploadFile(event.target.files?.[0])}
                  disabled={Boolean(uploading)}
                />
                <span className="drop-zone__icon">+</span>
                <strong>{uploading ? `업로드·분석 중 ${uploading}%` : "APK 또는 IPA 등록"}</strong>
                <small>파일 구조를 확인한 뒤 정적 분석을 바로 시작합니다. 최대 업로드 크기는 설정에서 확인하세요.</small>
                {uploading > 0 && <i style={{ width: `${uploading}%` }} />}
              </label>

              {project.run_mode === "live" && (
                <section className="installed-registry">
                  <div>
                    <span className="eyebrow">DEVICE APP REGISTRY</span>
                    <strong>이미 설치된 앱으로 진단</strong>
                    <small>Store·TestFlight·TrollStore 앱은 IPA 재설치 없이 Bundle ID를 Run 대상에 고정합니다.</small>
                  </div>
                  <button type="button" className="button button--quiet" onClick={() => void openInstalledRegistry()}>
                    단말 앱 선택
                  </button>
                </section>
              )}

              {registerInstalledOpen && (
                <section className="installed-registry__sheet">
                  <div className="form-grid">
                    <div className="field">
                      <label htmlFor="installed-device">연결 단말</label>
                      <select id="installed-device" value={registerDeviceId} onChange={(event) => {
                        setRegisterDeviceId(event.target.value);
                        setInstalledPackages([]);
                        setInstalledPackage("");
                      }}>
                        {registerDevices.map((device) => <option key={device.id} value={device.id}>{device.model} · {device.os_version}</option>)}
                      </select>
                    </div>
                    <div className="field installed-registry__load">
                      <button type="button" className="button button--primary" disabled={!registerDeviceId || registeringInstalled} onClick={() => void loadInstalledPackages()}>
                        {registeringInstalled ? "조회 중…" : "설치 앱 조회"}
                      </button>
                    </div>
                    <div className="field field--wide">
                      <label htmlFor="installed-package">대상 Bundle ID / Package</label>
                      <select id="installed-package" value={installedPackage} onChange={(event) => setInstalledPackage(event.target.value)} disabled={!installedPackages.length}>
                        {!installedPackages.length && <option value="">먼저 설치 앱을 조회하세요</option>}
                        {installedPackages.map((item) => <option key={item} value={item}>{item}</option>)}
                      </select>
                    </div>
                  </div>
                  <div className="form-actions">
                    <button type="button" className="button button--quiet" onClick={() => setRegisterInstalledOpen(false)}>취소</button>
                    <button type="button" className="button button--signal" disabled={!installedPackage || registeringInstalled} onClick={() => void registerInstalledApp()}>설치 앱 등록</button>
                  </div>
                </section>
              )}

              <div className="artifact-grid">
                <div className="artifact-list">
                  <div className="panel-label">등록 앱 {apps.length}</div>
                  {apps.map((app) => (
                    <button
                      key={app.id}
                      className={`artifact-row ${selectedApp?.id === app.id ? "artifact-row--active" : ""}`}
                      onClick={() => {
                        setSelectedApp(app);
                        localStorage.setItem("msw.app", app.id);
                      }}
                    >
                      <span className={`platform-mark platform-mark--${app.platform}`}>
                        {app.platform === "android" ? "A" : "i"}
                      </span>
                      <div>
                        <strong>{app.app_name || app.original_name}</strong>
                        <small>{app.package_name || "패키지 미확인"} · {app.analysis_result.source === "device_installed" ? "단말 설치본" : formatBytes(app.size_bytes)}</small>
                      </div>
                      <StatusChip value={app.analysis_status} />
                    </button>
                  ))}
                </div>
                <AnalysisSummary
                  app={selectedApp}
                  overview={overview}
                  reanalyzing={reanalyzing}
                  onReanalyze={() => void reanalyzeCurrentApp()}
                  onReanalyzeMobSF={
                    project.external_analyzer_allowed
                      ? () => void reanalyzeCurrentApp(true)
                      : undefined
                  }
                />
              </div>
              {selectedApp && selectedApp.platform.endsWith("ios") && (
                <IpaResignPanel
                  app={selectedApp}
                  mock={project.run_mode === "mock"}
                  onUpdated={() => void refreshSelectedApp(selectedApp.id)}
                />
              )}
              <AssessmentScopePanel project={project} />
            </>
          ) : (
            <EmptyState title="프로젝트를 선택하세요" description="왼쪽에서 프로젝트를 선택하거나 새로 만드세요." />
          )}
        </section>
      </div>
    </div>
  );
}

function AnalysisSummary({
  app,
  overview,
  reanalyzing,
  onReanalyze,
  onReanalyzeMobSF,
}: {
  app: AppArtifact | null;
  overview: AnalysisOverview | null;
  reanalyzing: boolean;
  onReanalyze: () => void;
  onReanalyzeMobSF?: () => void;
}) {
  if (!app) {
    return (
      <div className="analysis-summary">
        <EmptyState title="등록 앱이 없습니다" description="APK·IPA를 등록하면 Manifest와 코드 신호를 정리합니다." />
      </div>
    );
  }
  const permissions = app.analysis_result.permissions ?? [];
  const components = app.analysis_result.components ?? [];
  const candidates = app.analysis_result.candidates ?? [];
  const signals = app.analysis_result.signals ?? {};
  const manifest = (app.analysis_result.manifest ?? {}) as Record<string, unknown>;
  const structure = (app.analysis_result.structure ?? {}) as Record<string, unknown>;
  return (
    <div className="analysis-summary">
      <div className="analysis-summary__title">
        <div>
          <span className="eyebrow">STATIC SNAPSHOT</span>
          <h3>{app.app_name || app.original_name}</h3>
          <code>{app.package_name || "unknown package"}</code>
        </div>
        <div className="analysis-summary__actions">
          <strong>{app.version || "—"}</strong>
          <button
            className="button button--ghost-light button--small"
            onClick={onReanalyze}
            disabled={reanalyzing}
          >
            {reanalyzing ? "분석 중…" : "OSS 분석기 재실행"}
          </button>
          {onReanalyzeMobSF && (
            <button
              className="button button--signal button--small"
              onClick={onReanalyzeMobSF}
              disabled={reanalyzing}
            >
              MobSF 전송 확인 후 재실행
            </button>
          )}
        </div>
      </div>
      <div className="analysis-numbers">
        <div><strong>{permissions.length}</strong><span>권한</span></div>
        <div><strong>{components.length}</strong><span>컴포넌트</span></div>
        <div><strong>{candidates.length}</strong><span>문자열 후보</span></div>
        <div><strong>{Object.keys(signals).length}</strong><span>보안 신호</span></div>
      </div>
      <div className="summary-block">
        <span>SHA-256</span>
        <code>{app.sha256}</code>
      </div>
      <div className="analyzer-federation">
        <div className="analyzer-federation__head">
          <span>ANALYZER FEDERATION</span>
          <strong>{overview?.raw_findings.length ?? 0} raw signals</strong>
        </div>
        <div className="analyzer-rail">
          {overview?.tool_runs.map((tool) => (
            <div className="analyzer-node" key={tool.id}>
              <i className={`analyzer-node__signal analyzer-node__signal--${tool.status}`} />
              <div>
                <strong>{tool.tool_name}</strong>
                <small>
                  {tool.tool_version || "version n/a"} ·{" "}
                  {String(
                    tool.metadata.result_count
                    ?? tool.metadata.match_count
                    ?? tool.metadata.finding_count
                    ?? 0,
                  )} signals
                </small>
              </div>
              <StatusChip value={tool.status} />
            </div>
          ))}
          {!overview?.tool_runs.length && <small>분석 실행 이력을 읽는 중입니다.</small>}
        </div>
        <div className="analyzer-federation__foot">
          <span>국내 기준 {overview?.assessment_controls.length ?? 0} · MASTG {overview?.controls.length ?? 0}</span>
          <a href="/coverage">통제 원장 열기 →</a>
        </div>
      </div>
      <SecuritySolutionPanel analysis={overview?.security_solution_analysis ?? null} />
      <div className="summary-block">
        <span>상위 권한</span>
        <div className="tag-cloud">
          {permissions.slice(0, 7).map((item) => <span key={item}>{item.split(".").pop()}</span>)}
          {!permissions.length && <small>해석된 권한이 없습니다.</small>}
        </div>
      </div>
      <div className="manifest-snapshot">
        <div><span>Manifest</span><code>{JSON.stringify(manifest)}</code></div>
        <div><span>Structure</span><code>{JSON.stringify(structure)}</code></div>
      </div>
      {app.analysis_result.warnings?.map((warning) => (
        <div className="warning-line" key={warning}>{warning}</div>
      ))}
      <details className="raw-details raw-details--dark">
        <summary>전체 정적 분석 JSON 보기</summary>
        <pre className="code-view">{JSON.stringify(app.analysis_result, null, 2)}</pre>
      </details>
    </div>
  );
}

const CONTROL_AREA_LABELS: Record<string, string> = {
  tamper_detection: "변조 탐지",
  root_jailbreak_detection: "루팅·탈옥 탐지",
  hook_debug_detection: "후킹·디버거 탐지",
  code_obfuscation: "코드 난독화",
  reverse_engineering_resistance: "역공학 저항",
  sensitive_input_protection: "민감 입력 보호",
  screen_input_isolation: "입력 화면 격리",
  malicious_app_detection: "악성앱 탐지",
  device_risk_response: "단말 위험 대응",
  runtime_threat_detection: "런타임 위협 탐지",
  device_risk_telemetry: "위협 원격 측정",
  app_integrity_attestation: "앱 무결성 증명",
  device_integrity_attestation: "단말 무결성 증명",
};

function SecuritySolutionPanel({ analysis }: { analysis: SecuritySolutionAnalysis | null }) {
  if (!analysis) {
    return (
      <section className="solution-analyzer solution-analyzer--loading">
        <span className="eyebrow">MOBILE DEFENSE FINGERPRINT</span>
        <p>보안솔루션 분석 결과를 읽는 중입니다.</p>
      </section>
    );
  }

  return (
    <section className="solution-analyzer">
      <header className="solution-analyzer__head">
        <div>
          <span className="eyebrow">MOBILE DEFENSE FINGERPRINT</span>
          <h4>앱에 포함된 보호 계층</h4>
          <p>패키지·프레임워크·네이티브 라이브러리·제품 문자열을 교차 확인합니다.</p>
        </div>
        <div className="solution-analyzer__catalog" aria-label="보안솔루션 시그니처 카탈로그">
          <strong>{analysis.catalog_signature_count}</strong>
          <span>known signatures</span>
          <code>{analysis.catalog_version ?? "legacy"}</code>
        </div>
      </header>

      {analysis.solutions.length ? (
        <div className="solution-stack">
          {analysis.solutions.map((solution, index) => (
            <article className="solution-card" key={solution.signature_id}>
              <div className="solution-card__index">{String(index + 1).padStart(2, "0")}</div>
              <div className="solution-card__body">
                <div className="solution-card__title">
                  <div>
                    <small>{solution.vendor}</small>
                    <strong>{solution.product}</strong>
                  </div>
                  <span className={`solution-confidence solution-confidence--${solution.confidence_label}`}>
                    {Math.round(solution.confidence * 100)}% · {solution.confidence_label}
                  </span>
                </div>
                <div className="solution-card__meter" aria-label={`정적 식별 신뢰도 ${Math.round(solution.confidence * 100)}%`}>
                  <i style={{ width: `${Math.round(solution.confidence * 100)}%` }} />
                </div>
                <div className="solution-card__meta">
                  <span>{solution.category_label}</span>
                  <span>강한 지표 {solution.strong_indicator_count}</span>
                  <span>교차 근거 {solution.evidence_types.length}종</span>
                  <span>동적 검증 필요</span>
                </div>
                <div className="solution-card__controls">
                  {solution.expected_control_areas.map((area) => (
                    <span key={area}>{CONTROL_AREA_LABELS[area] ?? area}</span>
                  ))}
                </div>
                <details className="solution-card__evidence">
                  <summary>식별 근거 {solution.evidence.length}건 보기</summary>
                  <div>
                    {solution.evidence.map((evidence, evidenceIndex) => (
                      <div key={`${evidence.indicator}-${evidence.location}-${evidenceIndex}`}>
                        <span className={`evidence-strength evidence-strength--${evidence.strength}`} />
                        <strong>{evidence.indicator}</strong>
                        <small>{evidence.kind_label}</small>
                        <code>{evidence.location}</code>
                      </div>
                    ))}
                  </div>
                </details>
              </div>
            </article>
          ))}
        </div>
      ) : (
        <div className="solution-analyzer__empty">
          <strong>알려진 솔루션 지표를 식별하지 못했습니다</strong>
          <p>미적용을 의미하지 않습니다. 패킹·난독화 또는 카탈로그에 없는 제품은 고객 자료와 실단말 동작으로 확인하세요.</p>
        </div>
      )}

      <footer className="solution-analyzer__limits">
        <strong>STATIC IDENTIFICATION ONLY</strong>
        <span>제품 활성화·정책·보호 성공·우회 가능성은 자동 판정하지 않습니다.</span>
      </footer>
    </section>
  );
}
