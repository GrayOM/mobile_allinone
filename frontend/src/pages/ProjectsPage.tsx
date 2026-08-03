import { FormEvent, useEffect, useMemo, useState } from "react";
import { api, post, remove, upload } from "../api";
import type { AnalysisOverview, AppArtifact, Project } from "../types";
import {
  EmptyState,
  SectionHeading,
  StatusChip,
  formatBytes,
  formatDate,
} from "../components/UI";

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
        mock_mode: data.get("mock_mode") === "on",
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

  async function reanalyzeCurrentApp() {
    if (!selectedApp) return;
    setReanalyzing(true);
    setError("");
    try {
      const refreshed = await post<AppArtifact>(
        `/apps/${selectedApp.id}/reanalyze`,
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
            <label className="check-card">
              <input type="checkbox" name="ai_enabled" defaultChecked />
              <span><strong>AI 분석 사용</strong><small>증적 분류와 설명을 생성합니다.</small></span>
            </label>
            <label className="check-card">
              <input type="checkbox" name="external_ai_allowed" />
              <span><strong>외부 AI 전송 허용</strong><small>마스킹 후 NVIDIA·Claude로 전송합니다.</small></span>
            </label>
            <label className="check-card">
              <input type="checkbox" name="mock_mode" defaultChecked />
              <span><strong>Mock 모드</strong><small>외부 단말 없이 전체 흐름을 실행합니다.</small></span>
            </label>
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
              <span>{item.mock_mode ? "MOCK" : "LIVE"}</span>
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
                  <StatusChip value={project.mock_mode ? "available" : "manual_required"} label={project.mock_mode ? "Mock mode" : "Live mode"} />
                  <StatusChip value={project.external_ai_allowed ? "available" : "not_configured"} label={project.external_ai_allowed ? "외부 AI 허용" : "외부 AI 차단"} />
                  <button className="button button--danger button--small" onClick={() => void deleteCurrentProject()}>프로젝트 삭제</button>
                </div>
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
                        <small>{app.package_name || "패키지 미확인"} · {formatBytes(app.size_bytes)}</small>
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
                />
              </div>
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
}: {
  app: AppArtifact | null;
  overview: AnalysisOverview | null;
  reanalyzing: boolean;
  onReanalyze: () => void;
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
          <span>MASTG 기준선 {overview?.controls.length ?? 0}</span>
          <a href="/coverage">통제 원장 열기 →</a>
        </div>
      </div>
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
