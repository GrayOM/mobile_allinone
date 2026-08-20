import { FormEvent, useEffect, useMemo, useState } from "react";
import { api, post } from "../api";
import type { AppArtifact, DiagnosticRun, FridaScript, Project } from "../types";
import { EmptyState, SectionHeading, StatusChip } from "../components/UI";

async function sha256(content: string): Promise<string> {
  if (!globalThis.crypto?.subtle) {
    throw new Error("이 브라우저는 안전한 스크립트 검토 확인에 필요한 Web Crypto를 지원하지 않습니다.");
  }
  const digest = await globalThis.crypto.subtle.digest("SHA-256", new TextEncoder().encode(content));
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export default function ScriptsPage() {
  const [scripts, setScripts] = useState<FridaScript[]>([]);
  const [selectedId, setSelectedId] = useState("");
  const [platform, setPlatform] = useState("android");
  const [result, setResult] = useState<Record<string, unknown> | null>(null);
  const [running, setRunning] = useState(false);
  const [generating, setGenerating] = useState(false);
  const [showGenerator, setShowGenerator] = useState(false);
  const [error, setError] = useState("");
  const [project, setProject] = useState<Project | null>(null);
  const [pausedRuns, setPausedRuns] = useState<DiagnosticRun[]>([]);
  const [selectedRunId, setSelectedRunId] = useState("");
  const [apps, setApps] = useState<AppArtifact[]>([]);
  const [selectedAppId, setSelectedAppId] = useState("");

  function load() {
    void api<FridaScript[]>("/frida/scripts").then((items) => {
      setScripts(items);
      if (!selectedId && items[0]) setSelectedId(items[0].id);
    });
  }
  useEffect(load, []);
  useEffect(() => {
    const projectId = localStorage.getItem("msw.project");
    if (projectId) void Promise.all([
      api<Project>(`/projects/${projectId}`),
      api<DiagnosticRun[]>(`/projects/${projectId}/runs`),
      api<AppArtifact[]>(`/projects/${projectId}/apps`),
    ]).then(([projectItem, runs, appItems]) => {
      setProject(projectItem);
      setPausedRuns(runs.filter((run) => run.status === "safely_paused"));
      setApps(appItems);
      setSelectedAppId((current) => current || appItems[0]?.id || "");
    });
  }, []);

  const filtered = scripts.filter((item) => item.platform === platform);
  const selected = filtered.find((item) => item.id === selectedId) ?? filtered[0];
  const compatiblePausedRuns = pausedRuns.filter((item) => (
    platform === "ios"
      ? item.device_adapter.toLowerCase().includes("ios") || item.device_id.toLowerCase().includes("ios")
      : !item.device_adapter.toLowerCase().includes("ios") && !item.device_id.toLowerCase().includes("ios")
  ));
  const compatibleApps = apps.filter((item) => item.platform === platform);
  const categories = useMemo(
    () => [...new Set(filtered.map((item) => item.category))],
    [filtered],
  );

  async function execute() {
    if (!selected) return;
    if (!project) {
      setError("프로젝트를 먼저 선택하세요.");
      return;
    }
    const run = compatiblePausedRuns.find((item) => item.id === selectedRunId)
      ?? compatiblePausedRuns[0];
    if (!run) {
      setError("같은 플랫폼 진단을 안전 일시정지한 뒤 실행하세요. 진단 설정의 ‘루팅·탈옥 탐지 우회 준비’를 사용하면 첫 앱 실행 전에 멈춥니다.");
      return;
    }
    if (project.run_mode === "live" && !window.confirm(
      `${selected.name}을(를) 승인 범위의 실제 단말과 대상 앱에 실행합니다.\n\n현재 코드·위험도·대상 Run을 확인했습니까?`,
    )) return;
    setError("");
    setRunning(true);
    try {
      const approval = await post<{ token: string }>("/approvals", {
        project_id: project.id,
        run_id: run.id,
        resource_type: "frida",
        action: `execute:${selected.id}`,
        approved_by: "local_user",
      });
      const value = await post<Record<string, unknown>>(`/frida/scripts/${selected.id}/execute`, {
        mode: "spawn",
        project_id: project.id,
        run_id: run.id,
        approval_token: approval.token,
      });
      setResult(value);
      load();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Frida 실행 실패");
    } finally {
      setRunning(false);
    }
  }

  async function approve() {
    if (!selected) return;
    const acknowledged = window.confirm(
      "스크립트 전체 내용, 적용 대상, 위험도를 직접 검토했습니까?\n\n승인하면 현재 내용의 해시가 고정되며, 한 글자라도 변경되면 다시 승인해야 합니다.",
    );
    if (!acknowledged) return;
    setError("");
    try {
      await post(`/frida/scripts/${selected.id}/approve`, {
        approver: "local_user",
        review_acknowledged: true,
        reviewed_sha256: await sha256(selected.content),
      });
      load();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "승인 실패");
    }
  }

  async function generate(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const projectId = localStorage.getItem("msw.project");
    if (!projectId) {
      setError("프로젝트를 먼저 선택하세요.");
      return;
    }
    const data = new FormData(event.currentTarget);
    const purpose = String(data.get("purpose") || "security_bypass");
    const contextRun = compatiblePausedRuns.find((item) => item.id === selectedRunId)
      ?? compatiblePausedRuns[0];
    const contextApp = compatibleApps.find((item) => item.id === selectedAppId)
      ?? compatibleApps[0];
    if (purpose === "security_bypass" && !contextRun && !contextApp) {
      setError("분석할 APK 또는 IPA를 프로젝트에 먼저 등록하세요.");
      return;
    }
    setGenerating(true);
    setError("");
    try {
      const response = await post<{
        script: FridaScript | null;
        syntax_message: string | null;
      }>("/frida/scripts/generate", {
        project_id: projectId,
        run_id: contextRun?.id ?? null,
        app_id: contextRun?.app_id ?? contextApp?.id ?? null,
        purpose,
        platform,
        category: data.get("category"),
        target_framework: data.get("target_framework"),
        task: purpose === "repair"
          ? "런타임 실패 로그와 코드에 맞는 Frida 수정 후보 생성"
          : "대상 코드와 증적에 맞는 관찰 Frida 후보 생성",
        code_excerpt: data.get("code_excerpt"),
        runtime_log: data.get("runtime_log"),
        failed_script: selected?.content ?? "",
        failure_message: data.get("failure_message"),
        use_mock: data.get("use_mock") === "on",
        simulate_nvidia_failure: data.get("simulate_nvidia_failure") === "on",
      });
      if (response.script) {
        setShowGenerator(false);
        load();
        setSelectedId(response.script.id);
      } else {
        setError("Provider가 유효한 스크립트 후보를 만들지 못했습니다.");
      }
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "후보 생성 실패");
    } finally {
      setGenerating(false);
    }
  }

  return (
    <div className="stack stack--lg">
      <SectionHeading
        eyebrow="SCRIPT CONTROL"
        title="관찰 조건과 실행 이력을 함께 관리합니다"
        description="저위험 내장 스크립트만 자동 선택됩니다. 루팅·탈옥 탐지 우회와 AI·사용자 코드는 안전 일시정지 상태에서 코드 해시를 검토하고 1회 승인해야 실행됩니다."
        action={
          <button className="button button--primary" onClick={() => setShowGenerator((value) => !value)}>
            AI 후보 생성
          </button>
        }
      />
      {error && <div className="inline-alert">{error}</div>}
      {showGenerator && (
        <form className="script-generator panel panel--accent" onSubmit={generate}>
          <div>
            <span className="eyebrow">REVIEW-GATED GENERATION</span>
            <h3>증적 기반 AI Frida 후보 만들기</h3>
            <p>우회 분석은 현재 Run의 정적 통제 신호와 제한된 로그만 마스킹해 사용합니다. 결과는 고위험·승인 대기로 저장되고 자동 실행되지 않습니다.</p>
          </div>
          <div className="form-grid">
            <div className="field">
              <label htmlFor="candidate-purpose">분석 목적</label>
              <select id="candidate-purpose" name="purpose" defaultValue="security_bypass">
                <option value="security_bypass">보안솔루션 우회 분석</option>
                <option value="repair">실패 스크립트 수정</option>
                <option value="observation">관찰 Hook 생성</option>
              </select>
            </div>
            <div className="field">
              <label htmlFor="candidate-run">분석할 안전 일시정지 Run</label>
              <select
                id="candidate-run"
                value={selectedRunId || compatiblePausedRuns[0]?.id || ""}
                onChange={(event) => setSelectedRunId(event.target.value)}
              >
                {!compatiblePausedRuns.length && <option value="">준비된 Run 없음</option>}
                {compatiblePausedRuns.map((run) => (
                  <option key={run.id} value={run.id}>{run.current_stage} · {run.device_id} · {run.id.slice(0, 8)}</option>
                ))}
              </select>
              <small>Run이 있으면 정적 신호와 현재 로그를 함께 사용합니다.</small>
            </div>
            <div className="field">
              <label htmlFor="candidate-app">정적 사전 분석 앱</label>
              <select
                id="candidate-app"
                value={selectedAppId || compatibleApps[0]?.id || ""}
                onChange={(event) => setSelectedAppId(event.target.value)}
              >
                {!compatibleApps.length && <option value="">등록된 {platform.toUpperCase()} 앱 없음</option>}
                {compatibleApps.map((app) => (
                  <option key={app.id} value={app.id}>{app.app_name || app.original_name} · {app.sha256.slice(0, 10)}</option>
                ))}
              </select>
              <small>실제 단말이 없어도 APK·IPA의 정적 통제 신호로 검토 후보를 만들 수 있습니다.</small>
            </div>
            <div className="field">
              <label htmlFor="candidate-category">보안통제 범주</label>
              <input id="candidate-category" name="category" defaultValue={selected?.category || "Custom"} />
            </div>
            <div className="field">
              <label htmlFor="candidate-framework">대상 프레임워크</label>
              <input id="candidate-framework" name="target_framework" defaultValue={selected?.target_framework || "generic"} />
            </div>
            <div className="field field--wide">
              <label htmlFor="candidate-failure">실패 메시지</label>
              <input id="candidate-failure" name="failure_message" placeholder="예: ClassNotFoundException 또는 overload mismatch" />
            </div>
            <div className="field">
              <label htmlFor="candidate-code">관련 코드 일부</label>
              <textarea id="candidate-code" name="code_excerpt" rows={5} placeholder="필요한 클래스·메서드 주변 코드만 입력" />
            </div>
            <div className="field">
              <label htmlFor="candidate-log">관련 런타임 로그</label>
              <textarea id="candidate-log" name="runtime_log" rows={5} placeholder="실패 직전 Frida·단말 로그만 입력" />
            </div>
            <label className="check-card">
              <input type="checkbox" name="use_mock" defaultChecked={project?.run_mode === "mock"} disabled={project?.run_mode !== "mock"} />
              <span><strong>Mock Provider</strong><small>외부 전송 없이 승인 흐름을 시험합니다.</small></span>
            </label>
            <label className="check-card">
              <input type="checkbox" name="simulate_nvidia_failure" />
              <span><strong>NVIDIA 실패 모의</strong><small>Claude fallback 경로를 확인합니다.</small></span>
            </label>
          </div>
          <p className="form-note">AI는 국내 기준의 관련 항목도 추천하지만, 필수 재현 증적 없이 취약 판정을 확정하지 않습니다.</p>
          <button className="button button--signal" disabled={generating}>
            {generating ? "후보 생성·검사 중…" : "후보 생성"}
          </button>
        </form>
      )}
      <div className="platform-switch">
        <button className={platform === "android" ? "active" : ""} onClick={() => setPlatform("android")}>Android</button>
        <button className={platform === "ios" ? "active" : ""} onClick={() => setPlatform("ios")}>iOS</button>
      </div>
      <div className="script-layout">
        <aside className="script-index panel">
          {categories.map((category) => (
            <div className="script-group" key={category}>
              <div className="panel-label">{category}</div>
              {filtered.filter((item) => item.category === category).map((script) => (
                <button className={`script-tab ${selected?.id === script.id ? "script-tab--active" : ""}`} key={script.id} onClick={() => setSelectedId(script.id)}>
                  <strong>{script.name}</strong>
                  <small>{script.target_framework}</small>
                  <StatusChip value={script.approval_status} />
                </button>
              ))}
            </div>
          ))}
          {!filtered.length && <EmptyState title="스크립트가 없습니다" description="이 플랫폼에 등록된 스크립트가 없습니다." />}
        </aside>
        <section className="script-detail panel">
          {selected ? (
            <>
              <div className="script-detail__head">
                <div>
                  <span className="eyebrow">{selected.category} / {selected.platform}</span>
                  <h2>{selected.name}</h2>
                  <div className="chip-row">
                    <span className="plain-chip">위험도 {selected.risk}</span>
                    <span className="plain-chip">{selected.target_framework}</span>
                    {selected.target_app_id && <span className="plain-chip">앱 고정 {selected.target_app_id.slice(0, 8)}</span>}
                    <StatusChip value={selected.syntax_status} />
                  </div>
                </div>
                <div className="script-score">
                  <div><strong>{selected.success_count}</strong><span>성공</span></div>
                  <div><strong>{selected.failure_count}</strong><span>실패</span></div>
                </div>
              </div>
              <div className="summary-block">
                <span>적용 조건</span>
                <div className="tag-cloud">{selected.conditions.map((item) => <span key={item}>{item}</span>)}</div>
              </div>
              <pre className="code-view code-view--tall">{selected.content}</pre>
              {compatiblePausedRuns.length > 0 && (
                <div className="field">
                  <label htmlFor="frida-run">실행할 안전 일시정지 Run</label>
                  <select
                    id="frida-run"
                    value={selectedRunId || compatiblePausedRuns[0]?.id || ""}
                    onChange={(event) => setSelectedRunId(event.target.value)}
                  >
                    {compatiblePausedRuns.map((run) => (
                      <option key={run.id} value={run.id}>{run.current_stage} · {run.device_id} · {run.id.slice(0, 8)}</option>
                    ))}
                  </select>
                </div>
              )}
              <div className="form-actions">
                <button className="button button--signal" onClick={() => void execute()} disabled={running || selected.approval_status !== "approved" || selected.syntax_status !== "available" || !project || !compatiblePausedRuns.length}>
                  {running ? "승인 실행 중…" : project?.run_mode === "live" ? "Live 단말에서 1회 실행" : "Mock 단말에서 1회 실행"}
                </button>
                {selected.approval_status !== "approved" && (
                  <button className="button button--primary" onClick={() => void approve()} disabled={selected.syntax_status !== "available"}>
                    구문 재검사 후 승인
                  </button>
                )}
                {selected.approval_status !== "approved" && <small>승인 전 전체 코드·대상·위험도를 검토해야 하며, Node.js 구문 검사와 현재 내용 해시가 모두 일치해야 합니다.</small>}
              </div>
              {result && <pre className="code-view">{JSON.stringify(result, null, 2)}</pre>}
            </>
          ) : <EmptyState title="스크립트를 선택하세요" description="왼쪽 라이브러리에서 스크립트를 선택하세요." />}
        </section>
      </div>
    </div>
  );
}
