import { FormEvent, useEffect, useMemo, useState } from "react";
import { api, post } from "../api";
import type { DiagnosticRun, FridaScript, Project } from "../types";
import { EmptyState, SectionHeading, StatusChip } from "../components/UI";

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
    ]).then(([projectItem, runs]) => {
      setProject(projectItem);
      setPausedRuns(runs.filter((run) => run.status === "paused"));
    });
  }, []);

  const filtered = scripts.filter((item) => item.platform === platform);
  const selected = scripts.find((item) => item.id === selectedId) ?? filtered[0];
  const categories = useMemo(
    () => [...new Set(filtered.map((item) => item.category))],
    [filtered],
  );

  async function execute() {
    if (!selected) return;
    if (!project || project.run_mode !== "mock") {
      setError("Mock Frida 실행은 Mock 프로젝트에서만 허용됩니다. Live 단말 실행은 진단 설정에서 진행하세요.");
      return;
    }
    const run = pausedRuns.find((item) => (
      selected.platform === "ios" ? item.device_id.includes("ios") : !item.device_id.includes("ios")
    ));
    if (!run) {
      setError("같은 플랫폼의 Mock 진단을 일시정지한 뒤 실행하세요. 직접 Frida 실행도 Run Lease와 증적에 연결됩니다.");
      return;
    }
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
    } finally {
      setRunning(false);
    }
  }

  async function approve() {
    if (!selected) return;
    setError("");
    try {
      await post(`/frida/scripts/${selected.id}/approve`);
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
    setGenerating(true);
    setError("");
    try {
      const response = await post<{
        script: FridaScript | null;
        syntax_message: string | null;
      }>("/frida/scripts/generate", {
        project_id: projectId,
        platform,
        category: data.get("category"),
        target_framework: data.get("target_framework"),
        task: "런타임 실패 로그와 코드에 맞는 관찰·검증 Frida 후보 생성",
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
        description="내장 스크립트는 저위험 관찰용이며, AI·사용자 생성 후보는 구문 검사와 승인 전까지 실행할 수 없습니다."
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
            <h3>실패 증적에서 최소 후보 만들기</h3>
            <p>선택 스크립트와 아래 입력은 프로젝트 정책에 따라 마스킹됩니다. 결과는 승인 대기 상태로만 저장됩니다.</p>
          </div>
          <div className="form-grid">
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
              <div className="form-actions">
                <button className="button button--signal" onClick={() => void execute()} disabled={running || selected.approval_status !== "approved" || selected.syntax_status !== "available" || project?.run_mode !== "mock" || !pausedRuns.length}>
                  {running ? "Mock 실행 중…" : "Mock 단말에서 실행"}
                </button>
                {selected.approval_status !== "approved" && (
                  <button className="button button--primary" onClick={() => void approve()} disabled={selected.syntax_status !== "available"}>
                    구문 재검사 후 승인
                  </button>
                )}
                {selected.approval_status !== "approved" && <small>Node.js 구문 검사를 통과한 스크립트만 승인할 수 있습니다.</small>}
              </div>
              {result && <pre className="code-view">{JSON.stringify(result, null, 2)}</pre>}
            </>
          ) : <EmptyState title="스크립트를 선택하세요" description="왼쪽 라이브러리에서 스크립트를 선택하세요." />}
        </section>
      </div>
    </div>
  );
}
