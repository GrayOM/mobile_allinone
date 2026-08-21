import { FormEvent, useEffect, useMemo, useState } from "react";
import { api, patch, post } from "../api";
import { AuthenticatedDownload } from "../components/AuthenticatedFile";
import { EmptyState, SectionHeading, StatusChip, formatBytes, formatDate } from "../components/UI";
import { Link } from "../router";
import type {
  Project,
  ProjectDataInventory,
  ProxyFlow,
  RunRawIndex,
} from "../types";

interface RetentionApplyResult {
  status: string;
  removed_run_ids: string[];
  removed_bytes: number;
  removal_errors: string[];
  recoverable: false;
  remaining_inventory: ProjectDataInventory;
}

export default function DataManagementPage() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [projectId, setProjectId] = useState(
    () => localStorage.getItem("msw.project") ?? "",
  );
  const [inventory, setInventory] = useState<ProjectDataInventory | null>(null);
  const [retentionDays, setRetentionDays] = useState(90);
  const [rawEnabled, setRawEnabled] = useState(false);
  const [rawRunId, setRawRunId] = useState("");
  const [rawIndex, setRawIndex] = useState<RunRawIndex | null>(null);
  const [rawFlows, setRawFlows] = useState<ProxyFlow[]>([]);
  const [confirmName, setConfirmName] = useState("");
  const [reviewed, setReviewed] = useState(false);
  const [busy, setBusy] = useState("");
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  const project = useMemo(
    () => projects.find((item) => item.id === projectId) ?? null,
    [projectId, projects],
  );

  function loadInventory(selectedId: string) {
    setError("");
    void api<ProjectDataInventory>(`/projects/${selectedId}/data-inventory`)
      .then((value) => {
        setInventory(value);
        setRetentionDays(value.retention_days);
        setRawEnabled(value.raw_access_enabled);
      })
      .catch((reason: Error) => setError(reason.message));
  }

  useEffect(() => {
    void api<Project[]>("/projects")
      .then((items) => {
        setProjects(items);
        const selected = items.some((item) => item.id === projectId)
          ? projectId
          : items[0]?.id ?? "";
        if (selected) {
          setProjectId(selected);
          localStorage.setItem("msw.project", selected);
        }
      })
      .catch((reason: Error) => setError(reason.message));
  }, []);

  useEffect(() => {
    if (projectId) loadInventory(projectId);
    else setInventory(null);
    setRawRunId("");
    setRawIndex(null);
    setRawFlows([]);
    setConfirmName("");
    setReviewed(false);
  }, [projectId]);

  async function savePolicy(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!project) return;
    setBusy("policy");
    setError("");
    setMessage("");
    try {
      const updated = await patch<Project>(`/projects/${project.id}`, {
        retention_days: retentionDays,
        raw_access_enabled: rawEnabled,
      });
      setProjects((items) => items.map((item) => item.id === updated.id ? updated : item));
      setMessage("프로젝트 데이터 정책을 저장했습니다. 기존 Run의 만료 시각을 다시 계산했습니다.");
      loadInventory(project.id);
      if (!updated.raw_access_enabled) {
        setRawRunId("");
        setRawIndex(null);
        setRawFlows([]);
      }
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "데이터 정책 저장 실패");
    } finally {
      setBusy("");
    }
  }

  async function revealRaw(runId: string) {
    if (!project?.raw_access_enabled) {
      setError("프로젝트 데이터 정책에서 Raw 열람을 먼저 활성화하세요.");
      return;
    }
    const approved = window.confirm(
      "이 Run의 원본 패킷과 증적 파일 목록에는 토큰·개인정보가 포함될 수 있습니다. 로컬 전용 화면에서 열람할까요?",
    );
    if (!approved) return;
    setBusy(`raw:${runId}`);
    setError("");
    try {
      const [index, flows] = await Promise.all([
        api<RunRawIndex>(`/projects/${project.id}/runs/${runId}/raw-index`),
        api<ProxyFlow[]>(`/runs/${runId}/flows/raw`),
      ]);
      setRawRunId(runId);
      setRawIndex(index);
      setRawFlows(flows);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Raw 데이터 열람 실패");
    } finally {
      setBusy("");
    }
  }

  async function applyRetention() {
    if (!project || !inventory) return;
    setBusy("retention");
    setError("");
    setMessage("");
    try {
      const result = await post<RetentionApplyResult>(
        `/projects/${project.id}/retention/apply`,
        {
          reviewed,
          confirm_project_name: confirmName,
          expected_run_ids: inventory.expired_run_ids,
        },
      );
      setInventory(result.remaining_inventory);
      setProjects((items) => items.map((item) => item.id === project.id
        ? { ...item, retention_days: result.remaining_inventory.retention_days }
        : item));
      setRawRunId("");
      setRawIndex(null);
      setRawFlows([]);
      setConfirmName("");
      setReviewed(false);
      setMessage(
        `${result.removed_run_ids.length}개 Run과 ${formatBytes(result.removed_bytes)} 원본을 정리했습니다.${result.removal_errors.length ? " 일부 파일 삭제는 실패했습니다." : ""}`,
      );
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "보존기간 정리 실패");
      if (project) loadInventory(project.id);
    } finally {
      setBusy("");
    }
  }

  return (
    <div className="stack stack--lg data-vault-page">
      <SectionHeading
        eyebrow="LOCAL DATA VAULT"
        title="원본 데이터의 보존과 열람을 분리합니다"
        description="기본 화면은 마스킹 데이터를 사용합니다. Raw 열람과 만료 Run 삭제는 이 화면에서만 명시적으로 수행합니다."
      />
      {message && <div className="inline-alert inline-alert--ok">{message}</div>}
      {error && <div className="inline-alert">{error}</div>}

      <section className="panel data-policy-panel">
        <div className="data-policy-panel__selector field">
          <label htmlFor="data-project">프로젝트</label>
          <select
            id="data-project"
            value={projectId}
            onChange={(event) => {
              setProjectId(event.target.value);
              localStorage.setItem("msw.project", event.target.value);
            }}
          >
            {projects.map((item) => <option key={item.id} value={item.id}>{item.name}</option>)}
          </select>
        </div>
        {project && (
          <form className="data-policy-panel__form" onSubmit={savePolicy}>
            <div className="field">
              <label htmlFor="retention-days">보존기간</label>
              <div className="data-retention-input">
                <input
                  id="retention-days"
                  type="number"
                  min={1}
                  max={3650}
                  value={retentionDays}
                  onChange={(event) => setRetentionDays(Number(event.target.value))}
                />
                <span>일</span>
              </div>
            </div>
            <label className="toggle-line data-raw-toggle">
              <input
                type="checkbox"
                checked={rawEnabled}
                onChange={(event) => setRawEnabled(event.target.checked)}
              />
              <span />
              <div><strong>Raw 원본 열람 허용</strong><small>전용 화면에서 다시 확인한 경우에만 패킷 원문과 파일 내려받기를 표시합니다.</small></div>
            </label>
            <button className="button button--primary" disabled={busy === "policy"}>
              {busy === "policy" ? "저장 중…" : "데이터 정책 저장"}
            </button>
          </form>
        )}
      </section>

      {inventory ? (
        <>
          <section className="data-vault-ledger" aria-label="프로젝트 데이터 보존 현황">
            <div><span>RETENTION</span><strong>{inventory.retention_days} DAYS</strong><small>자동 삭제 안 함</small></div>
            <div><span>CUTOFF</span><strong>{formatDate(inventory.cutoff_at)}</strong><small>종료 시각 기준</small></div>
            <div className={inventory.expired_run_count ? "is-expired" : ""}><span>EXPIRED RUNS</span><strong>{inventory.expired_run_count}</strong><small>명시적 확인 필요</small></div>
            <div><span>LOCAL SIZE</span><strong>{formatBytes(inventory.total_disk_bytes)}</strong><small>{inventory.run_count} runs</small></div>
            <div><span>RAW ACCESS</span><strong>{inventory.raw_access_enabled ? "ENABLED" : "LOCKED"}</strong><small>Cache-Control: no-store</small></div>
          </section>

          <section className="panel data-run-register">
            <div className="data-run-register__head">
              <div><span className="eyebrow">RETENTION REGISTER</span><h2>Run별 원본 보존 현황</h2></div>
              <small>만료는 삭제 예약이 아니라 검토 대상 표시입니다.</small>
            </div>
            {inventory.runs.length ? (
              <div className="data-run-table">
                <div className="data-run-table__header"><span>Run</span><span>상태</span><span>원본 구성</span><span>만료</span><span>크기</span><span>열람</span></div>
                {inventory.runs.map((item) => (
                  <div className={item.expired ? "is-expired" : ""} key={item.run_id}>
                    <span><Link to={`/runs/${item.run_id}`}>{item.run_id.slice(0, 8)}</Link><small>{item.synthetic ? "SYNTHETIC MOCK" : "LIVE"}</small></span>
                    <StatusChip value={item.status} />
                    <span><strong>{item.evidence_count} evidence · {item.flow_count} flows</strong><small>{item.ai_invocation_count} AI · {item.has_frida_transcript ? "Frida JSONL" : "no Frida JSONL"}</small></span>
                    <span><strong>{formatDate(item.expires_at)}</strong><small>{item.expired ? "보존기간 경과" : "보존 중"}</small></span>
                    <strong>{formatBytes(item.disk_bytes)}</strong>
                    <button
                      type="button"
                      className="button button--quiet button--small"
                      disabled={!inventory.raw_access_enabled || Boolean(busy)}
                      onClick={() => void revealRaw(item.run_id)}
                    >
                      {busy === `raw:${item.run_id}` ? "불러오는 중…" : "Raw 열람"}
                    </button>
                  </div>
                ))}
              </div>
            ) : <EmptyState title="보존된 Run이 없습니다" description="진단을 실행하면 원본 구성과 만료 예정일이 이 원장에 표시됩니다." />}
          </section>

          {inventory.expired_run_count > 0 && project && (
            <section className="panel retention-action-panel">
              <div>
                <span className="eyebrow">IRREVERSIBLE RETENTION ACTION</span>
                <h2>만료 Run {inventory.expired_run_count}개 정리</h2>
                <p>현재 미리보기에 표시된 정확한 Run ID만 다시 계산해 삭제합니다. 활성 Run과 앱 원본·정적 분석 기준선은 삭제하지 않습니다.</p>
                <code>{inventory.expired_run_ids.join("\n")}</code>
              </div>
              <div className="retention-confirmation">
                <div className="field">
                  <label htmlFor="retention-confirm-name">프로젝트 이름을 그대로 입력</label>
                  <input id="retention-confirm-name" value={confirmName} onChange={(event) => setConfirmName(event.target.value)} placeholder={project.name} />
                </div>
                <label className="retention-check">
                  <input type="checkbox" checked={reviewed} onChange={(event) => setReviewed(event.target.checked)} />
                  <span>DB 이력과 로컬 원본 파일이 삭제되며 복구할 수 없음을 확인했습니다.</span>
                </label>
                <button
                  type="button"
                  className="button button--danger"
                  disabled={confirmName !== project.name || !reviewed || Boolean(busy)}
                  onClick={() => void applyRetention()}
                >
                  {busy === "retention" ? "서버 재검증 중…" : "미리 본 만료 Run 정리"}
                </button>
              </div>
            </section>
          )}

          {rawIndex && rawRunId && (
            <section className="panel raw-inspection-panel">
              <div className="raw-inspection-panel__head">
                <div><span className="eyebrow">SENSITIVE LOCAL VIEW · NO STORE</span><h2>Run {rawRunId.slice(0, 8)} 원본 인덱스</h2></div>
                <button type="button" className="button button--quiet button--small" onClick={() => { setRawRunId(""); setRawIndex(null); setRawFlows([]); }}>열람 닫기</button>
              </div>
              <div className="raw-inspection-grid">
                <div>
                  <h3>원본 증적 파일</h3>
                  <div className="raw-evidence-list">
                    {rawIndex.evidence.map((item) => (
                      <div key={item.id}>
                        <span>{String(item.sequence).padStart(3, "0")}</span>
                        <strong>{item.title}</strong>
                        <small>{item.type} · SHA {item.sha256?.slice(0, 12) ?? "inline"}</small>
                        {item.download_available && <AuthenticatedDownload path={`/evidence/${item.id}/download`} filename={`${item.sequence}-${item.id}`} sha256={item.sha256} />}
                      </div>
                    ))}
                  </div>
                </div>
                <div>
                  <h3>AI 호출 원장</h3>
                  <div className="raw-ai-list">
                    {rawIndex.ai_invocations.map((item) => (
                      <div key={item.id}><StatusChip value={item.status} /><strong>{item.task}</strong><small>{item.provider} · {item.model} · raw {item.raw_response_available ? "stored" : "not stored"}</small></div>
                    ))}
                    {!rawIndex.ai_invocations.length && <p>이 Run에는 AI 호출 이력이 없습니다.</p>}
                  </div>
                </div>
              </div>
              <div className="raw-flow-list">
                <h3>Raw 프록시 흐름 · {rawFlows.length}</h3>
                {rawFlows.map((flow) => (
                  <details key={flow.id}>
                    <summary><strong>{flow.method}</strong><code>{flow.url}</code><span>{flow.status_code ?? "—"}</span></summary>
                    <pre>{JSON.stringify({
                      request_headers: flow.request_headers,
                      request_body: flow.request_body,
                      response_headers: flow.response_headers,
                      response_body: flow.response_body,
                    }, null, 2)}</pre>
                  </details>
                ))}
              </div>
            </section>
          )}
        </>
      ) : projects.length ? <div className="loading-block">데이터 원장을 계산하는 중…</div> : <EmptyState title="프로젝트가 없습니다" description="프로젝트를 만든 뒤 보존 정책을 설정하세요." />}
    </div>
  );
}
