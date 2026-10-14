import { FormEvent, useEffect, useMemo, useState } from "react";
import { api, patch, post, put, remove } from "../api";
import type { Project, ProjectAssessmentScope, ScopeControlRecord } from "../types";
import { StatusChip } from "./UI";

const PLATFORM_LABELS: Record<string, string> = {
  any: "Android · iOS",
  android: "Android",
  ios: "iOS",
};

const AUTOMATION_LABELS: Record<string, string> = {
  manual: "승인 수동 점검",
  static: "정적 자동화",
  dynamic: "동적 자동화",
  hybrid: "정적 + 동적",
};

function lines(value: FormDataEntryValue | null): string[] {
  return String(value ?? "")
    .split("\n")
    .map((item) => item.trim())
    .filter(Boolean);
}

export function AssessmentScopePanel({ project }: { project: Project }) {
  const [scope, setScope] = useState<ProjectAssessmentScope | null>(null);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);
  const [showForm, setShowForm] = useState(false);
  const [evaluator, setEvaluator] = useState("manual");
  const [automation, setAutomation] = useState("manual");
  const [excluding, setExcluding] = useState("");
  const [exclusionReason, setExclusionReason] = useState("");
  const [filter, setFilter] = useState("");
  const [recorder, setRecorder] = useState(
    () => localStorage.getItem("msw.assessmentReviewer") ?? "",
  );

  function load() {
    void api<ProjectAssessmentScope>(`/projects/${project.id}/assessment-scope`)
      .then((value) => {
        setScope(value);
        setError("");
      })
      .catch((reason: Error) => setError(reason.message));
  }

  useEffect(load, [project.id]);

  const selectedEvaluator = useMemo(
    () => scope?.options.evaluators.find((item) => item.key === evaluator),
    [evaluator, scope],
  );
  const catalog = useMemo(() => {
    const query = filter.trim().toLowerCase();
    return (scope?.catalog ?? []).filter(
      (item) => !query
        || item.control_id.toLowerCase().includes(query)
        || item.title.toLowerCase().includes(query)
        || item.group.toLowerCase().includes(query),
    );
  }, [filter, scope]);
  const evaluatorLabels = useMemo(
    () => Object.fromEntries((scope?.options.evaluators ?? []).map((item) => [item.key, item.label])),
    [scope],
  );
  const exclusions = useMemo(
    () => Object.fromEntries((scope?.exclusions ?? []).map((item) => [item.control_id, item])),
    [scope],
  );

  function rememberRecorder(value: string) {
    setRecorder(value);
    localStorage.setItem("msw.assessmentReviewer", value);
  }

  async function run(action: () => Promise<unknown>, message: string) {
    setBusy(true);
    setError("");
    setNotice("");
    try {
      await action();
      setNotice(message);
      load();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "요청을 처리하지 못했습니다.");
    } finally {
      setBusy(false);
    }
  }

  async function createCustom(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const data = new FormData(form);
    await run(async () => {
      const created = await post<ScopeControlRecord>(`/projects/${project.id}/custom-controls`, {
        title: data.get("title"),
        group: data.get("group") || "사용자 정의 검사",
        criteria: lines(data.get("criteria")),
        procedure: lines(data.get("procedure")),
        automation,
        evaluator,
        risk: data.get("risk"),
        severity: data.get("severity"),
        platform_scope: data.get("platform_scope"),
        finding_categories: String(data.get("finding_categories") ?? "")
          .split(",")
          .map((item) => item.trim())
          .filter(Boolean),
        reference: data.get("reference") ?? "",
        reason: data.get("reason"),
        recorded_by: recorder,
      });
      form.reset();
      setShowForm(false);
      setNotice(`${created.control_id} 예외 검사를 추가했습니다.`);
    }, "예외 검사를 추가했습니다. 기존 Run 원장은 바뀌지 않고 새 Run부터 적용됩니다.");
  }

  async function confirmExclusion(controlId: string) {
    await run(
      () => put(`/projects/${project.id}/control-exclusions/${controlId}`, {
        reason: exclusionReason,
        recorded_by: recorder,
      }),
      `${controlId}를 프로젝트 범위에서 제외했습니다.`,
    );
    setExcluding("");
    setExclusionReason("");
  }

  if (!scope) {
    return (
      <section className="scope-ledger" aria-label="진단 범위">
        <div className="scope-ledger__head">
          <div>
            <span className="eyebrow">ASSESSMENT SCOPE</span>
            <h3>진단 범위 · 기준 외 예외 검사</h3>
          </div>
        </div>
        {error ? <div className="inline-alert">{error}</div> : <p className="scope-ledger__hint">범위를 불러오는 중…</p>}
      </section>
    );
  }

  return (
    <section className="scope-ledger" aria-label="진단 범위">
      <div className="scope-ledger__head">
        <div>
          <span className="eyebrow">ASSESSMENT SCOPE</span>
          <h3>진단 범위 · 기준 외 예외 검사</h3>
          <p>
            고정된 국내 기준은 그대로 두고, 권고안에 없는 검사를 추가하거나 합의된 범위 밖 항목을 사유와 함께 제외합니다.
            변경은 앱 기준선과 새 Run에만 적용되며 기존 Run 원장은 보존됩니다.
          </p>
        </div>
        <div className="scope-ledger__counts" aria-label="범위 요약">
          <div><span>기준</span><strong>{scope.catalog_total}</strong></div>
          <div><span>제외</span><strong>{scope.excluded_total}</strong></div>
          <div><span>예외 검사</span><strong>{scope.custom_enabled}</strong></div>
          <div className="scope-ledger__counts--total"><span>실행 대상</span><strong>{scope.effective_total}</strong></div>
        </div>
      </div>

      {error && <div className="inline-alert">{error}</div>}
      {notice && <div className="inline-notice">{notice}</div>}

      <div className="scope-ledger__recorder field">
        <label htmlFor="scope-recorder">기록자</label>
        <input
          id="scope-recorder"
          value={recorder}
          onChange={(event) => rememberRecorder(event.target.value)}
          placeholder="이름 또는 검토자 ID"
          maxLength={100}
        />
      </div>

      <div className="scope-ledger__section-head">
        <strong>기준 외 예외 검사 {scope.custom.length}</strong>
        <button
          type="button"
          className="button button--quiet button--small"
          onClick={() => setShowForm((value) => !value)}
          aria-expanded={showForm}
        >
          {showForm ? "입력 닫기" : "예외 검사 추가"}
        </button>
      </div>

      {showForm && (
        <form className="scope-form" onSubmit={(event) => void createCustom(event)}>
          <div className="field field--wide">
            <label htmlFor="scope-title">검사 이름</label>
            <input id="scope-title" name="title" required minLength={2} maxLength={200} placeholder="예: 결제 WebView 외부 도메인 로딩" />
          </div>
          <div className="field">
            <label htmlFor="scope-group">분류</label>
            <input id="scope-group" name="group" maxLength={100} placeholder="고객 추가 검사" />
          </div>
          <div className="field">
            <label htmlFor="scope-platform">적용 플랫폼</label>
            <select id="scope-platform" name="platform_scope" defaultValue="any">
              {scope.options.platform_scope.map((item) => (
                <option key={item} value={item}>{PLATFORM_LABELS[item] ?? item}</option>
              ))}
            </select>
          </div>
          <div className="field">
            <label htmlFor="scope-evaluator">판정 방식</label>
            <select
              id="scope-evaluator"
              value={evaluator}
              onChange={(event) => {
                setEvaluator(event.target.value);
                if (event.target.value === "static_review") setAutomation("static");
                else if (automation === "static") setAutomation("manual");
              }}
            >
              {scope.options.evaluators.map((item) => (
                <option key={item.key} value={item.key}>{item.label}</option>
              ))}
            </select>
            <small>
              취약 확정 필수 증적: {selectedEvaluator?.evidence_requirements.map((group) => group.join(" 또는 ")).join(" + ") ?? "—"}
            </small>
          </div>
          <div className="field">
            <label htmlFor="scope-automation">실행 방식</label>
            <select
              id="scope-automation"
              value={automation}
              onChange={(event) => setAutomation(event.target.value)}
            >
              {scope.options.automation.map((item) => (
                <option key={item} value={item} disabled={item === "static" && evaluator !== "static_review"}>
                  {AUTOMATION_LABELS[item] ?? item}
                </option>
              ))}
            </select>
          </div>
          <div className="field">
            <label htmlFor="scope-risk">작업 위험도</label>
            <select id="scope-risk" name="risk" defaultValue="medium">
              {scope.options.risk.map((item) => <option key={item} value={item}>{item.toUpperCase()}</option>)}
            </select>
          </div>
          <div className="field">
            <label htmlFor="scope-severity">취약 시 심각도</label>
            <select id="scope-severity" name="severity" defaultValue="medium">
              {scope.options.severity.map((item) => <option key={item} value={item}>{item.toUpperCase()}</option>)}
            </select>
          </div>
          <div className="field field--wide">
            <label htmlFor="scope-criteria">취약 판정 기준 (한 줄에 하나)</label>
            <textarea id="scope-criteria" name="criteria" rows={3} required placeholder="어떤 조건이면 취약으로 판단하는지 적습니다." />
          </div>
          <div className="field field--wide">
            <label htmlFor="scope-procedure">점검 절차 (선택, 한 줄에 하나)</label>
            <textarea id="scope-procedure" name="procedure" rows={3} placeholder="재현 단계를 순서대로 적습니다." />
          </div>
          <div className="field">
            <label htmlFor="scope-categories">Finding 분류 (쉼표 구분, 선택)</label>
            <input id="scope-categories" name="finding_categories" placeholder="webview, data_exposure" />
          </div>
          <div className="field">
            <label htmlFor="scope-reference">참조 (선택)</label>
            <input id="scope-reference" name="reference" maxLength={2000} placeholder="고객 요구사항·문서 번호" />
          </div>
          <div className="field field--wide">
            <label htmlFor="scope-reason">기준 외 검사 사유</label>
            <textarea id="scope-reason" name="reason" rows={2} required placeholder="선택한 권고안에 없는 검사를 추가하는 이유" />
          </div>
          <div className="form-actions field--wide">
            <button type="button" className="button button--quiet" onClick={() => setShowForm(false)}>취소</button>
            <button className="button button--primary" disabled={busy || !recorder.trim()}>
              {busy ? "저장 중…" : "예외 검사 저장"}
            </button>
          </div>
        </form>
      )}

      <div className="scope-table" role="table" aria-label="기준 외 예외 검사">
        {scope.custom.length === 0 && (
          <p className="scope-ledger__hint">추가된 예외 검사가 없습니다. 권고안 항목만 판정 원장에 생성됩니다.</p>
        )}
        {scope.custom.map((item) => (
          <article key={item.id} className={`scope-row ${item.enabled ? "" : "scope-row--off"}`} role="row">
            <div role="cell">
              <code>{item.control_id}</code>
              <small>{PLATFORM_LABELS[item.platform_scope ?? "any"]}</small>
            </div>
            <div role="cell">
              <strong>{item.title}</strong>
              <small>{item.evaluator_label} · {AUTOMATION_LABELS[item.automation ?? "manual"]} · RISK {item.risk?.toUpperCase()}</small>
              <small>필수 증적 {item.evidence_requirements?.map((group) => group.join(" 또는 ")).join(" + ")}</small>
              <small className="scope-row__reason">사유 · {item.recorded_by}: {item.reason}</small>
            </div>
            <div role="cell" className="scope-row__actions">
              <StatusChip value={item.enabled ? "available" : "not_configured"} label={item.enabled ? "사용" : "중지"} />
              <small>Run 사용 {item.run_usage ?? 0}</small>
              <button
                type="button"
                className="button button--quiet button--small"
                disabled={busy}
                onClick={() => void run(
                  () => patch(`/projects/${project.id}/custom-controls/${item.control_id}`, { enabled: !item.enabled }),
                  item.enabled ? `${item.control_id}를 새 Run에서 제외합니다.` : `${item.control_id}를 다시 사용합니다.`,
                )}
              >
                {item.enabled ? "중지" : "재사용"}
              </button>
              <button
                type="button"
                className="button button--danger button--small"
                disabled={busy || (item.run_usage ?? 0) > 0}
                title={(item.run_usage ?? 0) > 0 ? "Run 원장에 사용된 검사는 삭제할 수 없습니다." : "사용 이력이 없는 검사를 삭제합니다."}
                onClick={() => {
                  if (window.confirm(`${item.control_id} 예외 검사를 삭제할까요?`)) {
                    void run(() => remove(`/projects/${project.id}/custom-controls/${item.control_id}`), `${item.control_id}를 삭제했습니다.`);
                  }
                }}
              >
                삭제
              </button>
            </div>
          </article>
        ))}
      </div>

      <div className="scope-ledger__section-head">
        <strong>권고안 항목 범위 · 제외 {scope.excluded_total}</strong>
        <input
          className="scope-ledger__filter"
          aria-label="권고안 항목 검색"
          value={filter}
          onChange={(event) => setFilter(event.target.value)}
          placeholder="ID·항목명 검색"
        />
      </div>
      <div className="scope-table scope-table--catalog" role="table" aria-label="권고안 항목 범위">
        {catalog.map((item) => {
          const exclusion = exclusions[item.control_id];
          return (
            <article key={item.control_id} className={`scope-row ${exclusion ? "scope-row--excluded" : ""}`} role="row">
              <div role="cell">
                <code>{item.control_id}</code>
                <small>{item.group}</small>
              </div>
              <div role="cell">
                <strong>{item.title}</strong>
                {exclusion ? (
                  <small className="scope-row__reason">범위 제외 · {exclusion.recorded_by}: {exclusion.reason}</small>
                ) : (
                  <small>{AUTOMATION_LABELS[item.automation] ?? item.automation} · {evaluatorLabels[item.evaluator] ?? item.evaluator}</small>
                )}
                {excluding === item.control_id && (
                  <div className="scope-row__exclude">
                    <input
                      aria-label={`${item.control_id} 제외 사유`}
                      value={exclusionReason}
                      onChange={(event) => setExclusionReason(event.target.value)}
                      placeholder="제외 사유 (5자 이상, 예: 고객사 합의로 서버 점검 범위 제외)"
                      maxLength={2000}
                    />
                    <button
                      type="button"
                      className="button button--primary button--small"
                      disabled={busy || exclusionReason.trim().length < 5 || !recorder.trim()}
                      onClick={() => void confirmExclusion(item.control_id)}
                    >
                      제외 기록
                    </button>
                    <button type="button" className="button button--quiet button--small" onClick={() => setExcluding("")}>
                      취소
                    </button>
                  </div>
                )}
              </div>
              <div role="cell" className="scope-row__actions">
                {exclusion ? (
                  <>
                    <StatusChip value="not_configured" label="제외" />
                    <button
                      type="button"
                      className="button button--quiet button--small"
                      disabled={busy}
                      onClick={() => void run(
                        () => remove(`/projects/${project.id}/control-exclusions/${item.control_id}`),
                        `${item.control_id}를 다시 진단 범위에 포함했습니다.`,
                      )}
                    >
                      제외 해제
                    </button>
                  </>
                ) : (
                  <button
                    type="button"
                    className="button button--quiet button--small"
                    disabled={busy || excluding === item.control_id}
                    onClick={() => {
                      setExcluding(item.control_id);
                      setExclusionReason("");
                    }}
                  >
                    범위 제외
                  </button>
                )}
              </div>
            </article>
          );
        })}
      </div>
    </section>
  );
}
