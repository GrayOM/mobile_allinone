import { useEffect, useMemo, useState } from "react";
import { api, downloadAuthenticatedFile, post, upload } from "../api";
import type {
  AIStaticTriage,
  AppArtifact,
  AssessmentPlan,
  AssessmentPlanControl,
  AssessmentPlanLane,
  ControlTest,
  CoverageData,
  DiagnosticRun,
  Evidence,
  Project,
} from "../types";
import { EmptyState, SectionHeading, StatusChip } from "../components/UI";

const PROFILE_LABELS: Record<string, string> = {
  critical_infrastructure: "주요정보통신기반시설",
  electronic_financial: "전자금융기반시설",
  owasp_mastg: "OWASP MASTG 보조 원장",
};

type AssessmentOutcome = "confirmed" | "needs_review" | "not_vulnerable" | "not_applicable";

const ASSESSMENT_OUTCOMES: Array<{
  value: AssessmentOutcome;
  label: string;
  description: string;
}> = [
  { value: "confirmed", label: "취약 확정", description: "재현 원본 증적과 기준 충족 확인이 필수입니다." },
  { value: "needs_review", label: "추가 검토", description: "후보는 유지하지만 취약점으로 확정하지 않습니다." },
  { value: "not_vulnerable", label: "양호", description: "상태만 기록하며 양호 증적은 생성하지 않습니다." },
  { value: "not_applicable", label: "해당없음", description: "적용 대상이 아닌 사유만 기록합니다." },
];

const ASSESSMENT_RECORDABLE_STATUSES = new Set([
  "safely_paused",
  "completed",
  "completed_with_gaps",
  "manual_required",
]);

export default function CoveragePage() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [projectId, setProjectId] = useState(
    () => localStorage.getItem("msw.project") ?? "",
  );
  const [apps, setApps] = useState<AppArtifact[]>([]);
  const [appId, setAppId] = useState(
    () => localStorage.getItem("msw.app") ?? "",
  );
  const [coverage, setCoverage] = useState<CoverageData | null>(null);
  const [runs, setRuns] = useState<DiagnosticRun[]>([]);
  const [runId, setRunId] = useState(
    () => localStorage.getItem("msw.coverageRun") ?? "",
  );
  const [automation, setAutomation] = useState("all");
  const [ledger, setLedger] = useState<"domestic" | "mastg">("domestic");
  const [error, setError] = useState("");
  const [triage, setTriage] = useState<AIStaticTriage | null>(null);
  const [triaging, setTriaging] = useState(false);
  const [reporting, setReporting] = useState(false);
  const [assessmentPlan, setAssessmentPlan] = useState<AssessmentPlan | null>(null);
  const [refreshingPlan, setRefreshingPlan] = useState(false);
  const [runEvidence, setRunEvidence] = useState<Evidence[]>([]);
  const [selectedControlId, setSelectedControlId] = useState("");
  const [assessmentOutcome, setAssessmentOutcome] = useState<AssessmentOutcome>("confirmed");
  const [assessmentReviewer, setAssessmentReviewer] = useState(
    () => localStorage.getItem("msw.assessmentReviewer") ?? "",
  );
  const [assessmentSummary, setAssessmentSummary] = useState("");
  const [criteriaConfirmed, setCriteriaConfirmed] = useState(false);
  const [selectedEvidenceIds, setSelectedEvidenceIds] = useState<string[]>([]);
  const [assessmentFile, setAssessmentFile] = useState<File | null>(null);
  const [assessmentBusy, setAssessmentBusy] = useState(false);
  const [assessmentUploadBusy, setAssessmentUploadBusy] = useState(false);
  const [assessmentMessage, setAssessmentMessage] = useState("");
  const [assessmentError, setAssessmentError] = useState("");

  const project = useMemo(
    () => projects.find((item) => item.id === projectId),
    [projectId, projects],
  );
  const standard = ledger === "mastg"
    ? "owasp_mastg"
    : project?.assessment_profile ?? "critical_infrastructure";
  const selectedRun = useMemo(
    () => runs.find((item) => item.id === runId),
    [runId, runs],
  );
  const selectedControl = useMemo(
    () => coverage?.tests.find((item) => item.id === selectedControlId) ?? null,
    [coverage, selectedControlId],
  );

  useEffect(() => {
    void api<Project[]>("/projects")
      .then((items) => {
        setProjects(items);
        if (!projectId && items[0]) setProjectId(items[0].id);
      })
      .catch((reason: Error) => setError(reason.message));
  }, []);

  useEffect(() => {
    if (!projectId) {
      setApps([]);
      setRuns([]);
      return;
    }
    void Promise.all([
      api<AppArtifact[]>(`/projects/${projectId}/apps`),
      api<DiagnosticRun[]>(`/projects/${projectId}/runs`),
    ])
      .then(([items, runItems]) => {
        setApps(items);
        setRuns(runItems);
        if (!items.some((item) => item.id === appId)) {
          setAppId(items[0]?.id ?? "");
        }
        if (!runItems.some((item) => item.id === runId)) setRunId("");
      })
      .catch((reason: Error) => setError(reason.message));
  }, [projectId]);

  useEffect(() => {
    if (!appId) {
      setCoverage(null);
      return;
    }
    const query = new URLSearchParams(
      runId
        ? { run_id: runId, scope: "run", standard }
        : { app_id: appId, standard },
    );
    void api<CoverageData>(`/coverage?${query.toString()}`)
      .then(setCoverage)
      .catch((reason: Error) => setError(reason.message));
  }, [appId, runId, standard]);

  useEffect(() => {
    if (!runId) {
      setRunEvidence([]);
      setSelectedControlId("");
      return;
    }
    void api<Evidence[]>(`/runs/${runId}/evidence`)
      .then(setRunEvidence)
      .catch((reason: Error) => setError(reason.message));
  }, [runId]);

  useEffect(() => {
    if (selectedControlId && !selectedControl) setSelectedControlId("");
  }, [selectedControl, selectedControlId]);

  useEffect(() => {
    const selectedApp = apps.find((item) => item.id === appId);
    const value = selectedApp?.analysis_result.ai_static_triage;
    setTriage(value && typeof value === "object" ? value as unknown as AIStaticTriage : null);
  }, [appId, apps]);

  useEffect(() => {
    if (!appId || standard === "owasp_mastg") {
      setAssessmentPlan(null);
      return;
    }
    void api<AssessmentPlan>(`/apps/${appId}/assessment/plan`)
      .then(setAssessmentPlan)
      .catch((reason: Error) => setError(reason.message));
  }, [appId, standard]);

  const filtered = useMemo(
    () =>
      coverage?.tests.filter(
        (test) => automation === "all"
          || (automation.startsWith("lane:")
            ? test.execution?.lane === automation.slice(5)
            : test.automation === automation),
      ) ?? [],
    [automation, coverage],
  );
  const groups = useMemo(() => groupControls(filtered), [filtered]);
  const decided = standard === "owasp_mastg"
    ? coverage?.counts.completed ?? 0
    : (coverage?.result_counts.confirmed ?? 0)
      + (coverage?.result_counts.not_vulnerable ?? 0)
      + (coverage?.result_counts.not_applicable ?? 0);
  const total = coverage?.tests.length ?? 0;
  const completion = total ? Math.round((decided / total) * 100) : 0;
  const domestic = standard !== "owasp_mastg";
  const laneCounts = useMemo(() => {
    const values: Record<string, number> = {};
    for (const test of coverage?.tests ?? []) {
      const lane = test.execution?.lane;
      if (lane) values[lane] = (values[lane] ?? 0) + 1;
    }
    return values;
  }, [coverage]);

  async function runStaticTriage() {
    if (!appId || !project) return;
    setTriaging(true);
    setError("");
    try {
      const response = await post<{ triage: AIStaticTriage; assessment_plan: AssessmentPlan }>(`/apps/${appId}/ai/triage`, {
        use_mock: project.run_mode === "mock",
      });
      setTriage(response.triage);
      setAssessmentPlan(response.assessment_plan);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "AI 사전 분류를 완료하지 못했습니다.");
    } finally {
      setTriaging(false);
    }
  }

  async function refreshPlan() {
    if (!appId) return;
    setRefreshingPlan(true);
    setError("");
    try {
      const plan = await post<AssessmentPlan>(`/apps/${appId}/assessment/plan/refresh`);
      setAssessmentPlan(plan);
      const query = new URLSearchParams(
        runId
          ? { run_id: runId, scope: "run", standard }
          : { app_id: appId, standard },
      );
      setCoverage(await api<CoverageData>(`/coverage?${query.toString()}`));
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "앱 점검 계획을 다시 계산하지 못했습니다.");
    } finally {
      setRefreshingPlan(false);
    }
  }

  async function downloadDocxReport() {
    if (!runId) return;
    setReporting(true);
    setError("");
    try {
      const response = await post<{ file: string }>(`/runs/${runId}/report/docx`);
      await downloadAuthenticatedFile(`/runs/${runId}/report/docx`, response.file);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "취약점 DOCX 보고서를 생성하지 못했습니다.");
    } finally {
      setReporting(false);
    }
  }

  function openAssessmentReview(test: ControlTest) {
    const recordedOutcome = ASSESSMENT_OUTCOMES.some((item) => item.value === test.result)
      ? test.result as AssessmentOutcome
      : null;
    const existingOutcome = recordedOutcome ?? "confirmed";
    setSelectedControlId(test.id);
    setAssessmentOutcome(existingOutcome);
    setAssessmentSummary(recordedOutcome ? test.summary : "");
    setCriteriaConfirmed(false);
    setSelectedEvidenceIds(
      test.evidence_ids.filter((id) => {
        const evidence = runEvidence.find((item) => item.id === id);
        return evidence?.evidence_type !== "assessment_attestation";
      }),
    );
    setAssessmentFile(null);
    setAssessmentMessage("");
    setAssessmentError("");
  }

  async function refreshRunAssessment() {
    if (!appId || !runId) return;
    const query = new URLSearchParams({ run_id: runId, scope: "run", standard });
    const [nextCoverage, nextEvidence] = await Promise.all([
      api<CoverageData>(`/coverage?${query.toString()}`),
      api<Evidence[]>(`/runs/${runId}/evidence`),
    ]);
    setCoverage(nextCoverage);
    setRunEvidence(nextEvidence);
  }

  async function uploadAssessmentEvidence() {
    if (!selectedControl || !assessmentFile) return;
    setAssessmentUploadBusy(true);
    setAssessmentError("");
    setAssessmentMessage("");
    try {
      const response = await upload<{ evidence_id: string }>(
        `/assessment-controls/${selectedControl.id}/evidence`,
        assessmentFile,
      );
      setSelectedEvidenceIds((items) => [...new Set([...items, response.evidence_id])]);
      setAssessmentFile(null);
      await refreshRunAssessment();
      setAssessmentMessage("원본 증적을 이 항목에 첨부했습니다. 취약 확정 전 필수 증적 충족 여부를 확인하세요.");
    } catch (reason) {
      setAssessmentError(reason instanceof Error ? reason.message : "원본 증적을 첨부하지 못했습니다.");
    } finally {
      setAssessmentUploadBusy(false);
    }
  }

  async function recordAssessment() {
    if (!selectedControl) return;
    setAssessmentBusy(true);
    setAssessmentError("");
    setAssessmentMessage("");
    try {
      await post<ControlTest>(`/assessment-controls/${selectedControl.id}/record`, {
        outcome: assessmentOutcome,
        reviewer: assessmentReviewer.trim(),
        summary: assessmentSummary.trim(),
        evidence_ids: assessmentOutcome === "confirmed" ? selectedEvidenceIds : [],
        criteria_confirmed: assessmentOutcome === "confirmed" && criteriaConfirmed,
      });
      localStorage.setItem("msw.assessmentReviewer", assessmentReviewer.trim());
      await refreshRunAssessment();
      setAssessmentMessage(
        assessmentOutcome === "confirmed"
          ? "취약 판정과 연결 증적을 확정 원장에 기록했습니다. 이제 취약점 전용 DOCX에 포함됩니다."
          : "판정 상태와 검토 사유만 기록했습니다. 양호·해당없음 증적은 생성하거나 연결하지 않았습니다.",
      );
      setCriteriaConfirmed(false);
    } catch (reason) {
      setAssessmentError(reason instanceof Error ? reason.message : "판정을 기록하지 못했습니다.");
    } finally {
      setAssessmentBusy(false);
    }
  }

  return (
    <div className="stack stack--lg">
      <SectionHeading
        eyebrow="EVIDENCE-BOUND ASSESSMENT LEDGER"
        title="기준을 선택하고, 증적으로만 취약점을 확정합니다"
        description="취약 판정은 같은 Run의 재현 원본 증적이 있을 때만 확정합니다. 양호·해당없음은 상태만 기록하며 별도 증적을 요구하지 않습니다."
      />
      {error && <div className="inline-alert">{error}</div>}

      <section className="standard-switch" aria-label="진단 기준 원장">
        <button
          className={ledger === "domestic" ? "standard-switch__item standard-switch__item--active" : "standard-switch__item"}
          onClick={() => setLedger("domestic")}
        >
          <span>01 / 판정 기준</span>
          <strong>{PROFILE_LABELS[project?.assessment_profile ?? "critical_infrastructure"]}</strong>
          <small>{project?.assessment_profile === "electronic_financial" ? "56개 전자금융 점검 항목" : "27개 주요정보통신 점검 항목"}</small>
        </button>
        <button
          className={ledger === "mastg" ? "standard-switch__item standard-switch__item--active" : "standard-switch__item"}
          onClick={() => setLedger("mastg")}
        >
          <span>02 / 국제 보조 기준</span>
          <strong>OWASP MASTG</strong>
          <small>플랫폼별 통제 신호와 교차 확인</small>
        </button>
      </section>

      <section className="coverage-command">
        <div className="field">
          <label htmlFor="coverage-project">프로젝트</label>
          <select
            id="coverage-project"
            value={projectId}
            onChange={(event) => {
              setProjectId(event.target.value);
              setLedger("domestic");
              localStorage.setItem("msw.project", event.target.value);
            }}
          >
            <option value="">프로젝트 선택</option>
            {projects.map((item) => (
              <option key={item.id} value={item.id}>{item.name}</option>
            ))}
          </select>
        </div>
        <div className="field">
          <label htmlFor="coverage-app">앱 분석 기준선</label>
          <select
            id="coverage-app"
            value={appId}
            onChange={(event) => {
              setAppId(event.target.value);
              setRunId("");
              localStorage.removeItem("msw.coverageRun");
              localStorage.setItem("msw.app", event.target.value);
            }}
          >
            <option value="">앱 선택</option>
            {apps.map((app) => (
              <option key={app.id} value={app.id}>
                {app.app_name || app.original_name} · {app.version || "—"}
              </option>
            ))}
          </select>
          <select
            aria-label="진단 실행 원장"
            value={runId}
            onChange={(event) => {
              setRunId(event.target.value);
              if (event.target.value) localStorage.setItem("msw.coverageRun", event.target.value);
              else localStorage.removeItem("msw.coverageRun");
            }}
          >
            <option value="">정적 분석 기준선</option>
            {runs.filter((item) => item.app_id === appId).map((item) => (
              <option key={item.id} value={item.id}>
                Run {item.id.slice(0, 8)} · {item.status}
              </option>
            ))}
          </select>
        </div>
        <div className="field">
          <label htmlFor="coverage-mode">실행 방식</label>
          <select
            id="coverage-mode"
            value={automation}
            onChange={(event) => setAutomation(event.target.value)}
          >
            <option value="all">전체 항목</option>
            <option value="static">정적 자동화</option>
            <option value="dynamic">동적 자동화</option>
            <option value="hybrid">정적 + 동적</option>
            <option value="manual">승인 수동 점검</option>
            <option value="lane:ready_now">NOW · 단말 없이 가능</option>
            <option value="lane:device_required">DEVICE · 실제 단말 대기</option>
            <option value="lane:server_scope_required">SERVER · 승인 서버 필요</option>
            <option value="lane:manual_review">MANUAL · 수동 검토</option>
          </select>
        </div>
        <div className="coverage-gauge" aria-label={`판정 완료율 ${completion}%`}>
          <span>DECISION COVERAGE</span>
          <strong>{String(completion).padStart(2, "0")}<small>%</small></strong>
          <i><b style={{ width: `${completion}%` }} /></i>
          <em>{decided} / {total} decision-complete</em>
        </div>
      </section>

      {domestic && coverage && (
        <section className="execution-rail" aria-label="진단 실행 경계">
          <div className="execution-rail__label">
            <span>EXECUTION BOUNDARY</span>
            <strong>단말 없이 할 일과 대기 항목</strong>
          </div>
          <ExecutionLane code="NOW" label="지금 가능" value={laneCounts.ready_now ?? 0} tone="now" />
          <ExecutionLane code="DEVICE" label="실제 단말" value={laneCounts.device_required ?? 0} tone="device" />
          <ExecutionLane code="SERVER" label="승인 서버" value={laneCounts.server_scope_required ?? 0} tone="server" />
          <ExecutionLane code="MANUAL" label="수동 검토" value={laneCounts.manual_review ?? 0} tone="manual" />
          <div className="execution-rail__actions">
            <button
              className="button button--primary"
              onClick={() => void runStaticTriage()}
              disabled={triaging || !appId || !project?.ai_enabled || (project.run_mode === "live" && !project.external_ai_allowed)}
            >
              {triaging ? "정적 증적 분류 중…" : "AI 사전 진단"}
            </button>
            <button
              className="button button--signal"
              onClick={() => void downloadDocxReport()}
              disabled={reporting || !runId || (coverage.result_counts.confirmed ?? 0) === 0}
            >
              {reporting ? "DOCX 생성 중…" : "취약점만 DOCX"}
            </button>
          </div>
        </section>
      )}

      {domestic && assessmentPlan && (
        <AssessmentDispatch
          plan={assessmentPlan}
          refreshing={refreshingPlan}
          onRefresh={() => void refreshPlan()}
          onSelectLane={(lane) => setAutomation(`lane:${lane}`)}
        />
      )}

      {selectedControl && runId && (
        <AssessmentDecisionDesk
          control={selectedControl}
          outcome={assessmentOutcome}
          reviewer={assessmentReviewer}
          summary={assessmentSummary}
          criteriaConfirmed={criteriaConfirmed}
          evidence={runEvidence}
          selectedEvidenceIds={selectedEvidenceIds}
          file={assessmentFile}
          busy={assessmentBusy}
          uploadBusy={assessmentUploadBusy}
          message={assessmentMessage}
          error={assessmentError}
          onOutcomeChange={(value) => {
            setAssessmentOutcome(value);
            setAssessmentMessage("");
            setAssessmentError("");
          }}
          onReviewerChange={setAssessmentReviewer}
          onSummaryChange={setAssessmentSummary}
          onCriteriaChange={setCriteriaConfirmed}
          onEvidenceChange={setSelectedEvidenceIds}
          onFileChange={setAssessmentFile}
          onUpload={() => void uploadAssessmentEvidence()}
          onRecord={() => void recordAssessment()}
          onClose={() => setSelectedControlId("")}
        />
      )}

      {domestic && triage && (
        <section className="ai-precheck">
          <header>
            <div><span>AI STATIC PRECHECK</span><strong>{triage.provider} / {triage.model}</strong></div>
            <StatusChip value={triage.status} />
          </header>
          <p>정적 사전 분류는 모두 검토 필요 상태입니다. 실제 재현과 필수 증적 없이는 취약 확정에 포함되지 않습니다.</p>
          {triage.findings.length ? triage.findings.map((finding, index) => (
            <article key={`${finding.title}-${index}`}>
              <code>{finding.control_ids.join(", ") || "UNMAPPED"}</code>
              <div><strong>{finding.title}</strong><small>{finding.rationale}</small></div>
              <StatusChip value="needs_review" />
            </article>
          )) : <small>현재 정적 결과에서 국내 기준에 매핑할 AI 후보가 없습니다.</small>}
        </section>
      )}

      {coverage && coverage.tests.length ? (
        <>
          <div className="coverage-strip">
            <CoverageMetric label="전체 항목" value={coverage.total_catalog} tone="neutral" />
            <CoverageMetric label={domestic ? "취약 확정" : "자동 완료"} value={domestic ? coverage.result_counts.confirmed ?? 0 : coverage.counts.completed ?? 0} tone={domestic ? "warn" : "ok"} />
            <CoverageMetric label={domestic ? "양호·해당없음" : "수동 필요"} value={domestic ? (coverage.result_counts.not_vulnerable ?? 0) + (coverage.result_counts.not_applicable ?? 0) : coverage.counts.manual_required ?? 0} tone={domestic ? "ok" : "warn"} />
            <CoverageMetric label="검토 필요" value={coverage.result_counts.needs_review ?? 0} tone="signal" />
            <CoverageMetric label="미실행" value={(coverage.result_counts.not_tested ?? 0) + (coverage.result_counts.unknown ?? 0)} tone="muted" />
          </div>
          <section className={domestic ? "coverage-ledger coverage-ledger--domestic" : "coverage-ledger"}>
            <header className="coverage-ledger__head">
              <span>{domestic ? "기준 / 항목 ID" : "MASVS / MASTG"}</span>
              <span>진단 기준과 취약 증적</span>
              <span>실행 상태</span>
              <span>판정</span>
            </header>
            {groups.map(([group, tests]) => (
              <div className="coverage-group" key={group}>
                <div className="coverage-group__spine">
                  <span>{group.replace("MASVS-", "")}</span>
                  <strong>{tests.length}</strong>
                </div>
                <div>
                  {tests.map((test) => (
                    <ControlRow
                      key={test.id}
                      test={test}
                      domestic={domestic}
                      plan={assessmentPlan?.controls.find((item) => item.control_id === (test.control_id || test.mastg_id))}
                      onReview={test.run_id ? () => openAssessmentReview(test) : undefined}
                      reviewDisabled={!selectedRun || !ASSESSMENT_RECORDABLE_STATUSES.has(selectedRun.status)}
                    />
                  ))}
                </div>
              </div>
            ))}
          </section>
          <p className="catalog-note">
            기준: {String(coverage.source.name ?? PROFILE_LABELS[standard])} · 검토일 {String(coverage.source.reviewed_at ?? coverage.source.metadata_reviewed_at ?? "—")} · 항목명과 진단 기준은 제공된 문서를 실행 가능한 로컬 판정 정책으로 요약했습니다.
          </p>
        </>
      ) : (
        <EmptyState
          title="판정 원장이 아직 없습니다"
          description="APK 또는 IPA를 등록하거나 기존 앱을 재분석하면 선택한 국내 기준의 항목 원장이 만들어집니다."
        />
      )}
    </div>
  );
}

function groupControls(tests: ControlTest[]): Array<[string, ControlTest[]]> {
  const values = new Map<string, ControlTest[]>();
  for (const test of tests) {
    const group = test.group || test.masvs_id || "기타";
    values.set(group, [...(values.get(group) ?? []), test]);
  }
  return [...values.entries()];
}

function CoverageMetric({ label, value, tone }: { label: string; value: number; tone: string }) {
  return (
    <div className={`coverage-metric coverage-metric--${tone}`}>
      <i />
      <strong>{value}</strong>
      <span>{label}</span>
    </div>
  );
}

function ExecutionLane({ code, label, value, tone }: { code: string; label: string; value: number; tone: string }) {
  return (
    <div className={`execution-lane execution-lane--${tone}`}>
      <code>{code}</code><strong>{value}</strong><span>{label}</span>
    </div>
  );
}

const DISPATCH_LANES: Array<{
  lane: AssessmentPlanLane;
  code: string;
  label: string;
  blocker: string;
}> = [
  { lane: "ready_now", code: "NOW", label: "정적 선별", blocker: "APK·IPA 분석 결과" },
  { lane: "device_required", code: "DEVICE", label: "단말 대기", blocker: "승인된 실제 단말" },
  { lane: "server_scope_required", code: "SERVER", label: "서버 범위 대기", blocker: "허용 서버·계정" },
  { lane: "manual_review", code: "MANUAL", label: "전문가 검토", blocker: "검토자·원본 증적" },
];

function AssessmentDispatch({
  plan,
  refreshing,
  onRefresh,
  onSelectLane,
}: {
  plan: AssessmentPlan;
  refreshing: boolean;
  onRefresh: () => void;
  onSelectLane: (lane: AssessmentPlanLane) => void;
}) {
  return (
    <section className="assessment-dispatch" aria-label="앱 점검 배차판">
      <header>
        <div>
          <span>APP ASSESSMENT DISPATCH / SHA {plan.artifact_sha256.slice(0, 12)}</span>
          <strong>앱 분석 직후 생성된 점검 계획</strong>
          <small>NOW는 정적 선별을 완료하고, 나머지는 필요한 승인·환경이 준비될 때까지 대기합니다.</small>
        </div>
        <div className="assessment-dispatch__progress">
          <span>NOW SCREENED</span>
          <strong>{plan.ready_now_screened}<small> / {plan.ready_now_total}</small></strong>
          <button className="button button--quiet" onClick={onRefresh} disabled={refreshing}>
            {refreshing ? "계획 계산 중…" : "점검 계획 다시 계산"}
          </button>
        </div>
      </header>
      <div className="assessment-dispatch__lanes">
        {DISPATCH_LANES.map((item) => {
          const count = plan.lane_counts[item.lane] ?? 0;
          const screened = item.lane === "ready_now" ? plan.ready_now_screened : 0;
          return (
            <button
              key={item.lane}
              className={`dispatch-lane dispatch-lane--${item.lane}`}
              onClick={() => onSelectLane(item.lane)}
            >
              <code>{item.code}</code>
              <strong>{count}</strong>
              <span>{item.label}</span>
              <small>{item.lane === "ready_now" ? `${screened}개 선별 완료` : item.blocker}</small>
            </button>
          );
        })}
      </div>
      <footer>
        <span>후보 연결 항목 {plan.candidate_controls}개</span>
        <span>정책 {plan.decision_policy}</span>
        <time dateTime={plan.generated_at}>{new Date(plan.generated_at).toLocaleString()}</time>
      </footer>
    </section>
  );
}

function ControlRow({
  test,
  domestic,
  plan,
  onReview,
  reviewDisabled = false,
}: {
  test: ControlTest;
  domestic: boolean;
  plan?: AssessmentPlanControl;
  onReview?: () => void;
  reviewDisabled?: boolean;
}) {
  const id = test.control_id || test.mastg_id;
  return (
    <article className="control-row">
      <div>
        <code>{id}</code>
        {domestic && test.execution && (
          <span className={`execution-badge execution-badge--${test.execution.lane}`}>
            {test.execution.lane.replaceAll("_", " ")}
          </span>
        )}
        {domestic && plan && (
          <span className={`dispatch-status dispatch-status--${plan.queue_status}`}>
            {plan.queue_status.replaceAll("_", " ")}
          </span>
        )}
        {domestic ? <small>RISK · {test.risk.toUpperCase()}</small> : test.replacement_ids.length > 0 && (
          <small>→ {test.replacement_ids.join(", ")}</small>
        )}
      </div>
      <div>
        {test.source_url ? (
          <a href={test.source_url} target="_blank" rel="noreferrer">{test.title}</a>
        ) : <strong>{test.title}</strong>}
        <small>{test.automation.toUpperCase()} · {test.summary}</small>
        {domestic && plan && <small className="control-next-action">NEXT · {plan.next_action}</small>}
        {domestic && test.criteria.length > 0 && (
          <details className="control-criteria">
            <summary>취약 판정 기준·필수 증적 보기</summary>
            <ol>{test.criteria.map((criterion) => <li key={criterion}>{criterion}</li>)}</ol>
            <p>취약 확정 시 필수 증적: {test.evidence_requirements.map((group) => group.join(" 또는 ")).join(" + ")}</p>
            <p>연결 증적 {test.evidence_ids.length}건 · Finding {test.finding_ids.length}건</p>
          </details>
        )}
        {domestic && onReview && (
          <button
            type="button"
            className="button button--quiet button--small control-review-button"
            onClick={onReview}
            disabled={reviewDisabled}
            title={reviewDisabled ? "안전 일시정지 또는 종료된 Run에서 판정할 수 있습니다." : "이 항목의 취약 증적과 판정을 검토합니다."}
          >
            취약 판정 작업
          </button>
        )}
      </div>
      <StatusChip value={test.status} />
      <StatusChip value={test.result} />
    </article>
  );
}

function AssessmentDecisionDesk({
  control,
  outcome,
  reviewer,
  summary,
  criteriaConfirmed,
  evidence,
  selectedEvidenceIds,
  file,
  busy,
  uploadBusy,
  message,
  error,
  onOutcomeChange,
  onReviewerChange,
  onSummaryChange,
  onCriteriaChange,
  onEvidenceChange,
  onFileChange,
  onUpload,
  onRecord,
  onClose,
}: {
  control: ControlTest;
  outcome: AssessmentOutcome;
  reviewer: string;
  summary: string;
  criteriaConfirmed: boolean;
  evidence: Evidence[];
  selectedEvidenceIds: string[];
  file: File | null;
  busy: boolean;
  uploadBusy: boolean;
  message: string;
  error: string;
  onOutcomeChange: (value: AssessmentOutcome) => void;
  onReviewerChange: (value: string) => void;
  onSummaryChange: (value: string) => void;
  onCriteriaChange: (value: boolean) => void;
  onEvidenceChange: (value: string[]) => void;
  onFileChange: (value: File | null) => void;
  onUpload: () => void;
  onRecord: () => void;
  onClose: () => void;
}) {
  const requiredKinds = new Set(control.evidence_requirements.flat());
  const eligibleEvidence = evidence.filter((item) => {
    if (item.evidence_type === "assessment_attestation") return false;
    if (item.evidence_type === "manual_assessment_attachment") {
      return !Array.isArray(item.inline_data)
        && item.inline_data?.control_test_id === control.id;
    }
    return requiredKinds.has(item.evidence_type) || selectedEvidenceIds.includes(item.id);
  });
  const selectedTypes = new Set(
    evidence
      .filter((item) => selectedEvidenceIds.includes(item.id))
      .map((item) => item.evidence_type),
  );
  const requirementStatus = control.evidence_requirements.map((group) => ({
    group,
    satisfied: group.some((kind) => selectedTypes.has(kind)),
  }));
  const requirementsSatisfied = requirementStatus.every((item) => item.satisfied);
  const manualAttachmentAccepted = requiredKinds.has("manual_assessment_attachment");
  const canRecord = reviewer.trim().length > 0
    && summary.trim().length > 0
    && (outcome !== "confirmed" || (criteriaConfirmed && requirementsSatisfied));

  function toggleEvidence(id: string) {
    onEvidenceChange(
      selectedEvidenceIds.includes(id)
        ? selectedEvidenceIds.filter((item) => item !== id)
        : [...selectedEvidenceIds, id],
    );
  }

  return (
    <div className="consent-dialog-backdrop assessment-review-backdrop" role="presentation">
      <section
        className="assessment-review-desk"
        role="dialog"
        aria-modal="true"
        aria-labelledby="assessment-review-title"
      >
        <header className="assessment-review-desk__header">
          <div>
            <span>VULNERABILITY CASE FILE / {control.control_id || control.mastg_id}</span>
            <h2 id="assessment-review-title">{control.title}</h2>
            <small>같은 Run의 원본 증적으로 취약한 항목만 확정합니다.</small>
          </div>
          <button type="button" className="assessment-review-desk__close" onClick={onClose} aria-label="판정 작업 닫기">×</button>
        </header>

        <div className="assessment-review-desk__body">
          <section className="assessment-evidence-bay">
            <header>
              <span>01 / REQUIRED EVIDENCE</span>
              <strong>증적 충족 상태</strong>
            </header>
            <div className="assessment-requirements">
              {requirementStatus.map(({ group, satisfied }) => (
                <div className={satisfied ? "assessment-requirement assessment-requirement--ok" : "assessment-requirement"} key={group.join("|")}>
                  <i aria-hidden="true">{satisfied ? "✓" : "!"}</i>
                  <span>{group.join(" 또는 ")}</span>
                  <strong>{satisfied ? "충족" : "필요"}</strong>
                </div>
              ))}
            </div>

            {outcome === "confirmed" ? (
              <>
                <div className="assessment-evidence-list">
                  <div className="assessment-evidence-list__head">
                    <span>같은 Run의 연결 가능한 원본</span>
                    <strong>{selectedEvidenceIds.length} selected</strong>
                  </div>
                  {eligibleEvidence.length ? eligibleEvidence.map((item) => (
                    <label className="assessment-evidence-row" key={item.id}>
                      <input
                        type="checkbox"
                        checked={selectedEvidenceIds.includes(item.id)}
                        onChange={() => toggleEvidence(item.id)}
                      />
                      <span><strong>{item.title}</strong><small>{item.evidence_type} · #{item.sequence}</small></span>
                      <code>{item.sha256?.slice(0, 10) ?? "INLINE"}</code>
                    </label>
                  )) : (
                    <p className="assessment-evidence-empty">필수 유형과 일치하는 원본 증적이 없습니다. 자동 수집을 실행하거나 허용된 수동 증적을 첨부하세요.</p>
                  )}
                </div>

                {manualAttachmentAccepted && (
                  <div className="assessment-upload">
                    <label>
                      <span>수동 원본 첨부</span>
                      <input
                        type="file"
                        accept=".png,.jpg,.jpeg,.txt,.log,.json,.xml,.har"
                        onChange={(event) => onFileChange(event.target.files?.[0] ?? null)}
                      />
                    </label>
                    <button type="button" className="button button--primary button--small" onClick={onUpload} disabled={!file || uploadBusy}>
                      {uploadBusy ? "첨부 중…" : "원본 첨부"}
                    </button>
                  </div>
                )}
              </>
            ) : (
              <div className="assessment-no-evidence">
                <strong>증적을 연결하지 않습니다</strong>
                <p>양호·해당없음·추가 검토 판정은 상태와 검토 사유만 저장합니다. 취약점 보고서에도 포함되지 않습니다.</p>
              </div>
            )}
          </section>

          <section className="assessment-verdict-bay">
            <header>
              <span>02 / REVIEWER DECISION</span>
              <strong>판정 기록</strong>
            </header>
            <div className="assessment-outcomes" role="radiogroup" aria-label="판정 결과">
              {ASSESSMENT_OUTCOMES.map((item) => (
                <button
                  type="button"
                  role="radio"
                  aria-checked={outcome === item.value}
                  className={outcome === item.value ? `assessment-outcome assessment-outcome--${item.value} assessment-outcome--active` : `assessment-outcome assessment-outcome--${item.value}`}
                  key={item.value}
                  onClick={() => onOutcomeChange(item.value)}
                >
                  <strong>{item.label}</strong>
                  <small>{item.description}</small>
                </button>
              ))}
            </div>

            <div className="assessment-review-fields">
              <label>
                <span>검토자</span>
                <input value={reviewer} maxLength={100} onChange={(event) => onReviewerChange(event.target.value)} placeholder="판정 책임자 또는 로컬 식별자" />
              </label>
              <label>
                <span>{outcome === "confirmed" ? "취약 판정 근거" : "검토 사유"}</span>
                <textarea value={summary} maxLength={4000} rows={6} onChange={(event) => onSummaryChange(event.target.value)} placeholder="재현한 취약 조건과 증적에서 확인한 사실을 기록하세요." />
              </label>
            </div>

            {outcome === "confirmed" && (
              <label className="assessment-criteria-check">
                <input type="checkbox" checked={criteriaConfirmed} onChange={(event) => onCriteriaChange(event.target.checked)} />
                <span>
                  <strong>문서의 취약 진단 기준을 실제로 수행했습니다</strong>
                  <small>{control.criteria.join(" ")}</small>
                </span>
              </label>
            )}

            {error && <div className="inline-alert">{error}</div>}
            {message && <div className="inline-alert inline-alert--ok">{message}</div>}

            <footer className="assessment-review-actions">
              <div>
                <span>{outcome === "confirmed" ? "확정 후 취약점 전용 DOCX 대상" : "증적·DOCX 제외"}</span>
                <small>{outcome === "confirmed" && !requirementsSatisfied ? "필수 증적이 아직 부족합니다." : "판정 정책을 충족했습니다."}</small>
              </div>
              <button type="button" className="button button--quiet" onClick={onClose}>닫기</button>
              <button type="button" className={outcome === "confirmed" ? "button button--danger" : "button button--primary"} onClick={onRecord} disabled={busy || !canRecord}>
                {busy ? "기록 중…" : outcome === "confirmed" ? "취약점 확정 기록" : "판정 상태 기록"}
              </button>
            </footer>
          </section>
        </div>
      </section>
    </div>
  );
}
