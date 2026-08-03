import { useEffect, useMemo, useState } from "react";
import { api } from "../api";
import type {
  AppArtifact,
  ControlTest,
  CoverageData,
  Project,
} from "../types";
import { EmptyState, SectionHeading, StatusChip } from "../components/UI";

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
  const [automation, setAutomation] = useState("all");
  const [error, setError] = useState("");

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
      return;
    }
    void api<AppArtifact[]>(`/projects/${projectId}/apps`)
      .then((items) => {
        setApps(items);
        if (!items.some((item) => item.id === appId)) {
          setAppId(items[0]?.id ?? "");
        }
      })
      .catch((reason: Error) => setError(reason.message));
  }, [projectId]);

  useEffect(() => {
    if (!appId) {
      setCoverage(null);
      return;
    }
    void api<CoverageData>(`/coverage?app_id=${encodeURIComponent(appId)}`)
      .then(setCoverage)
      .catch((reason: Error) => setError(reason.message));
  }, [appId]);

  const filtered = useMemo(
    () =>
      coverage?.tests.filter(
        (test) => automation === "all" || test.automation === automation,
      ) ?? [],
    [automation, coverage],
  );
  const groups = useMemo(() => groupControls(filtered), [filtered]);
  const completed = coverage?.counts.completed ?? 0;
  const total = coverage?.tests.length ?? 0;
  const completion = total ? Math.round((completed / total) * 100) : 0;

  return (
    <div className="stack stack--lg">
      <SectionHeading
        eyebrow="MASTG CONTROL LEDGER"
        title="검사한 것과 남겨둔 것을 같은 화면에서 봅니다"
        description="정적·동적 자동화와 수동 확인 항목을 MASTG 식별자로 추적합니다. 자동 신호는 최종 취약점 판정이 아니라 검토 상태입니다."
      />
      {error && <div className="inline-alert">{error}</div>}

      <section className="coverage-command">
        <div className="field">
          <label htmlFor="coverage-project">프로젝트</label>
          <select
            id="coverage-project"
            value={projectId}
            onChange={(event) => {
              setProjectId(event.target.value);
              localStorage.setItem("msw.project", event.target.value);
            }}
          >
            <option value="">프로젝트 선택</option>
            {projects.map((project) => (
              <option key={project.id} value={project.id}>{project.name}</option>
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
        </div>
        <div className="field">
          <label htmlFor="coverage-mode">자동화 범위</label>
          <select
            id="coverage-mode"
            value={automation}
            onChange={(event) => setAutomation(event.target.value)}
          >
            <option value="all">전체 통제</option>
            <option value="static">정적 자동화</option>
            <option value="dynamic">동적 자동화</option>
            <option value="hybrid">정적 + 동적</option>
            <option value="manual">수동 확인</option>
          </select>
        </div>
        <div className="coverage-gauge" aria-label={`완료율 ${completion}%`}>
          <span>CONTROL SIGNAL</span>
          <strong>{String(completion).padStart(2, "0")}<small>%</small></strong>
          <i><b style={{ width: `${completion}%` }} /></i>
          <em>{completed} / {total} completed</em>
        </div>
      </section>

      {coverage && coverage.tests.length ? (
        <>
          <div className="coverage-strip">
            <CoverageMetric label="카탈로그" value={coverage.total_catalog} tone="neutral" />
            <CoverageMetric label="자동 완료" value={completed} tone="ok" />
            <CoverageMetric label="수동 필요" value={coverage.counts.manual_required ?? 0} tone="warn" />
            <CoverageMetric label="검토 필요" value={coverage.result_counts.needs_review ?? 0} tone="signal" />
            <CoverageMetric label="미지원" value={coverage.counts.unsupported ?? 0} tone="muted" />
          </div>
          <section className="coverage-ledger">
            <header className="coverage-ledger__head">
              <span>MASVS / MASTG</span>
              <span>통제와 자동화 방식</span>
              <span>실행 상태</span>
              <span>판정 신호</span>
            </header>
            {groups.map(([group, tests]) => (
              <div className="coverage-group" key={group}>
                <div className="coverage-group__spine">
                  <span>{group.replace("MASVS-", "")}</span>
                  <strong>{tests.length}</strong>
                </div>
                <div>
                  {tests.map((test) => <ControlRow key={test.id} test={test} />)}
                </div>
              </div>
            ))}
          </section>
          <p className="catalog-note">
            카탈로그: {String(coverage.source.name ?? "OWASP MASTG")} · 검토일{" "}
            {String(coverage.source.metadata_reviewed_at ?? "—")} · 전체 원문을 복제하지 않고
            식별자·링크·로컬 실행 상태만 저장합니다.
          </p>
        </>
      ) : (
        <EmptyState
          title="통제 원장이 아직 없습니다"
          description="APK 또는 IPA를 등록하거나 기존 앱을 재분석하면 플랫폼별 MASTG 기준선이 만들어집니다."
        />
      )}
    </div>
  );
}

function groupControls(tests: ControlTest[]): Array<[string, ControlTest[]]> {
  const values = new Map<string, ControlTest[]>();
  for (const test of tests) {
    const group = test.masvs_id || "MASVS-OTHER";
    values.set(group, [...(values.get(group) ?? []), test]);
  }
  return [...values.entries()];
}

function CoverageMetric({
  label,
  value,
  tone,
}: {
  label: string;
  value: number;
  tone: string;
}) {
  return (
    <div className={`coverage-metric coverage-metric--${tone}`}>
      <i />
      <strong>{value}</strong>
      <span>{label}</span>
    </div>
  );
}

function ControlRow({ test }: { test: ControlTest }) {
  return (
    <article className="control-row">
      <div>
        <code>{test.mastg_id}</code>
        {test.replacement_ids.length > 0 && (
          <small>→ {test.replacement_ids.join(", ")}</small>
        )}
      </div>
      <div>
        <a href={test.source_url} target="_blank" rel="noreferrer">{test.title}</a>
        <small>{test.automation.toUpperCase()} · {test.summary}</small>
      </div>
      <StatusChip value={test.status} />
      <StatusChip value={test.result} />
    </article>
  );
}
