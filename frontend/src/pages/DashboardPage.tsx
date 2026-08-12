import { useEffect, useState } from "react";
import { Link, useNavigate } from "../router";
import { api, post } from "../api";
import type { AppArtifact, DashboardData, Project } from "../types";
import { EmptyState, SectionHeading, StatusChip, formatDate } from "../components/UI";

type DemoResponse = { project: Project; app: AppArtifact; next: string };

export default function DashboardPage() {
  const [data, setData] = useState<DashboardData | null>(null);
  const [loading, setLoading] = useState(true);
  const [demoLoading, setDemoLoading] = useState(false);
  const [error, setError] = useState("");
  const navigate = useNavigate();

  const load = () =>
    api<DashboardData>("/dashboard")
      .then(setData)
      .catch((reason: Error) => setError(reason.message))
      .finally(() => setLoading(false));

  useEffect(() => {
    void load();
  }, []);

  async function makeDemo() {
    setDemoLoading(true);
    setError("");
    try {
      const result = await post<DemoResponse>("/demo/bootstrap");
      localStorage.setItem("msw.project", result.project.id);
      localStorage.setItem("msw.app", result.app.id);
      localStorage.setItem("msw.device", "mock-android-01");
      localStorage.setItem("msw.deviceAdapter", "mock");
      navigate("/diagnostics/new");
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "데모 생성 실패");
    } finally {
      setDemoLoading(false);
    }
  }

  return (
    <div className="stack stack--xl">
      <section className="command-hero">
        <div className="command-hero__copy">
          <span className="eyebrow eyebrow--light">EVIDENCE-FIRST WORKSPACE</span>
          <h2>한 번의 실행을<br />검증 가능한 증적으로.</h2>
          <p>
            앱 구조, 단말 동작, Frida 메시지와 HTTP 흐름을 시간순으로
            연결합니다. 자동화할 수 없는 단계는 숨기지 않고 정확한 상태로 남깁니다.
          </p>
          <div className="button-row">
            <button className="button button--signal" onClick={makeDemo} disabled={demoLoading}>
              {demoLoading ? "데모 준비 중…" : "Mock 전체 데모 시작"}
            </button>
            <Link className="button button--ghost-light" to="/projects">
              APK·IPA 등록
            </Link>
          </div>
          {error && <div className="inline-alert inline-alert--dark">{error}</div>}
        </div>
        <div className="run-map" aria-label="진단 단계">
          <div className="run-map__beam" />
          {[
            ["01", "STATIC", "구조·코드"],
            ["02", "DEVICE", "실행·로그"],
            ["03", "RUNTIME", "Frida·프록시"],
            ["04", "EVIDENCE", "판정·설명서"],
          ].map(([number, label, sub], index) => (
            <div className="run-map__step" key={number}>
              <span>{number}</span>
              <div>
                <strong>{label}</strong>
                <small>{sub}</small>
              </div>
              {index < 3 && <i />}
            </div>
          ))}
        </div>
      </section>

      {!loading && (data?.counts.runs ?? 0) === 0 && (
        <section className="getting-started panel" aria-labelledby="getting-started-title">
          <div className="getting-started__head">
            <div>
              <span className="eyebrow">GUIDED FIRST RUN</span>
              <h2 id="getting-started-title">처음이라면 이 순서로 시작하세요</h2>
              <p>실제 앱이나 단말을 바로 연결하지 않아도 됩니다. 먼저 합성 데모로 결과 화면과 승인 절차를 익힌 뒤, 권한을 받은 앱·단말만 Live 진단에 연결하세요.</p>
            </div>
            <span className="guide-time">약 3분</span>
          </div>
          <ol className="getting-started__steps">
            <li><span>1</span><div><strong>Mock 데모 실행</strong><small>실제 단말·외부 AI 전송 없이 전체 과정을 안전하게 체험합니다.</small></div></li>
            <li><span>2</span><div><strong>결과와 증적 확인</strong><small>발견항목이 어떤 근거로 분류됐는지와 보류된 작업을 확인합니다.</small></div></li>
            <li><span>3</span><div><strong>실제 진단 준비</strong><small>승인받은 APK·IPA와 단말을 선택하고, 안내형 진단 설정에서 범위를 확인합니다.</small></div></li>
          </ol>
          <div className="button-row">
            <button className="button button--signal" onClick={makeDemo} disabled={demoLoading}>
              {demoLoading ? "데모 준비 중…" : "안전한 Mock 데모로 연습"}
            </button>
            <Link className="button button--quiet" to="/diagnostics/new">이미 준비됨 · 진단 설정으로</Link>
          </div>
        </section>
      )}

      <section className="metric-strip" aria-label="누적 현황">
        {[
          ["프로젝트", data?.counts.projects ?? 0, "P"],
          ["진단 실행", data?.counts.runs ?? 0, "R"],
          ["발견항목", data?.counts.findings ?? 0, "F"],
          ["증적 원본", data?.counts.evidence ?? 0, "E"],
        ].map(([label, value, mark]) => (
          <div className="metric" key={String(label)}>
            <span className="metric__mark">{mark}</span>
            <div>
              <strong>{loading ? "—" : value}</strong>
              <small>{label}</small>
            </div>
          </div>
        ))}
      </section>

      <div className="dashboard-grid">
        <section className="panel">
          <SectionHeading
            eyebrow="RECENT RUNS"
            title="최근 진단"
            action={<Link to="/diagnostics/new">새 진단 →</Link>}
          />
          {data?.recent_runs.length ? (
            <div className="list-rows">
              {data.recent_runs.map((run) => (
                <Link to={`/runs/${run.id}`} className="list-row" key={run.id}>
                  <div className="list-row__lead">
                    <span className="mono-id">{run.id.slice(0, 7)}</span>
                    <div>
                      <strong>{run.current_stage.replaceAll("_", " ")}</strong>
                      <small>{run.device_id} · {formatDate(run.created_at)}</small>
                    </div>
                  </div>
                  <div className="list-row__trail">
                    <StatusChip value={run.status} />
                    <span className="progress-number">{run.progress}%</span>
                  </div>
                </Link>
              ))}
            </div>
          ) : (
            <EmptyState
              title="아직 실행 기록이 없습니다"
              description="Mock 데모를 시작하면 설치부터 증적 생성까지 전 과정을 확인할 수 있습니다."
            />
          )}
        </section>

        <section className="panel">
          <SectionHeading
            eyebrow="LATEST SIGNALS"
            title="최근 발견항목"
            action={<Link to="/findings">전체 보기 →</Link>}
          />
          {data?.recent_findings.length ? (
            <div className="finding-stack">
              {data.recent_findings.map((finding) => (
                <Link to={`/findings/${finding.id}`} className="finding-mini" key={finding.id}>
                  <div className={`severity-bar severity-bar--${finding.severity}`} />
                  <div>
                    <span>{finding.category.replaceAll("_", " ")}</span>
                    <strong>{finding.title}</strong>
                    <small>{Math.round(finding.confidence * 100)}% confidence · {finding.source}</small>
                  </div>
                </Link>
              ))}
            </div>
          ) : (
            <EmptyState
              title="분류된 신호가 없습니다"
              description="앱을 등록하면 정적 분석 신호가 이곳에 표시됩니다."
            />
          )}
        </section>
      </div>
    </div>
  );
}
