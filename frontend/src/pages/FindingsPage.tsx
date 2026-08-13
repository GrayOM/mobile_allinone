import { useEffect, useMemo, useState } from "react";
import { Link } from "../router";
import { api } from "../api";
import type { Finding, Project } from "../types";
import { EmptyState, SectionHeading, StatusChip, formatDate } from "../components/UI";
import { findingEvidenceLabel, findingLane, findingLaneLabel } from "../findingPresentation";

export default function FindingsPage() {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [projects, setProjects] = useState<Project[]>([]);
  const [projectId, setProjectId] = useState("");
  const [severity, setSeverity] = useState("");
  const [verdict, setVerdict] = useState("");
  const [lane, setLane] = useState("");

  useEffect(() => {
    void Promise.all([api<Finding[]>("/findings"), api<Project[]>("/projects")]).then(
      ([findingItems, projectItems]) => {
        setFindings(findingItems);
        setProjects(projectItems);
      },
    );
  }, []);

  const filtered = useMemo(
    () =>
      findings.filter(
        (item) =>
          (!projectId || item.project_id === projectId) &&
          (!severity || item.severity === severity) &&
          (!verdict || item.verdict === verdict) &&
          (!lane || findingLane(item) === lane),
      ),
    [findings, projectId, severity, verdict, lane],
  );
  const highCount = filtered.filter((item) => item.severity === "high").length;
  const reviewCount = filtered.filter((item) => item.verdict === "needs_review").length;
  const controlCount = filtered.filter((item) => findingLane(item) === "security_control").length;

  return (
    <div className="stack stack--lg">
      <SectionHeading
        eyebrow="FINDING REGISTER"
        title="신호와 판정을 분리해서 봅니다"
        description="앱 취약점과 모바일 보안통제 신호를 분리하고, 정적 후보부터 실제 단말 재현까지 같은 원장에서 추적합니다."
      />
      <section className="result-guide panel" aria-labelledby="result-guide-title">
        <div>
          <span className="eyebrow">HOW TO READ RESULTS</span>
          <h2 id="result-guide-title">결과는 우선순위와 근거를 함께 보세요</h2>
          <p>심각도는 먼저 확인할 순서이고, 증적 상태는 현재 결론의 범위를 뜻합니다. 보안통제 문자열은 취약점으로 세지 않고 실제 단말에서 탐지·차단 동작을 별도로 검증합니다.</p>
        </div>
        <div className="result-guide__metrics">
          <div><span>우선 확인</span><strong>{highCount}</strong><small>High 심각도</small></div>
          <div><span>사람 검토</span><strong>{reviewCount}</strong><small>증거 보강 필요</small></div>
          <div><span>솔루션 분석</span><strong>{controlCount}</strong><small>보안통제 신호</small></div>
        </div>
        <div className="button-row">
          <button className="button button--quiet" type="button" onClick={() => setVerdict("needs_review")}>검토 필요한 항목만 보기</button>
          {verdict && <button className="button button--quiet" type="button" onClick={() => setVerdict("")}>판정 필터 해제</button>}
        </div>
      </section>
      <div className="filter-bar">
        <div className="field field--compact">
          <label htmlFor="finding-project">프로젝트</label>
          <select id="finding-project" value={projectId} onChange={(event) => setProjectId(event.target.value)}>
            <option value="">전체 프로젝트</option>
            {projects.map((item) => <option key={item.id} value={item.id}>{item.name}</option>)}
          </select>
        </div>
        <div className="field field--compact">
          <label htmlFor="finding-severity">심각도</label>
          <select id="finding-severity" value={severity} onChange={(event) => setSeverity(event.target.value)}>
            <option value="">전체 심각도</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="info">Info</option>
          </select>
        </div>
        <div className="field field--compact">
          <label htmlFor="finding-lane">분석 구분</label>
          <select id="finding-lane" value={lane} onChange={(event) => setLane(event.target.value)}>
            <option value="">전체 구분</option>
            <option value="vulnerability">앱 취약점</option>
            <option value="security_control">모바일 보안통제</option>
          </select>
        </div>
        <div className="field field--compact">
          <label htmlFor="finding-verdict">판정 상태</label>
          <select id="finding-verdict" value={verdict} onChange={(event) => setVerdict(event.target.value)}>
            <option value="">전체 판정</option>
            <option value="confirmed">확인됨</option>
            <option value="needs_review">검토 필요</option>
            <option value="informational">참고</option>
            <option value="unknown">미확인</option>
          </select>
        </div>
        <span className="filter-result">{filtered.length}개 항목</span>
      </div>
      {filtered.length ? (
        <div className="finding-table">
          <div className="finding-table__head">
            <span>심각도</span><span>발견항목</span><span>판정</span><span>근거</span><span>시점</span>
          </div>
          {filtered.map((finding) => (
            <Link to={`/findings/${finding.id}`} className="finding-table__row" key={finding.id}>
              <span className={`severity-label severity-label--${finding.severity}`}>{finding.severity}</span>
              <div>
                <strong>{finding.title}</strong>
                <small>{findingLaneLabel(finding)} · {finding.category.replaceAll("_", " ")} · {finding.platform}{finding.synthetic ? " · SYNTHETIC" : ""}</small>
              </div>
              <div title={findingEvidenceLabel(finding)}><StatusChip value={finding.verdict} /><small>{findingEvidenceLabel(finding)}</small></div>
              <div className="confidence">
                <span><i style={{ width: `${finding.confidence * 100}%` }} /></span>
                <strong>{Math.round(finding.confidence * 100)}%</strong>
              </div>
              <span>{formatDate(finding.created_at)}</span>
            </Link>
          ))}
        </div>
      ) : (
        <EmptyState title="조건에 맞는 발견항목이 없습니다" description="정적 분석 또는 진단 실행 후 판정 결과가 표시됩니다." />
      )}
    </div>
  );
}
