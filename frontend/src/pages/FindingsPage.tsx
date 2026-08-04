import { useEffect, useMemo, useState } from "react";
import { Link } from "../router";
import { api } from "../api";
import type { Finding, Project } from "../types";
import { EmptyState, SectionHeading, StatusChip, formatDate } from "../components/UI";

export default function FindingsPage() {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [projects, setProjects] = useState<Project[]>([]);
  const [projectId, setProjectId] = useState("");
  const [severity, setSeverity] = useState("");

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
          (!severity || item.severity === severity),
      ),
    [findings, projectId, severity],
  );

  return (
    <div className="stack stack--lg">
      <SectionHeading
        eyebrow="FINDING REGISTER"
        title="신호와 판정을 분리해서 봅니다"
        description="정적 시그니처는 런타임 증적 없이 확정하지 않으며, 자동 판정의 근거와 오탐 가능성을 함께 표시합니다."
      />
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
                <small>{finding.category.replaceAll("_", " ")} · {finding.platform}{finding.synthetic ? " · SYNTHETIC" : ""}</small>
              </div>
              <StatusChip value={finding.verdict} />
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
