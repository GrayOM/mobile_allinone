import { useEffect, useState } from "react";
import { Link, useParams } from "../router";
import { api, post } from "../api";
import type { Evidence, Finding, FindingSource } from "../types";
import { EmptyState, StatusChip, formatDate } from "../components/UI";

export default function FindingDetailPage() {
  const { findingId = "" } = useParams();
  const [finding, setFinding] = useState<Finding | null>(null);
  const [evidence, setEvidence] = useState<Evidence[]>([]);
  const [sources, setSources] = useState<FindingSource[]>([]);
  const [reporting, setReporting] = useState(false);

  useEffect(() => {
    void api<Finding>(`/findings/${findingId}`).then(async (item) => {
      setFinding(item);
      setSources(await api<FindingSource[]>(`/findings/${findingId}/sources`));
      if (item.run_id) setEvidence(await api<Evidence[]>(`/runs/${item.run_id}/evidence`));
    });
  }, [findingId]);

  async function openReport() {
    setReporting(true);
    try {
      await post(`/findings/${findingId}/report`);
      window.open(`/api/findings/${findingId}/report`, "_blank", "noopener,noreferrer");
    } finally {
      setReporting(false);
    }
  }

  if (!finding) return <div className="loading-block">발견항목을 불러오는 중…</div>;

  return (
    <div className="finding-detail stack stack--lg">
      <div className="detail-breadcrumb"><Link to="/findings">발견항목</Link><span>/</span>{finding.id.slice(0, 8)}</div>
      <header className="finding-title">
        <div className={`finding-title__severity finding-title__severity--${finding.severity}`}>
          <span>{finding.severity}</span>
        </div>
        <div>
          <span className="eyebrow">{finding.category.replaceAll("_", " ")} · {finding.platform}</span>
          <h2>{finding.title}</h2>
          <div className="chip-row">
            <StatusChip value={finding.verdict} />
            <span className="plain-chip">{finding.source}</span>
            <span className="plain-chip">{formatDate(finding.created_at)}</span>
          </div>
        </div>
        <button className="button button--signal" onClick={() => void openReport()} disabled={reporting}>
          {reporting ? "생성 중…" : "HTML 증적 설명서"}
        </button>
      </header>

      <div className="finding-facts">
        <section>
          <span className="eyebrow">AUTOMATED VERDICT</span>
          <div className="confidence-dial" style={{ "--score": `${finding.confidence * 360}deg` } as React.CSSProperties}>
            <div><strong>{Math.round(finding.confidence * 100)}</strong><small>%</small></div>
          </div>
          <p>{finding.verdict}</p>
        </section>
        <section>
          <span className="eyebrow">RATIONALE</span>
          <h3>판정 근거</h3>
          <p>{finding.rationale}</p>
          <dl>
            <div><dt>발견 위치</dt><dd>{finding.location || "미지정"}</dd></div>
            <div><dt>오탐 가능성</dt><dd>{finding.false_positive_risk || "별도 정보 없음"}</dd></div>
          </dl>
        </section>
        <section>
          <span className="eyebrow">REPRODUCTION</span>
          <h3>재현 순서</h3>
          <ol className="reproduction-list">
            {finding.reproduction.length ? finding.reproduction.map((item, index) => (
              <li key={item}><span>{index + 1}</span>{item}</li>
            )) : <li><span>!</span>런타임 재현 순서가 아직 없습니다.</li>}
          </ol>
        </section>
      </div>

      {sources.length > 0 && (
        <section className="source-ledger panel">
          <div>
            <span className="eyebrow">CORRELATED PROVENANCE</span>
            <h2>도구별 원시 탐지 출처</h2>
            <p>동일 코드 위치와 보안 범주를 기준으로 묶었으며 원시 fingerprint는 그대로 보존합니다.</p>
          </div>
          <div className="source-ledger__rows">
            {sources.map((source) => (
              <article key={source.id}>
                <strong>{source.source_tool}</strong>
                <code>{source.source_rule_id}</code>
                <span>{source.fingerprint.slice(0, 16)}…</span>
              </article>
            ))}
          </div>
        </section>
      )}

      <section>
        <div className="section-heading">
          <div>
            <span className="eyebrow">EVIDENCE TIMELINE</span>
            <h2>발생 순서와 원본</h2>
            <p>각 단계의 화면, 명령, 스크립트, 패킷과 로그를 수집 시각대로 표시합니다.</p>
          </div>
          {finding.run_id && <Link to={`/runs/${finding.run_id}`}>실시간 실행 보기 →</Link>}
        </div>
        {evidence.length ? (
          <div className="evidence-timeline">
            {evidence.map((item) => (
              <article className="evidence-item" key={item.id}>
                <div className="evidence-item__index">{String(item.sequence).padStart(2, "0")}</div>
                <div className="evidence-item__card">
                  <div className="evidence-item__meta">
                    <span>{item.evidence_type.replaceAll("_", " ")}</span>
                    <time>{formatDate(item.captured_at)}</time>
                  </div>
                  <h3>{item.title}</h3>
                  {item.description && <p>{item.description}</p>}
                  {item.mime_type?.startsWith("image/") && (
                    <img src={`/api/evidence/${item.id}/download`} alt={item.title} />
                  )}
                  {item.command && <pre className="code-view">{item.command}</pre>}
                  {item.inline_data && (
                    <details className="raw-details">
                      <summary>구조화된 원본 보기</summary>
                      <pre className="code-view">{JSON.stringify(item.inline_data, null, 2)}</pre>
                    </details>
                  )}
                  {item.file_path && (
                    <a className="download-link" href={`/api/evidence/${item.id}/download`}>
                      원본 내려받기 <span>SHA {item.sha256?.slice(0, 12)}…</span>
                    </a>
                  )}
                </div>
              </article>
            ))}
          </div>
        ) : (
          <EmptyState title="연결된 실행 증적이 없습니다" description="이 항목은 정적 분석에서 생성되었습니다. 진단 실행 후 동적 증적을 연결할 수 있습니다." />
        )}
      </section>
    </div>
  );
}
