import { useEffect, useState } from "react";
import { api } from "../api";
import type { ControlGuidance } from "../types";

function GuidanceList({ title, items, limit = 12 }: { title: string; items: string[]; limit?: number }) {
  const [expanded, setExpanded] = useState(false);
  if (!items.length) return null;
  const visible = expanded ? items : items.slice(0, limit);
  return (
    <div className="guidance-block">
      <span>{title}</span>
      <ul>{visible.map((item, index) => <li key={`${index}-${item.slice(0, 24)}`}>{item}</li>)}</ul>
      {items.length > limit && (
        <button type="button" className="button button--quiet button--small" onClick={() => setExpanded((value) => !value)}>
          {expanded ? "접기" : `${items.length - limit}줄 더 보기`}
        </button>
      )}
    </div>
  );
}

export function ControlGuidancePanel({
  standard,
  controlId,
  projectId,
  platform,
}: {
  standard: string;
  controlId: string;
  projectId: string;
  platform: string;
}) {
  const [guidance, setGuidance] = useState<ControlGuidance | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    setGuidance(null);
    setError("");
    const query = controlId.startsWith("CUS-MA-") ? `?project_id=${encodeURIComponent(projectId)}` : "";
    void api<ControlGuidance>(`/assessment/guidance/${standard}/${controlId}${query}`)
      .then(setGuidance)
      .catch((reason: Error) => setError(reason.message));
  }, [standard, controlId, projectId]);

  if (error) return <p className="guidance-panel__error">{error}</p>;
  if (!guidance) return <p className="guidance-panel__loading">보안 권고안 지침을 불러오는 중…</p>;
  const platformKey = platform.endsWith("ios") ? "ios" : "android";
  const examples = Object.entries(guidance.remediation_examples).filter(([name]) =>
    name.toLowerCase().includes(platformKey),
  );
  return (
    <div className="guidance-panel">
      <header>
        <code>{guidance.control_id}</code>
        <strong>{guidance.custom ? "기준 외 예외 검사 정의" : "보안 권고안 원문 기준"}</strong>
        {guidance.custom && guidance.recorded_by && <small>등록 {guidance.recorded_by}</small>}
      </header>
      <GuidanceList title={guidance.custom ? "추가 사유" : "취약점 설명"} items={guidance.description} />
      <GuidanceList title="위협 요소" items={guidance.threats} />
      <GuidanceList title={guidance.custom ? "취약 판정 기준" : "진단 기준"} items={guidance.diagnostic_criteria} />
      <GuidanceList title={guidance.custom ? "점검 절차" : "진단 예시"} items={guidance.diagnostic_examples} limit={8} />
      <GuidanceList title="조치 방안" items={guidance.remediation} />
      {examples.map(([name, items]) => (
        <GuidanceList key={name} title={name} items={items} limit={6} />
      ))}
      {guidance.reference && <p className="guidance-panel__reference">참조 · {guidance.reference}</p>}
    </div>
  );
}
