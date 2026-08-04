import { useEffect, useMemo, useRef, useState } from "react";
import { Link, useParams } from "../router";
import { api, post, runWebSocket } from "../api";
import type {
  DiagnosticRun,
  Evidence,
  Finding,
  LiveEvent,
  ProxyFlow,
} from "../types";
import { EmptyState, StatusChip, formatDate } from "../components/UI";

const stageLabels: Record<string, string> = {
  preflight: "사전 확인",
  static_analysis: "정적 분석",
  install: "앱 설치",
  launch_baseline: "원본 실행",
  security_control_validation: "보안통제 우회 내성 검증",
  frida: "Frida 적용",
  manual_interaction: "수동 조작",
  network_dynamic: "동적·네트워크",
  ai_analysis: "AI 판정",
  finalize: "증적 정리",
  completed: "완료",
  failed: "실패",
};

export default function LiveRunPage() {
  const { runId = "" } = useParams();
  const [run, setRun] = useState<DiagnosticRun | null>(null);
  const [evidence, setEvidence] = useState<Evidence[]>([]);
  const [flows, setFlows] = useState<ProxyFlow[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [events, setEvents] = useState<LiveEvent[]>([]);
  const [connected, setConnected] = useState(false);
  const [actionBusy, setActionBusy] = useState("");
  const wsRef = useRef<WebSocket | null>(null);

  async function refresh() {
    const current = await api<DiagnosticRun>(`/runs/${runId}`);
    setRun(current);
    const [evidenceItems, flowItems, findingItems] = await Promise.all([
      api<Evidence[]>(`/runs/${runId}/evidence`),
      api<ProxyFlow[]>(`/runs/${runId}/flows`),
      api<Finding[]>(`/findings?run_id=${runId}`),
    ]);
    setEvidence(evidenceItems);
    setFlows(flowItems);
    setFindings(findingItems);
  }

  useEffect(() => {
    void refresh();
    const socket = runWebSocket(runId);
    wsRef.current = socket;
    socket.onopen = () => setConnected(true);
    socket.onclose = () => setConnected(false);
    socket.onmessage = (message) => {
      const event = JSON.parse(message.data) as LiveEvent;
      setEvents((items) => [...items.slice(-119), event]);
      if (["stage", "run_status", "evidence", "proxy_flow", "finding"].includes(event.type)) {
        void refresh();
      }
    };
    const poll = window.setInterval(() => void refresh(), 2500);
    return () => {
      window.clearInterval(poll);
      socket.close();
    };
  }, [runId]);

  async function control(action: "pause" | "resume" | "stop") {
    setActionBusy(action);
    try {
      await post(`/runs/${runId}/${action}`);
      await refresh();
    } finally {
      setActionBusy("");
    }
  }

  const screenshot = useMemo(
    () => [...evidence].reverse().find((item) => item.evidence_type === "screenshot"),
    [evidence],
  );
  const fridaEvents = events.filter((event) => event.type === "frida_log");
  const aiEvents = events.filter((event) => event.type === "ai_status");
  const stageEvents = events.filter((event) => event.type === "stage");

  if (!run) {
    return <div className="loading-block">진단 실행을 불러오는 중…</div>;
  }

  return (
    <div className="live-workbench">
      <header className="live-header">
        <div>
          <div className="live-header__line">
            <span className={`connection-led ${connected ? "connection-led--on" : ""}`} />
            {connected ? "실시간 채널 연결" : "재연결 대기"} · {run.synthetic ? "SYNTHETIC MOCK" : "LIVE"} · RUN {run.id.slice(0, 8)}
          </div>
          <h2>{stageLabels[run.current_stage] ?? run.current_stage}</h2>
        </div>
        <div className="live-progress">
          <div><i style={{ width: `${run.progress}%` }} /></div>
          <strong>{run.progress}%</strong>
          <StatusChip value={run.status} />
        </div>
        <div className="live-controls">
          {run.status === "paused" ? (
            <button className="button button--signal" onClick={() => void control("resume")} disabled={Boolean(actionBusy)}>재개</button>
          ) : (
            <button className="button button--quiet" onClick={() => void control("pause")} disabled={run.status !== "running" || Boolean(actionBusy)}>일시정지</button>
          )}
          <button className="button button--quiet" onClick={() => void control("pause")} disabled={run.status !== "running"}>수동 조작 전환</button>
          <button className="button button--danger" onClick={() => void control("stop")} disabled={!["running", "paused"].includes(run.status)}>중지</button>
        </div>
      </header>

      {run.error && <div className="inline-alert">{run.error}</div>}

      <div className="live-grid">
        <section className="console-panel device-console">
          <div className="console-head"><span>DEVICE VIEW</span><small>{run.device_id}</small></div>
          <div className="phone-stage">
            <div className="phone-frame">
              <div className="phone-frame__speaker" />
              {screenshot ? (
                <img src={`/api/evidence/${screenshot.id}/download`} alt={screenshot.title} />
              ) : (
                <div className="phone-empty">
                  <span />
                  <strong>화면 대기</strong>
                  <small>첫 캡처가 생성되면 표시됩니다.</small>
                </div>
              )}
            </div>
          </div>
          <div className="capture-caption">
            <span>LAST CAPTURE</span>
            <strong>{screenshot?.title ?? "아직 없음"}</strong>
            <small>{formatDate(screenshot?.captured_at)}</small>
          </div>
        </section>

        <section className="console-panel stage-console">
          <div className="console-head"><span>DIAGNOSTIC SEQUENCE</span><small>{stageEvents.length} transitions</small></div>
          <div className="stage-rail">
            {[
              "preflight",
              "static_analysis",
              "install",
              "launch_baseline",
              "security_control_validation",
              "frida",
              "network_dynamic",
              "ai_analysis",
              "finalize",
            ].map((stage, index) => {
              const stageProgress = [4, 12, 22, 32, 44, 56, 70, 84, 96][index];
              const done = run.progress >= stageProgress;
              const current = run.current_stage === stage;
              return (
                <div className={`stage-node ${done ? "stage-node--done" : ""} ${current ? "stage-node--current" : ""}`} key={stage}>
                  <div className="stage-node__mark"><span>{done ? "✓" : index + 1}</span></div>
                  <div><strong>{stageLabels[stage]}</strong><small>{current ? "현재 실행 중" : done ? "증적 기록됨" : "대기"}</small></div>
                </div>
              );
            })}
          </div>
        </section>

        <section className="console-panel log-console">
          <div className="console-head"><span>FRIDA STREAM</span><small>{fridaEvents.length} sessions</small></div>
          <div className="terminal-stream">
            {fridaEvents.length ? fridaEvents.flatMap((event) => {
              const messages = Array.isArray(event.data.messages) ? event.data.messages : [];
              return messages.map((message, index) => (
                <div className="terminal-line" key={`${event.timestamp}-${index}`}>
                  <span>{formatDate(event.timestamp)}</span>
                  <code>{JSON.stringify(message)}</code>
                </div>
              ));
            }) : (
              <div className="terminal-empty">$ Frida 메시지를 기다리는 중<span className="terminal-cursor" /></div>
            )}
          </div>
        </section>

        <section className="console-panel packet-console">
          <div className="console-head"><span>PROXY TRAFFIC</span><small>{flows.length} flows</small></div>
          {run.proxy_adapter === "mitmproxy" && (
            <div className="proxy-boundary">
              <span>LISTENER</span>
              <strong>{String(run.options.proxy_listen_host ?? "—")}:{String(run.options.proxy_port ?? "dynamic")}</strong>
              <span>ALLOWED DEVICE</span>
              <strong>{String(run.options.proxy_allowed_client_ip ?? "—")}</strong>
            </div>
          )}
          <div className="packet-list">
            {flows.length ? flows.map((flow) => (
              <details className="packet-row" key={flow.id}>
                <summary>
                  <span className={`method method--${flow.method.toLowerCase()}`}>{flow.method}</span>
                  <strong>{safeUrl(flow.url)}</strong>
                  <span className="http-status">{flow.status_code ?? "—"}</span>
                  {flow.sensitive_candidates.length > 0 && <i>{flow.sensitive_candidates.length} signal</i>}
                </summary>
                <pre>{JSON.stringify({
                  request: { headers: flow.request_headers, body: flow.request_body },
                  response: { status: flow.status_code, headers: flow.response_headers, body: flow.response_body },
                  source_ip: flow.source_ip,
                  sensitive_candidates: flow.sensitive_candidates,
                }, null, 2)}</pre>
              </details>
            )) : <div className="console-empty">캡처된 HTTP 흐름이 없습니다.</div>}
          </div>
        </section>

        <section className="console-panel ai-console">
          <div className="console-head"><span>AI DECISION</span><small>{aiEvents.length} attempts</small></div>
          <div className="ai-state">
            {aiEvents.length ? aiEvents.map((event, index) => (
              <div className="ai-attempt" key={`${event.timestamp}-${index}`}>
                <span className="ai-attempt__index">{String(index + 1).padStart(2, "0")}</span>
                <div>
                  <strong>{String(event.data.provider ?? "policy")}</strong>
                  <small>{String(event.data.model ?? "")}</small>
                  <p>{String(event.data.message ?? "")}</p>
                </div>
                <StatusChip value={String(event.data.status ?? "unknown")} />
              </div>
            )) : (
              <div className="ai-wait">
                <div className="ai-wait__orbit"><i /><i /><i /></div>
                <strong>증적 범위를 구성하는 중</strong>
                <small>정적 신호, 로그, 패킷이 준비된 뒤 AI 정책을 적용합니다.</small>
              </div>
            )}
          </div>
        </section>

        <section className="console-panel finding-console">
          <div className="console-head"><span>FINDINGS</span><small>{findings.length} classified</small></div>
          {findings.length ? (
            <div className="live-findings">
              {findings.map((finding) => (
                <Link to={`/findings/${finding.id}`} key={finding.id}>
                  <span className={`severity-pip severity-pip--${finding.severity}`} />
                  <div><strong>{finding.title}</strong><small>{finding.category} · {Math.round(finding.confidence * 100)}%</small></div>
                  <span>→</span>
                </Link>
              ))}
            </div>
          ) : (
            <div className="console-empty">판정된 발견항목이 아직 없습니다.</div>
          )}
          <div className="evidence-counter">
            <span>연결된 증적</span>
            <strong>{evidence.length}</strong>
          </div>
        </section>
      </div>
    </div>
  );
}

function safeUrl(value: string) {
  try {
    const url = new URL(value);
    return `${url.host}${url.pathname}`;
  } catch {
    return value;
  }
}
