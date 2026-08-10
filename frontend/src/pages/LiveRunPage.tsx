import { useEffect, useMemo, useRef, useState } from "react";
import { Link, useParams } from "../router";
import { api, post, runWebSocket, upload } from "../api";
import type {
  DiagnosticRun,
  Evidence,
  Finding,
  FridaHealth,
  LiveEvent,
  NetworkTestingSummary,
  NavigationSummary,
  ProxyFlow,
  StorageSummary,
} from "../types";
import { EmptyState, StatusChip, formatDate } from "../components/UI";
import { AuthenticatedImage } from "../components/AuthenticatedFile";

const stageLabels: Record<string, string> = {
  preflight: "사전 확인",
  static_analysis: "정적 분석",
  install: "앱 설치",
  launch_baseline: "원본 실행",
  security_control_validation: "보안통제 우회 내성 검증",
  frida: "Frida 적용",
  navigation: "안전 UI 자동 탐색",
  dynamic_storage_before: "조작 전 앱 저장소",
  dynamic_storage: "앱 저장소 변화 분석",
  manual_interaction: "수동 조작",
  proxy_manual_setup: "수동 프록시 준비",
  proxy_capture_import: "최종 프록시 캡처 가져오기",
  network_dynamic: "동적·네트워크",
  network_testing: "API Candidate 판정",
  ai_analysis: "AI 판정",
  finalize: "증적 정리",
  completed: "완료",
  completed_with_gaps: "일부 범위 미완료",
  manual_required: "수동 확인 필요",
  failed: "실패",
  stopped: "중지됨",
  interrupted: "중단됨",
};

export default function LiveRunPage() {
  const { runId = "" } = useParams();
  const [run, setRun] = useState<DiagnosticRun | null>(null);
  const [evidence, setEvidence] = useState<Evidence[]>([]);
  const [flows, setFlows] = useState<ProxyFlow[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [events, setEvents] = useState<LiveEvent[]>([]);
  const [fridaHealth, setFridaHealth] = useState<FridaHealth | null>(null);
  const [connected, setConnected] = useState(false);
  const [actionBusy, setActionBusy] = useState("");
  const [proxyImporting, setProxyImporting] = useState(0);
  const [actionError, setActionError] = useState("");
  const wsRef = useRef<WebSocket | null>(null);

  async function refresh() {
    const current = await api<DiagnosticRun>(`/runs/${runId}`);
    setRun(current);
    const [evidenceItems, flowItems, findingItems, health] = await Promise.all([
      api<Evidence[]>(`/runs/${runId}/evidence`),
      api<ProxyFlow[]>(`/runs/${runId}/flows`),
      api<Finding[]>(`/findings?run_id=${runId}`),
      api<FridaHealth>(`/runs/${runId}/frida/health`),
    ]);
    setEvidence(evidenceItems);
    setFlows(flowItems);
    setFindings(findingItems);
    setFridaHealth(health);
  }

  useEffect(() => {
    let disposed = false;
    void refresh();
    void runWebSocket(runId).then((socket) => {
      if (disposed) {
        socket.close();
        return;
      }
      wsRef.current = socket;
      socket.onopen = () => setConnected(true);
      socket.onclose = () => setConnected(false);
      socket.onmessage = (message) => {
        const event = JSON.parse(message.data) as LiveEvent;
        setEvents((items) => [...items.slice(-119), event]);
        if (event.type === "frida_health") {
          setFridaHealth(event.data as unknown as FridaHealth);
        } else if (event.type === "frida_log" && event.data.health) {
          setFridaHealth(event.data.health as FridaHealth);
        }
        if (["stage", "run_status", "evidence", "proxy_flow", "finding"].includes(event.type)) {
          void refresh();
        }
      };
    }).catch((reason: Error) => {
      if (!disposed) setActionError(reason.message);
    });
    const poll = window.setInterval(() => void refresh(), 2500);
    return () => {
      disposed = true;
      window.clearInterval(poll);
      wsRef.current?.close();
    };
  }, [runId]);

  async function control(action: "pause" | "resume" | "stop") {
    setActionBusy(action);
    try {
      setActionError("");
      await post(`/runs/${runId}/${action}`);
      await refresh();
    } catch (reason) {
      setActionError(reason instanceof Error ? reason.message : "진단 상태 변경 실패");
    } finally {
      setActionBusy("");
    }
  }

  async function importProxyCapture(file?: File) {
    if (!file) return;
    setActionError("");
    try {
      await upload<Record<string, unknown>>(`/runs/${runId}/proxy/import`, file, setProxyImporting);
      await refresh();
    } catch (reason) {
      setActionError(reason instanceof Error ? reason.message : "프록시 파일 Import 실패");
    } finally {
      setProxyImporting(0);
    }
  }

  async function confirmProxySetup() {
    setActionBusy("proxy-setup");
    setActionError("");
    try {
      await post(`/runs/${runId}/proxy/confirm-setup`);
      await refresh();
    } catch (reason) {
      setActionError(reason instanceof Error ? reason.message : "프록시 설정 확인 실패");
    } finally {
      setActionBusy("");
    }
  }

  const screenshot = useMemo(
    () => [...evidence].reverse().find((item) => item.evidence_type === "screenshot"),
    [evidence],
  );
  const fridaEvents = events.filter((event) => event.type === "frida_log");
  const fridaMessages = fridaEvents.flatMap((event) => {
    const messages = Array.isArray(event.data.messages) ? event.data.messages : [];
    return messages.map((message) => ({ message, timestamp: event.timestamp }));
  });
  const aiEvents = events.filter((event) => event.type === "ai_status");
  const stageEvents = events.filter((event) => event.type === "stage");
  if (!run) {
    return <div className="loading-block">진단 실행을 불러오는 중…</div>;
  }
  const navigation = readNavigation(run.options.navigation);
  const recentNavigationActions = navigation?.actions.slice(-8).reverse() ?? [];
  const currentNavigationState = navigation
    ? resolveCurrentNavigationState(navigation)
    : null;
  const storage = readStorage(run.options.storage);
  const networkTesting = readNetworkTesting(run.options.network_testing);

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
          {run.status === "safely_paused" ? (
            <button className="button button--signal" onClick={() => void control("resume")} disabled={Boolean(actionBusy) || Boolean(run.options.manual_action_active)}>재개</button>
          ) : run.status === "pause_requested" ? (
            <button className="button button--quiet" disabled>안전 지점 대기 중</button>
          ) : (
            <button className="button button--quiet" onClick={() => void control("pause")} disabled={run.status !== "running" || Boolean(actionBusy)}>일시정지</button>
          )}
          <button className="button button--danger" onClick={() => void control("stop")} disabled={!["running", "pause_requested", "safely_paused"].includes(run.status) || Boolean(run.options.manual_action_active)}>중지</button>
        </div>
      </header>

      {run.error && <div className="inline-alert">{run.error}</div>}
      {actionError && <div className="inline-alert">{actionError}</div>}
      {run.current_stage === "proxy_manual_setup" && (
        <section className="panel manual-proxy-panel">
          <div>
            <span className="eyebrow">MANUAL PROXY CHECKPOINT</span>
            <h3>{run.proxy_adapter === "burp" ? "Burp Suite" : "Fiddler"} 캡처 준비</h3>
            <ol>
              {Array.isArray(run.options.manual_proxy_instructions)
                ? run.options.manual_proxy_instructions.map((item) => (
                    <li key={String(item)}>{String(item)}</li>
                  ))
                : <li>프록시 설정 후 HAR 또는 JSON을 가져오세요.</li>}
            </ol>
          </div>
          <div className="drop-zone">
            <strong>{run.options.manual_proxy_setup_confirmed ? "프록시 설정 확인 완료" : "Listener와 단말 프록시를 준비하세요"}</strong>
            <small>이 단계에서는 HAR를 가져오지 않습니다. 앱 동적 조작이 끝난 뒤 최종 캡처를 요청합니다.</small>
            <button
              type="button"
              className="button button--signal"
              disabled={run.status !== "safely_paused" || Boolean(actionBusy) || Boolean(run.options.manual_proxy_setup_confirmed)}
              onClick={() => void confirmProxySetup()}
            >
              설정 확인
            </button>
          </div>
        </section>
      )}

      {run.current_stage === "proxy_capture_import" && (
        <section className="panel manual-proxy-panel">
          <div>
            <span className="eyebrow">FINAL CAPTURE CHECKPOINT</span>
            <h3>동적 조작 후 HAR/JSON Import</h3>
            <p>앱 설치·실행·로그인·기능 조작이 끝났습니다. Burp/Fiddler 캡처를 종료하고 이 Run의 최종 파일을 가져오세요.</p>
          </div>
          <label className={`drop-zone ${proxyImporting ? "drop-zone--busy" : ""}`}>
            <input
              type="file"
              accept=".har,.json,application/json"
              disabled={run.status !== "safely_paused" || Boolean(proxyImporting)}
              onChange={(event) => void importProxyCapture(event.target.files?.[0])}
            />
            <strong>
              {run.options.manual_proxy_imported
                ? `${String(run.options.manual_proxy_flow_count ?? 0)}개 흐름 Import 완료`
                : proxyImporting
                  ? `Import 중 ${proxyImporting}%`
                  : "최종 HAR/JSON 가져오기"}
            </strong>
            <small>1개 이상의 흐름이 확인된 뒤에만 분석을 재개할 수 있습니다.</small>
          </label>
        </section>
      )}

      <div className="live-grid">
        <section className="console-panel device-console">
          <div className="console-head"><span>DEVICE VIEW</span><small>{run.device_id}</small></div>
          <div className="phone-stage">
            <div className="phone-frame">
              <div className="phone-frame__speaker" />
              {screenshot ? (
                <AuthenticatedImage path={`/evidence/${screenshot.id}/download`} alt={screenshot.title} />
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
              "navigation",
              "dynamic_storage",
              "network_dynamic",
              "network_testing",
              "ai_analysis",
              "finalize",
            ].map((stage, index) => {
              const stageProgress = [4, 12, 22, 32, 44, 56, 64, 68, 70, 80, 84, 96][index];
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
          <div className="console-head"><span>FRIDA STREAM</span><small>{fridaMessages.length} messages</small></div>
          <div className="frida-health-ledger">
            <div>
              <span>SESSION</span>
              <strong className={fridaHealth?.healthy ? "health-ok" : ""}>
                {fridaHealth?.active ? "ACTIVE" : fridaHealth?.cleanup_status === "available" ? "CLOSED CLEAN" : "IDLE"}
              </strong>
            </div>
            <div>
              <span>ROUTE</span>
              <strong>{fridaRoute(fridaHealth)}</strong>
              <small>{fridaHealth?.actual_device?.id ? `actual ${fridaHealth.actual_device.id}` : "actual device 대기"}</small>
            </div>
            <div>
              <span>RING</span>
              <strong>{fridaHealth?.buffer_count ?? 0}/{fridaHealth?.buffer_capacity ?? 0}</strong>
              <small>{fridaHealth?.total_message_count ?? 0} received</small>
            </div>
            <div>
              <span>JSONL</span>
              <strong>{formatBytes(fridaHealth?.transcript_bytes ?? 0)}</strong>
              <small>limit {formatBytes(fridaHealth?.transcript_max_bytes ?? 0)}</small>
            </div>
            <div className={(fridaHealth?.dropped_count ?? 0) > 0 ? "health-warn" : ""}>
              <span>LOSS / TRUNC</span>
              <strong>{fridaHealth?.dropped_count ?? 0} / {fridaHealth?.truncated_count ?? 0}</strong>
              <small>{fridaHealth?.stream_sampled_count ?? 0} stream sampled</small>
            </div>
          </div>
          <div className="terminal-stream">
            {fridaMessages.length ? fridaMessages.map((item, index) => (
              <div className="terminal-line" key={`${item.timestamp}-${index}`}>
                <span>{formatDate(item.timestamp)}</span>
                <code>{JSON.stringify(maskForDisplay(item.message))}</code>
              </div>
            )) : (
              <div className="terminal-empty">$ Frida 메시지를 기다리는 중<span className="terminal-cursor" /></div>
            )}
          </div>
        </section>

        <section className="console-panel navigation-console">
          <div className="console-head">
            <span>NAVIGATION GRAPH</span>
            <small>{navigation ? `${navigation.state_count} states · ${navigation.action_count} actions` : "not started"}</small>
          </div>
          <div className="navigation-ledger">
            <div>
              <span>ENGINE</span>
              <strong>{navigation?.status === "available" ? "BOUNDED COMPLETE" : navigation?.status?.toUpperCase() ?? "WAITING"}</strong>
              <small>{navigation?.termination_reason ?? "탐색 시작 전"}</small>
            </div>
            <div>
              <span>CURRENT SCREEN</span>
              <strong>{currentNavigationState?.activity || "—"}</strong>
              <small>{currentNavigationState?.package || run.device_id}</small>
            </div>
            <div>
              <span>GRAPH</span>
              <strong>{navigation?.state_count ?? 0} / {navigation?.action_count ?? 0}</strong>
              <small>states / actions</small>
            </div>
            <div className={(navigation?.pending_approval.length ?? 0) > 0 ? "health-warn" : ""}>
              <span>APPROVAL QUEUE</span>
              <strong>{navigation?.pending_approval.length ?? 0}</strong>
              <small>자동 실행 차단</small>
            </div>
          </div>
          <div className="navigation-body">
            <div className="navigation-state-strip">
              {navigation?.states.length ? navigation.states.slice(0, 12).map((state, index) => (
                <div className="navigation-state-node" key={state.fingerprint}>
                  <span>{String(index + 1).padStart(2, "0")}</span>
                  <strong>{state.activity || "unknown activity"}</strong>
                  <small>{state.element_count} elements · {state.fingerprint.slice(0, 8)}</small>
                </div>
              )) : <div className="console-empty">UI Tree가 수집되면 화면 상태가 fingerprint로 연결됩니다.</div>}
            </div>
            <div className="navigation-detail-grid">
              <div>
                <h4>RECENT SAFE ACTIONS</h4>
                <div className="navigation-action-list">
                  {recentNavigationActions.length ? recentNavigationActions.map((action) => (
                    <div key={`${action.sequence}-${action.timestamp}`}>
                      <span>{String(action.sequence).padStart(3, "0")}</span>
                      <strong>{action.action_type.toUpperCase()} · {action.label}</strong>
                      <small>{action.result} · {action.destination_state?.slice(0, 8) ?? "no transition"}</small>
                    </div>
                  )) : <div className="console-empty">실행된 저위험 UI 동작이 없습니다.</div>}
                </div>
              </div>
              <div>
                <h4>POLICY BLOCKS / APPROVAL</h4>
                <div className="navigation-approval-list">
                  {navigation?.pending_approval.length ? navigation.pending_approval.slice(0, 8).map((item) => (
                    <div key={`${item.state_fingerprint}-${item.element_id}`}>
                      <StatusChip value={item.risk} />
                      <span><strong>{item.label || "이름 없는 동작"}</strong><small>{item.rationale}</small></span>
                    </div>
                  )) : <div className="console-empty">위험 정책에 의해 보류된 UI 동작이 없습니다.</div>}
                </div>
              </div>
            </div>
          </div>
        </section>

        <section className="console-panel storage-console">
          <div className="console-head">
            <span>DYNAMIC STORAGE DIFF</span>
            <small>{storage ? `${storage.change_count} changes · ${storage.databases.length} databases` : "not requested"}</small>
          </div>
          <div className="storage-ledger">
            <div><span>SCOPE</span><strong>APP PACKAGE ONLY</strong><small>/data/data/{currentNavigationState?.package ?? "target"}</small></div>
            <div><span>FILES</span><strong>{storage?.before_file_count ?? 0} → {storage?.after_file_count ?? 0}</strong><small>before / after</small></div>
            <div><span>DIFF</span><strong>{storage?.change_count ?? 0}</strong><small>created · modified · deleted</small></div>
            <div><span>SQLITE</span><strong>{storage?.databases.length ?? 0}</strong><small>masked preview</small></div>
            <div><span>CLIPBOARD</span><strong>{String(storage?.clipboard.status ?? "not tested").toUpperCase()}</strong><small>{storage?.clipboard.changed_signal ? "change signal" : "no attributed change"}</small></div>
          </div>
          <div className="storage-detail-grid">
            <div>
              <h4>FILESYSTEM CHANGES</h4>
              <div className="storage-change-list">
                {storage?.changes.length ? storage.changes.slice(0, 100).map((change) => (
                  <div key={`${change.change_type}-${change.path}`}>
                    <span className={`storage-change storage-change--${change.change_type}`}>{change.change_type}</span>
                    <strong>{change.path}</strong>
                    <small>{formatBytes(change.before_size ?? 0)} → {formatBytes(change.after_size ?? 0)}</small>
                  </div>
                )) : <div className="console-empty">수집된 앱 전용 파일 변화가 없습니다.</div>}
              </div>
            </div>
            <div>
              <h4>DATABASE STRUCTURE</h4>
              <div className="storage-database-list">
                {storage?.databases.length ? storage.databases.map((database) => (
                  <details key={database.path}>
                    <summary><strong>{database.path}</strong><span>{database.tables.length} tables · {formatBytes(database.size)}</span></summary>
                    {database.tables.map((table) => (
                      <div className="storage-table" key={table.name}>
                        <strong>{table.name}</strong>
                        <small>{table.row_count} rows · {table.columns.map((column) => column.name).join(", ")}</small>
                        <span>Preview masked by default</span>
                      </div>
                    ))}
                  </details>
                )) : <div className="console-empty">구조화된 SQLite 파일이 없습니다.</div>}
              </div>
            </div>
          </div>
        </section>

        <section className="console-panel network-test-console">
          <div className="console-head">
            <span>API TEST CANDIDATES</span>
            <small>{networkTesting ? `${networkTesting.executed_count} executed · ${networkTesting.pending_count} approval` : "waiting for proxy flush"}</small>
          </div>
          <div className="network-test-ledger">
            <div><span>PASSIVE FLOWS</span><strong>{networkTesting?.flow_count ?? 0}</strong><small>normalized locally</small></div>
            <div><span>CANDIDATES</span><strong>{networkTesting?.candidate_count ?? 0}</strong><small>rule engine proposals</small></div>
            <div><span>SAFE EXECUTION</span><strong>{networkTesting?.executed_count ?? 0}</strong><small>{run.synthetic ? "synthetic only" : "local passive only"}</small></div>
            <div className={(networkTesting?.pending_count ?? 0) > 0 ? "health-warn" : ""}><span>APPROVAL REQUIRED</span><strong>{networkTesting?.pending_count ?? 0}</strong><small>state / object boundary</small></div>
          </div>
          <div className="network-test-body">
            <div>
              <h4>NORMALIZED ENDPOINTS</h4>
              <div className="network-endpoint-list">
                {networkTesting?.analyses.length ? networkTesting.analyses.slice(0, 100).map((analysis) => (
                  <div key={analysis.source_flow_id}>
                    <span className={`method method--${analysis.method.toLowerCase()}`}>{analysis.method}</span>
                    <strong>{analysis.endpoint}</strong>
                    <small>{analysis.protocol_style} · auth {analysis.auth_scheme ?? "none"} · {analysis.sensitive_response_fields.length} sensitive fields</small>
                  </div>
                )) : <div className="console-empty">Proxy Flush 이후 endpoint가 구조화됩니다.</div>}
              </div>
            </div>
            <div>
              <h4>CANDIDATE / POLICY</h4>
              <div className="network-candidate-list">
                {networkTesting?.candidates.length ? networkTesting.candidates.slice(0, 100).map((candidate) => (
                  <details key={candidate.id}>
                    <summary>
                      <StatusChip value={candidate.status} />
                      <strong>{candidate.test_type}</strong>
                      <span>{candidate.method} {candidate.endpoint}</span>
                      <i>{candidate.risk}</i>
                    </summary>
                    <p>{candidate.rationale}</p>
                    {candidate.modified_fields.length > 0 && <pre>{JSON.stringify(candidate.modified_fields, null, 2)}</pre>}
                  </details>
                )) : <div className="console-empty">아직 생성된 API 검증 Candidate가 없습니다.</div>}
              </div>
            </div>
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
                <pre>{JSON.stringify(maskForDisplay({
                  request: { headers: flow.request_headers, body: flow.request_body },
                  response: { status: flow.status_code, headers: flow.response_headers, body: flow.response_body },
                  source_ip: flow.source_ip,
                  sensitive_candidates: flow.sensitive_candidates,
                }), null, 2)}</pre>
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

function fridaRoute(health: FridaHealth | null): string {
  if (!health?.transport) return "not started";
  return `${health.transport} · ${health.endpoint ?? health.device_id ?? "unresolved"}`;
}

function formatBytes(value: number): string {
  if (!value) return "0 B";
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
  return `${(value / (1024 * 1024)).toFixed(1)} MB`;
}

function readNavigation(value: unknown): NavigationSummary | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const item = value as Partial<NavigationSummary>;
  if (!Array.isArray(item.states) || !Array.isArray(item.actions) || !Array.isArray(item.pending_approval)) return null;
  return item as NavigationSummary;
}

function resolveCurrentNavigationState(navigation: NavigationSummary) {
  const lastAction = navigation.actions[navigation.actions.length - 1];
  const fingerprint = lastAction?.destination_state;
  return navigation.states.find((item) => item.fingerprint === fingerprint)
    ?? navigation.states[navigation.states.length - 1]
    ?? null;
}

function readStorage(value: unknown): StorageSummary | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const item = value as Partial<StorageSummary>;
  if (!Array.isArray(item.changes) || !Array.isArray(item.databases)) return null;
  return item as StorageSummary;
}

function readNetworkTesting(value: unknown): NetworkTestingSummary | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const item = value as Partial<NetworkTestingSummary>;
  if (!Array.isArray(item.analyses) || !Array.isArray(item.candidates) || !Array.isArray(item.executions)) return null;
  return item as NetworkTestingSummary;
}

const sensitiveDisplayKey = /authorization|cookie|token|secret|password|passwd|session|email|phone|address|account|card/i;

function maskForDisplay(value: unknown, key = ""): unknown {
  if (sensitiveDisplayKey.test(key) && value !== null && value !== undefined) {
    const size = typeof value === "string" ? value.length : JSON.stringify(value).length;
    return `<masked:${size}>`;
  }
  if (Array.isArray(value)) return value.map((item) => maskForDisplay(item));
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>).map(([itemKey, item]) => [
        itemKey,
        maskForDisplay(item, itemKey),
      ]),
    );
  }
  if (typeof value === "string") {
    try {
      const parsed = JSON.parse(value) as unknown;
      if (parsed && typeof parsed === "object") return maskForDisplay(parsed);
    } catch {
      // Non-JSON bodies remain text, with common bearer material removed below.
    }
    return value
      .replace(/Bearer\s+[A-Za-z0-9._~+/=-]+/gi, "Bearer <masked>")
      .replace(/((?:token|secret|password|session|cookie)=)[^&\s]+/gi, "$1<masked>")
      .replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi, "<masked-email>");
  }
  return value;
}
