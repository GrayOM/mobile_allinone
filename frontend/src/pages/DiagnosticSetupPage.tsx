import { FormEvent, useEffect, useState } from "react";
import { useNavigate } from "../router";
import { api, post } from "../api";
import type { AppArtifact, Device, FridaScript, Project, DiagnosticRun } from "../types";
import { EmptyState, SectionHeading, StatusChip } from "../components/UI";

function deviceReadinessMessage(device: Device): string {
  const details = device.details;
  const adapterMessage = ["error", "message", "reason"]
    .map((key) => details[key])
    .find((value): value is string => typeof value === "string" && value.trim().length > 0);
  if (adapterMessage) return adapterMessage;
  if (device.availability === "not_configured") {
    return "선택한 단말 Adapter가 준비되지 않았습니다. 설정에서 관련 실행 파일 경로를 확인한 뒤 단말 목록을 새로고침하세요.";
  }
  if (device.availability === "manual_required") {
    return "선택한 단말은 수동 준비가 필요합니다. USB 디버깅·신뢰 확인·필수 단말 도구 상태를 점검한 뒤 다시 시도하세요.";
  }
  if (device.availability === "unsupported") {
    return "선택한 단말 연결 방식은 현재 자동 진단 범위에서 지원하지 않습니다. 지원되는 USB/SSH 프로필 또는 수동 절차를 사용하세요.";
  }
  return "선택한 단말이 현재 연결 또는 권한 문제로 준비되지 않았습니다. 단말 케이블·디버깅 승인·Adapter 상태를 확인하세요.";
}

function defaultAuthorizationExpiry(): string {
  const expires = new Date(Date.now() + (8 * 60 * 60 * 1000));
  const local = new Date(expires.getTime() - (expires.getTimezoneOffset() * 60 * 1000));
  return local.toISOString().slice(0, 16);
}

function networkHostLines(value: string): string[] {
  return value
    .split(/\r?\n|,/)
    .map((item) => item.trim())
    .filter(Boolean);
}

export default function DiagnosticSetupPage() {
  const navigate = useNavigate();
  const [projects, setProjects] = useState<Project[]>([]);
  const [projectId, setProjectId] = useState(() => localStorage.getItem("msw.project") ?? "");
  const [apps, setApps] = useState<AppArtifact[]>([]);
  const [appId, setAppId] = useState(() => localStorage.getItem("msw.app") ?? "");
  const [devices, setDevices] = useState<Device[]>([]);
  const [deviceId, setDeviceId] = useState(() => localStorage.getItem("msw.device") ?? "");
  const [proxyAdapter, setProxyAdapter] = useState("mitmproxy");
  const [proxyListenHost, setProxyListenHost] = useState("");
  const [proxyAllowedClientIp, setProxyAllowedClientIp] = useState("");
  const [proxyPort, setProxyPort] = useState("8080");
  const [scripts, setScripts] = useState<FridaScript[]>([]);
  const [selectedScripts, setSelectedScripts] = useState<string[]>([]);
  const [autoSelectFrida, setAutoSelectFrida] = useState(false);
  const [controlValidationEnabled, setControlValidationEnabled] = useState(false);
  const [controlValidationDialogOpen, setControlValidationDialogOpen] = useState(false);
  const [authorizedDeviceId, setAuthorizedDeviceId] = useState("");
  const [authorizationReference, setAuthorizationReference] = useState("");
  const [approvedBy, setApprovedBy] = useState("");
  const [authorizationExpiresAt, setAuthorizationExpiresAt] = useState(defaultAuthorizationExpiry);
  const [testAccountReference, setTestAccountReference] = useState("");
  const [allowedNetworkHosts, setAllowedNetworkHosts] = useState("");
  const [scopeDescription, setScopeDescription] = useState("");
  const [authorizationConfirmed, setAuthorizationConfirmed] = useState(false);
  const [testEnvironmentConfirmed, setTestEnvironmentConfirmed] = useState(false);
  const [testDataOnlyConfirmed, setTestDataOnlyConfirmed] = useState(false);
  const [guideNote, setGuideNote] = useState("");
  const [starting, setStarting] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    void Promise.all([
      api<Project[]>("/projects"),
      api<{ devices: Device[] }>("/devices"),
    ]).then(([projectItems, deviceResult]) => {
      setProjects(projectItems);
      setDevices(deviceResult.devices);
      if (!projectId && projectItems[0]) setProjectId(projectItems[0].id);
      if (!deviceId && deviceResult.devices[0]) setDeviceId(deviceResult.devices[0].id);
    });
  }, []);

  useEffect(() => {
    if (!projectId) return;
    void api<AppArtifact[]>(`/projects/${projectId}/apps`).then((items) => {
      setApps(items);
      if (!items.some((item) => item.id === appId)) setAppId(items[0]?.id ?? "");
    });
  }, [projectId]);

  const project = projects.find((item) => item.id === projectId);
  const selectedApp = apps.find((item) => item.id === appId);
  const selectedDevice = devices.find((item) => item.id === deviceId);
  const matchesAppPlatform = (device: Device) => !selectedApp || (
    selectedApp.platform === "android"
      ? device.platform.includes("android")
      : device.platform.includes("ios")
  );
  const compatibleDevices = devices.filter((item) =>
    (project?.run_mode === "mock" ? item.adapter === "mock" : item.adapter !== "mock")
    && matchesAppPlatform(item)
  );

  useEffect(() => {
    if (!selectedApp) {
      setScripts([]);
      setSelectedScripts([]);
      return;
    }
    void api<FridaScript[]>(`/frida/scripts?platform=${selectedApp.platform}`).then((items) => {
      setScripts(items);
      setSelectedScripts([]);
      setAutoSelectFrida(false);
    });
  }, [selectedApp?.id, selectedApp?.platform]);

  useEffect(() => {
    if (!project) return;
    setProxyAdapter(project.run_mode === "mock" ? "mock" : "mitmproxy");
    if (project.run_mode !== "live") {
      setControlValidationEnabled(false);
      setControlValidationDialogOpen(false);
      setAuthorizedDeviceId("");
    }
    const compatible = devices.filter((item) =>
      (project.run_mode === "mock" ? item.adapter === "mock" : item.adapter !== "mock")
      && matchesAppPlatform(item)
    );
    if (!compatible.some((item) => item.id === deviceId)) {
      const next = compatible[0]?.id ?? "";
      setDeviceId(next);
      if (next) localStorage.setItem("msw.device", next);
    }
  }, [project, devices, deviceId, selectedApp?.id, selectedApp?.platform]);

  useEffect(() => {
    if (
      controlValidationEnabled
      && authorizedDeviceId
      && authorizedDeviceId !== deviceId
    ) {
      setControlValidationEnabled(false);
      setGuideNote("단말 선택이 변경되어 통제 검증 승인이 해제됐습니다. 현재 단말로 승인 범위를 다시 확인하세요.");
    }
  }, [authorizedDeviceId, controlValidationEnabled, deviceId]);

  function applyGuidedDefaults() {
    if (!project) return;
    setProxyAdapter(project.run_mode === "mock" ? "mock" : "mitmproxy");
    setSelectedScripts([]);
    setAutoSelectFrida(false);
    setControlValidationEnabled(false);
    setControlValidationDialogOpen(false);
    setAuthorizedDeviceId("");
    setGuideNote(
      project.run_mode === "mock"
        ? "Mock 데모에 맞는 안전한 기본값을 적용했습니다. 단말과 앱을 확인한 뒤 진단을 시작하세요."
        : "Live 진단의 보수적인 기본값을 적용했습니다. 단말 IP와 프록시 정보를 확인한 뒤 진단을 시작하세요.",
    );
  }

  async function start(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    const device = devices.find((item) => item.id === deviceId);
    setStarting(true);
    setError("");
    try {
      if (!project || !device) throw new Error("프로젝트 모드에 맞는 단말을 선택하세요.");
      if (device.availability !== "available") throw new Error(deviceReadinessMessage(device));
      const run = await post<DiagnosticRun>("/runs", {
        project_id: projectId,
        app_id: appId || null,
        device_id: deviceId,
        device_adapter: device.adapter,
        proxy_adapter: proxyAdapter,
        frida_script_ids: selectedScripts,
        auto_select_frida: autoSelectFrida,
        pause_for_login: data.get("pause_for_login") === "on",
        options: {
          frida_mode: data.get("frida_mode"),
          runtime_tool: data.get("runtime_tool"),
          auto_navigation: data.get("auto_navigation") === "on",
          ai_rank_navigation: data.get("ai_rank_navigation") === "on",
          dynamic_storage: data.get("dynamic_storage") === "on",
          pause_for_approval_candidates:
            data.get("pause_for_approval_candidates") === "on",
          pause_for_security_bypass:
            data.get("pause_for_security_bypass") === "on",
          ...(controlValidationEnabled ? {
            control_validation: {
              enabled: true,
              authorization_reference: authorizationReference,
              approved_by: approvedBy,
              authorization_expires_at: new Date(authorizationExpiresAt).toISOString(),
              authorized_device_id: authorizedDeviceId,
              test_account_reference: testAccountReference,
              allowed_network_hosts: networkHostLines(allowedNetworkHosts),
              scope_description: scopeDescription,
              authorized_scope_confirmed: authorizationConfirmed,
              test_environment_confirmed: testEnvironmentConfirmed,
              test_data_only_confirmed: testDataOnlyConfirmed,
            },
          } : {}),
          auto_ai_script_candidate:
            data.get("auto_ai_script_candidate") === "on",
          simulate_nvidia_failure: data.get("simulate_nvidia_failure") === "on",
          ...(proxyAdapter === "mitmproxy" ? {
            proxy_listen_host: proxyListenHost,
            proxy_allowed_client_ip: proxyAllowedClientIp,
          } : ["burp", "fiddler"].includes(proxyAdapter) ? {
            proxy_listen_host: proxyListenHost,
            proxy_port: Number(proxyPort),
          } : {}),
        },
      });
      navigate(`/runs/${run.id}`);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "진단 시작 실패");
    } finally {
      setStarting(false);
    }
  }

  if (!projects.length) {
    return (
      <EmptyState
        title="먼저 프로젝트를 준비하세요"
        description="프로젝트와 앱을 등록한 뒤 진단 설정을 선택할 수 있습니다."
        action={<button className="button button--primary" onClick={() => navigate("/projects")}>프로젝트로 이동</button>}
      />
    );
  }

  return (
    <form className="setup-layout" onSubmit={start}>
      <div className="stack stack--lg">
        <SectionHeading
          eyebrow="RUN CONFIGURATION"
          title="실행 범위와 승인 경계를 정합니다"
          description="아래 준비도를 위에서 아래 순서로 확인하세요. 상태 변경 네트워크 요청은 자동 재전송하지 않습니다."
        />
        {error && <div className="inline-alert">{error}</div>}
        <section className="diagnostic-guide panel" aria-labelledby="diagnostic-guide-title">
          <div className="diagnostic-guide__head">
            <div>
              <span className="eyebrow">STEP-BY-STEP CHECK</span>
              <h3 id="diagnostic-guide-title">진단 전에 네 가지만 확인하세요</h3>
              <p>복잡한 옵션은 기본적으로 안전한 값으로 유지됩니다. 준비되지 않은 항목을 먼저 해결하면 실행 실패를 줄일 수 있습니다.</p>
            </div>
            <button className="button button--quiet" type="button" onClick={applyGuidedDefaults}>권장 설정 적용</button>
          </div>
          <div className="diagnostic-guide__checks">
            <div className={project ? "guide-check guide-check--done" : "guide-check"}>
              <span>1</span><div><strong>프로젝트·기준</strong><small>{project ? `${project.run_mode === "mock" ? "Mock 연습" : "Live 진단"} · ${project.assessment_profile === "electronic_financial" ? "전자금융기반시설 56항목" : "주요정보통신기반시설 27항목"}` : "프로젝트를 선택하세요"}</small></div>
            </div>
            <div className={selectedApp ? "guide-check guide-check--done" : "guide-check"}>
              <span>2</span><div><strong>대상 앱</strong><small>{selectedApp ? (selectedApp.app_name || selectedApp.original_name) : "APK 또는 IPA를 선택하세요"}</small></div>
            </div>
            <div className={selectedDevice?.availability === "available" ? "guide-check guide-check--done" : "guide-check"}>
              <span>3</span><div><strong>단말 준비</strong><small>{selectedDevice?.availability === "available" ? `${selectedDevice.model} 연결 확인` : "연결·권한·도구 상태를 확인하세요"}</small></div>
            </div>
            <div className={project?.run_mode === "mock" || (proxyListenHost && (proxyAdapter !== "mitmproxy" || proxyAllowedClientIp)) ? "guide-check guide-check--done" : "guide-check"}>
              <span>4</span><div><strong>캡처 범위</strong><small>{project?.run_mode === "mock" ? "합성 프록시 사용" : "프록시 Listener와 단말 IP를 입력하세요"}</small></div>
            </div>
          </div>
          {guideNote && <div className="inline-alert inline-alert--ok">{guideNote}</div>}
        </section>
        <section className="panel setup-section">
          <div className="setup-number">01</div>
          <div className="setup-content">
            <h3>대상 앱</h3>
            <div className="form-grid">
              <div className="field">
                <label htmlFor="run-project">프로젝트</label>
                <select id="run-project" value={projectId} onChange={(event) => {
                  setProjectId(event.target.value);
                  localStorage.setItem("msw.project", event.target.value);
                }}>
                  {projects.map((item) => <option key={item.id} value={item.id}>{item.name}</option>)}
                </select>
              </div>
              <div className="field">
                <label htmlFor="run-app">앱 파일</label>
                <select id="run-app" value={appId} onChange={(event) => {
                  setAppId(event.target.value);
                  localStorage.setItem("msw.app", event.target.value);
                }} required>
                  <option value="">앱 선택</option>
                  {apps.map((item) => <option key={item.id} value={item.id}>{item.app_name || item.original_name} · {item.version || "—"}</option>)}
                </select>
              </div>
            </div>
          </div>
        </section>
        <section className="panel setup-section">
          <div className="setup-number">02</div>
          <div className="setup-content">
            <h3>단말과 프록시</h3>
            <div className="select-cards">
              {compatibleDevices.map((device) => (
                <label className={`select-card ${deviceId === device.id ? "select-card--active" : ""}`} key={`${device.adapter}-${device.id}`}>
                  <input type="radio" name="device" value={device.id} checked={deviceId === device.id} onChange={() => {
                    setDeviceId(device.id);
                    localStorage.setItem("msw.device", device.id);
                  }} />
                  <span className="platform-mark">{device.platform.includes("ios") ? "i" : "A"}</span>
                  <span><strong>{device.model}</strong><small>{device.id} · {device.connection}</small></span>
                  <StatusChip value={device.availability} />
                </label>
              ))}
            </div>
            {selectedDevice && selectedDevice.availability !== "available" && (
              <div className="inline-alert">
                <strong>선택한 단말은 아직 진단을 시작할 수 없습니다.</strong><br />
                {deviceReadinessMessage(selectedDevice)}{" "}
                <button className="button button--quiet" type="button" onClick={() => navigate("/devices")}>단말 상태 확인</button>
              </div>
            )}
            <div className="form-grid">
              <div className="field">
                <label htmlFor="proxy">프록시 Adapter</label>
                <select id="proxy" name="proxy" value={proxyAdapter} onChange={(event) => setProxyAdapter(event.target.value)}>
                  {project?.run_mode === "mock" ? (
                    <option value="mock">Mock Proxy · 합성 데모 전용</option>
                  ) : (
                    <>
                      <option value="mitmproxy">mitmproxy · 실제 캡처</option>
                      <option value="burp">Burp Suite · 수동 연동</option>
                      <option value="fiddler">Fiddler · 수동 연동</option>
                    </>
                  )}
                </select>
              </div>
              {project?.run_mode === "live" && proxyAdapter !== "mock" && (
                <>
                  <div className="field">
                    <label htmlFor="proxy-listen-host">Windows Listener IP</label>
                    <input id="proxy-listen-host" value={proxyListenHost} onChange={(event) => setProxyListenHost(event.target.value)} placeholder="예: 192.168.0.10" required />
                    <small>0.0.0.0 대신 단말이 접근할 Windows LAN IP를 입력합니다.</small>
                  </div>
                  {proxyAdapter === "mitmproxy" ? (
                    <div className="field">
                      <label htmlFor="proxy-client-ip">허용 진단 단말 IP</label>
                      <input id="proxy-client-ip" value={proxyAllowedClientIp} onChange={(event) => setProxyAllowedClientIp(event.target.value)} placeholder="예: 192.168.0.25" required />
                      <small>이 IP가 아닌 연결과 패킷은 거부합니다.</small>
                    </div>
                  ) : (
                    <div className="field">
                      <label htmlFor="proxy-port">수동 프록시 Listener 포트</label>
                      <input id="proxy-port" type="number" min="1" max="65535" value={proxyPort} onChange={(event) => setProxyPort(event.target.value)} required />
                      <small>Burp/Fiddler에서 같은 IP와 포트로 Listener를 설정합니다.</small>
                    </div>
                  )}
                </>
              )}
              <div className="field">
                <label htmlFor="frida-mode">Frida 연결 방식</label>
                <select id="frida-mode" name="frida_mode" defaultValue="attach">
                  <option value="spawn">Spawn · 실행 시점부터</option>
                  <option value="attach">Attach · 실행 중 프로세스</option>
                </select>
              </div>
              <div className="field field--wide">
                <label htmlFor="runtime-tool">OSS 런타임 탐색</label>
                <select id="runtime-tool" name="runtime_tool" defaultValue="none">
                  <option value="none">사용 안 함</option>
                  <option value="objection">objection · 환경 읽기</option>
                  {selectedApp?.platform === "android" && <option value="drozer">drozer · Android 공격 표면 조회</option>}
                </select>
                <small>진단 자동 흐름에서는 읽기 전용 작업만 실행합니다. 상태 변경 작업은 별도 승인 API가 필요합니다.</small>
              </div>
            </div>
          </div>
        </section>
        <section className="panel setup-section">
          <div className="setup-number">03</div>
          <div className="setup-content">
            <h3>승인된 Frida 스크립트</h3>
            <label className="toggle-line">
              <input
                type="checkbox"
                checked={autoSelectFrida}
                onChange={(event) => {
                  setAutoSelectFrida(event.target.checked);
                  if (event.target.checked) setSelectedScripts([]);
                }}
              />
              <span />
              <div>
                <strong>안전한 내장 스크립트 자동 선택</strong>
                <small>대상 앱 조건과 일치하는 builtin·low 스크립트만 자동 실행합니다.</small>
              </div>
            </label>
            <p className="form-note">아무 것도 선택하지 않으면 Frida를 실행하지 않습니다. 사용자·AI 또는 medium/high 스크립트는 안전 일시정지 후 Run별 승인으로 직접 실행합니다.</p>
            <div className="script-choices">
              {scripts.map((script) => (
                <label className="check-card" key={script.id}>
                  <input
                    type="checkbox"
                    checked={selectedScripts.includes(script.id)}
                    disabled={
                      autoSelectFrida
                      || script.approval_status !== "approved"
                      || script.syntax_status !== "available"
                      || script.source !== "builtin"
                      || script.risk !== "low"
                    }
                    onChange={(event) => setSelectedScripts((items) =>
                      event.target.checked ? [...items, script.id] : items.filter((id) => id !== script.id)
                    )}
                  />
                  <span>
                    <strong>{script.name}</strong>
                    <small>{script.category} · {script.source} · 위험도 {script.risk} · 성공 {script.success_count}</small>
                  </span>
                </label>
              ))}
            </div>
          </div>
        </section>
        <section className="panel setup-section">
          <div className="setup-number">04</div>
          <div className="setup-content">
            <h3>사용자 개입과 AI 테스트</h3>
            <div className="option-row">
              {selectedApp?.platform === "android" && (
                <>
                  <label className="toggle-line">
                    <input type="checkbox" name="auto_navigation" defaultChecked />
                    <span />
                    <div><strong>저위험 UI 자동 탐색</strong><small>UIAutomator Tree에 실제 존재하는 요소만 실행하며 결제·송금·삭제 등은 승인 대기로 분리합니다.</small></div>
                  </label>
                  <label className="toggle-line">
                    <input
                      type="checkbox"
                      name="ai_rank_navigation"
                      defaultChecked={project?.run_mode === "mock" && project.ai_enabled}
                      disabled={!project?.ai_enabled || (project.run_mode === "live" && !project.external_ai_allowed)}
                    />
                    <span />
                    <div><strong>AI 안전 후보 순서 추천</strong><small>로컬 정책이 허용한 low 후보만 증적 수집 기대도로 정렬합니다. 새 동작·클릭·취약 판정은 AI가 수행하지 않습니다.</small></div>
                  </label>
                  <label className="toggle-line">
                    <input type="checkbox" name="dynamic_storage" defaultChecked />
                    <span />
                    <div><strong>앱 저장소 Before/After</strong><small>Root Android에서 대상 package의 /data/data 범위만 수집하고 SQLite Preview는 기본 마스킹합니다.</small></div>
                  </label>
                </>
              )}
              <label className="toggle-line">
                <input type="checkbox" name="pause_for_login" />
                <span />
                <div><strong>로그인 전 자동 일시정지</strong><small>사용자가 로그인한 뒤 재개합니다.</small></div>
              </label>
              <label className="toggle-line">
                <input type="checkbox" name="pause_for_approval_candidates" />
                <span />
                <div><strong>승인 후보에서 자동 일시정지</strong><small>중위험 UI 동작 또는 Live GET/HEAD 후보가 만들어지면 현재 화면·Flow를 고정해 1회 승인 검토를 기다립니다.</small></div>
              </label>
              <label className="toggle-line">
                <input type="checkbox" name="pause_for_security_bypass" />
                <span />
                <div><strong>루팅·탈옥 탐지 우회 준비</strong><small>앱 설치 후 첫 실행 전에 멈춥니다. Frida 라이브러리에서 고위험 우회 코드를 검토·승인·Spawn한 뒤 재개합니다.</small></div>
              </label>
              <label className="toggle-line">
                <input type="checkbox" name="simulate_nvidia_failure" />
                <span />
                <div><strong>NVIDIA 실패 모의</strong><small>외부 AI 프로젝트에서 Claude fallback을 검증합니다.</small></div>
              </label>
              <label className="toggle-line">
                <input type="checkbox" name="auto_ai_script_candidate" />
                <span />
                <div><strong>실패 시 AI 수정 후보 생성</strong><small>구문 검사 후 승인 대기 상태로만 저장하며 자동 실행하지 않습니다.</small></div>
              </label>
              <label className="toggle-line">
                <input
                  type="checkbox"
                  checked={controlValidationEnabled}
                  disabled={project?.run_mode !== "live" || !selectedDevice}
                  onChange={(event) => {
                    if (event.target.checked) {
                      setAuthorizedDeviceId(deviceId);
                      if (!authorizationExpiresAt) setAuthorizationExpiresAt(defaultAuthorizationExpiry());
                      setControlValidationDialogOpen(true);
                    } else {
                      setControlValidationEnabled(false);
                    }
                  }}
                />
                <span />
                <div>
                  <strong>승인된 통제 검증 모드</strong>
                  <small>{project?.run_mode !== "live" ? "Live 진단에서만 사용할 수 있습니다." : !selectedDevice ? "승인 범위를 고정할 실제 단말을 먼저 선택하세요." : controlValidationEnabled ? "승인 범위가 기록되며 고위험 우회는 별도 코드 검토와 1회 승인이 필요합니다." : "사용자 동의와 승인 범위를 기록한 뒤에만 활성화합니다."}</small>
                </div>
              </label>
            </div>
          </div>
        </section>
      </div>
      <aside className="run-summary panel">
        <span className="eyebrow">EXECUTION BOUNDARY</span>
        <h3>진단 시작 전 확인</h3>
        <div className="inline-alert">{project?.run_mode === "mock" ? "Mock 실행: 모든 결과가 SYNTHETIC으로 표시됩니다." : "Live 실행: Mock Adapter와 Mock AI는 차단됩니다."}</div>
        {controlValidationEnabled && (
          <div className="inline-alert inline-alert--ok">
            <strong>승인된 통제 검증</strong><br />
            {authorizedDeviceId} · {networkHostLines(allowedNetworkHosts).length}개 허용 서버 · {authorizationExpiresAt.replace("T", " ")} 만료
          </div>
        )}
        <ol>
          <li><span>1</span>소유하거나 명시적으로 진단 권한을 받은 앱·단말입니다.</li>
          <li><span>2</span>AI 생성 스크립트는 승인 전 실행되지 않습니다.</li>
          <li><span>3</span>POST·PUT·PATCH·DELETE 요청은 자동 재전송하지 않습니다.</li>
          <li><span>4</span>도구가 없으면 성공으로 위장하지 않고 상태를 남깁니다.</li>
        </ol>
        <button className="button button--signal button--full" disabled={starting || !appId || !deviceId || selectedDevice?.availability !== "available" || (project?.run_mode === "live" && !proxyListenHost) || (proxyAdapter === "mitmproxy" && !proxyAllowedClientIp) || (["burp", "fiddler"].includes(proxyAdapter) && !proxyPort)}>
          {starting ? "실행 준비 중…" : "진단 실행"}
        </button>
      </aside>
      {controlValidationDialogOpen && (
        <div className="consent-dialog-backdrop" role="presentation">
          <section className="consent-dialog consent-dialog--scope panel" role="dialog" aria-modal="true" aria-labelledby="control-validation-title">
            <span className="eyebrow">APPROVED CONTROL VALIDATION</span>
            <h3 id="control-validation-title">승인 범위를 확인하세요</h3>
            <p>승인 단말과 테스트 서버를 실행에 고정합니다. mitmproxy는 범위 밖 목적지를 upstream 전송 전에 차단하고, 수동 프록시에서 발견하면 Run을 즉시 중단합니다.</p>
            <div className="control-scope-sheet" aria-label="실행에 고정되는 승인 경계">
              <div><span>DEVICE LOCK</span><strong>{selectedDevice?.model ?? "단말 선택 필요"}</strong><code>{authorizedDeviceId || "—"}</code></div>
              <div><span>NETWORK POLICY</span><strong>DEFAULT DENY</strong><code>범위 밖 → 차단·수동 검토</code></div>
              <div><span>DATA POLICY</span><strong>TEST ONLY</strong><code>승인 기록 외부 AI 제외</code></div>
            </div>
            <div className="consent-dialog__grid">
              <div className="field">
                <label htmlFor="authorization-reference">승인 참조</label>
                <input id="authorization-reference" value={authorizationReference} onChange={(event) => setAuthorizationReference(event.target.value)} placeholder="예: SEC-TICKET-2048" maxLength={200} />
              </div>
              <div className="field">
                <label htmlFor="approved-by">승인자 또는 승인 기관</label>
                <input id="approved-by" value={approvedBy} onChange={(event) => setApprovedBy(event.target.value)} placeholder="예: 고객사 보안책임자" maxLength={120} />
              </div>
              <div className="field">
                <label htmlFor="authorization-expires-at">승인 만료 시각</label>
                <input id="authorization-expires-at" type="datetime-local" value={authorizationExpiresAt} onChange={(event) => setAuthorizationExpiresAt(event.target.value)} />
                <small>서버가 실행 시작과 네트워크 판정 시점에 다시 확인합니다.</small>
              </div>
              <div className="field">
                <label htmlFor="test-account-reference">테스트 계정 참조</label>
                <input id="test-account-reference" value={testAccountReference} onChange={(event) => setTestAccountReference(event.target.value)} placeholder="예: QA-ACCOUNT-03 (비밀번호 입력 금지)" maxLength={200} />
                <small>계정 식별용 참조만 입력하고 비밀번호·토큰은 입력하지 않습니다.</small>
              </div>
              <div className="field field--wide">
                <label htmlFor="allowed-network-hosts">허용 테스트 서버</label>
                <textarea id="allowed-network-hosts" value={allowedNetworkHosts} onChange={(event) => setAllowedNetworkHosts(event.target.value)} placeholder={"api.test.example\n*.sandbox.example\n192.0.2.15"} rows={4} />
                <small>한 줄에 하나씩 호스트·IP·*.하위도메인을 입력합니다. URL 경로와 단일 *는 허용되지 않습니다.</small>
              </div>
              <div className="field field--wide">
                <label htmlFor="control-validation-scope">승인된 테스트 범위</label>
                <textarea id="control-validation-scope" value={scopeDescription} onChange={(event) => setScopeDescription(event.target.value)} placeholder="대상 패키지, 허용 기능, 테스트 데이터와 제외 범위를 적으세요." maxLength={1000} rows={4} />
              </div>
            </div>
            <div className="consent-dialog__checks">
              <label><input type="checkbox" checked={authorizationConfirmed} onChange={(event) => setAuthorizationConfirmed(event.target.checked)} /> 앱 소유자 또는 권한자의 명시적 진단 승인을 받았습니다.</label>
              <label><input type="checkbox" checked={testEnvironmentConfirmed} onChange={(event) => setTestEnvironmentConfirmed(event.target.checked)} /> 승인된 테스트 단말·테스트 서버 범위에서만 실행합니다.</label>
              <label><input type="checkbox" checked={testDataOnlyConfirmed} onChange={(event) => setTestDataOnlyConfirmed(event.target.checked)} /> 테스트 계정과 테스트 데이터만 사용하며 운영 고객 데이터에는 접근하지 않습니다.</label>
            </div>
            <div className="consent-dialog__actions">
              <button className="button button--quiet" type="button" onClick={() => setControlValidationDialogOpen(false)}>취소</button>
              <button
                className="button button--signal"
                type="button"
                disabled={
                  !authorizationConfirmed
                  || !testEnvironmentConfirmed
                  || !testDataOnlyConfirmed
                  || authorizationReference.trim().length < 4
                  || approvedBy.trim().length < 2
                  || testAccountReference.trim().length < 2
                  || networkHostLines(allowedNetworkHosts).length < 1
                  || scopeDescription.trim().length < 10
                  || Number.isNaN(Date.parse(authorizationExpiresAt))
                  || Date.parse(authorizationExpiresAt) <= Date.now()
                }
                onClick={() => { setControlValidationEnabled(true); setControlValidationDialogOpen(false); }}
              >
                범위를 고정하고 검증 모드 사용
              </button>
            </div>
          </section>
        </div>
      )}
    </form>
  );
}
