import { FormEvent, useEffect, useState } from "react";
import { useNavigate } from "../router";
import { api, post } from "../api";
import type { AppArtifact, Device, FridaScript, Project, DiagnosticRun } from "../types";
import { EmptyState, SectionHeading, StatusChip } from "../components/UI";

export default function DiagnosticSetupPage() {
  const navigate = useNavigate();
  const [projects, setProjects] = useState<Project[]>([]);
  const [projectId, setProjectId] = useState(() => localStorage.getItem("msw.project") ?? "");
  const [apps, setApps] = useState<AppArtifact[]>([]);
  const [appId, setAppId] = useState(() => localStorage.getItem("msw.app") ?? "");
  const [devices, setDevices] = useState<Device[]>([]);
  const [deviceId, setDeviceId] = useState(() => localStorage.getItem("msw.device") ?? "mock-android-01");
  const [scripts, setScripts] = useState<FridaScript[]>([]);
  const [selectedScripts, setSelectedScripts] = useState<string[]>([]);
  const [starting, setStarting] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    void Promise.all([
      api<Project[]>("/projects"),
      api<{ devices: Device[] }>("/devices"),
      api<FridaScript[]>("/frida/scripts?platform=android"),
    ]).then(([projectItems, deviceResult, scriptItems]) => {
      setProjects(projectItems);
      setDevices(deviceResult.devices);
      setScripts(scriptItems);
      if (!projectId && projectItems[0]) setProjectId(projectItems[0].id);
      if (!deviceId && deviceResult.devices[0]) setDeviceId(deviceResult.devices[0].id);
      const approved = scriptItems.find((item) => item.approval_status === "approved");
      if (approved) setSelectedScripts([approved.id]);
    });
  }, []);

  useEffect(() => {
    if (!projectId) return;
    void api<AppArtifact[]>(`/projects/${projectId}/apps`).then((items) => {
      setApps(items);
      if (!items.some((item) => item.id === appId)) setAppId(items[0]?.id ?? "");
    });
  }, [projectId]);

  async function start(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    const device = devices.find((item) => item.id === deviceId);
    setStarting(true);
    setError("");
    try {
      const run = await post<DiagnosticRun>("/runs", {
        project_id: projectId,
        app_id: appId || null,
        device_id: deviceId,
        device_adapter: device?.adapter ?? "mock",
        proxy_adapter: data.get("proxy"),
        frida_script_ids: selectedScripts,
        pause_for_login: data.get("pause_for_login") === "on",
        options: {
          frida_mode: data.get("frida_mode"),
          runtime_tool: data.get("runtime_tool"),
          auto_ai_script_candidate:
            data.get("auto_ai_script_candidate") === "on",
          simulate_nvidia_failure: data.get("simulate_nvidia_failure") === "on",
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
          description="선택 내용을 확인한 뒤 진단을 시작하세요. 상태 변경 네트워크 요청은 자동 재전송하지 않습니다."
        />
        {error && <div className="inline-alert">{error}</div>}
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
              {devices.map((device) => (
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
            <div className="form-grid">
              <div className="field">
                <label htmlFor="proxy">프록시 Adapter</label>
                <select id="proxy" name="proxy" defaultValue="mock">
                  <option value="mock">Mock Proxy · 자동 데모</option>
                  <option value="mitmproxy">mitmproxy · 실제 캡처</option>
                  <option value="burp">Burp Suite · 수동 연동</option>
                  <option value="fiddler">Fiddler · 수동 연동</option>
                </select>
              </div>
              <div className="field">
                <label htmlFor="frida-mode">Frida 연결 방식</label>
                <select id="frida-mode" name="frida_mode" defaultValue="spawn">
                  <option value="spawn">Spawn · 실행 시점부터</option>
                  <option value="attach">Attach · 실행 중 프로세스</option>
                </select>
              </div>
              <div className="field field--wide">
                <label htmlFor="runtime-tool">OSS 런타임 탐색</label>
                <select id="runtime-tool" name="runtime_tool" defaultValue="none">
                  <option value="none">사용 안 함</option>
                  <option value="objection">objection · 환경 읽기</option>
                  <option value="drozer">drozer · Android 공격 표면 조회</option>
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
            <div className="script-choices">
              {scripts.map((script) => (
                <label className="check-card" key={script.id}>
                  <input
                    type="checkbox"
                    checked={selectedScripts.includes(script.id)}
                    disabled={script.approval_status !== "approved"}
                    onChange={(event) => setSelectedScripts((items) =>
                      event.target.checked ? [...items, script.id] : items.filter((id) => id !== script.id)
                    )}
                  />
                  <span>
                    <strong>{script.name}</strong>
                    <small>{script.category} · 위험도 {script.risk} · 성공 {script.success_count}</small>
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
              <label className="toggle-line">
                <input type="checkbox" name="pause_for_login" />
                <span />
                <div><strong>로그인 전 자동 일시정지</strong><small>사용자가 로그인한 뒤 재개합니다.</small></div>
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
            </div>
          </div>
        </section>
      </div>
      <aside className="run-summary panel">
        <span className="eyebrow">EXECUTION BOUNDARY</span>
        <h3>진단 시작 전 확인</h3>
        <ol>
          <li><span>1</span>소유하거나 명시적으로 진단 권한을 받은 앱·단말입니다.</li>
          <li><span>2</span>AI 생성 스크립트는 승인 전 실행되지 않습니다.</li>
          <li><span>3</span>POST·PUT·PATCH·DELETE 요청은 자동 재전송하지 않습니다.</li>
          <li><span>4</span>도구가 없으면 성공으로 위장하지 않고 상태를 남깁니다.</li>
        </ol>
        <button className="button button--signal button--full" disabled={starting || !appId || !deviceId}>
          {starting ? "실행 준비 중…" : "진단 실행"}
        </button>
      </aside>
    </form>
  );
}
