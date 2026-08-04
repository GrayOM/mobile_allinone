import { FormEvent, useEffect, useState } from "react";
import { api, post, put } from "../api";
import { SectionHeading, StatusChip } from "../components/UI";

interface SettingsData {
  server: { host: string; port: number; data_dir: string; max_upload_mb: number };
  ai: {
    nvidia_configured: boolean;
    nvidia_model: string;
    claude_configured: boolean;
    claude_model: string;
    mask_external_ai_data: boolean;
    store_raw_responses: boolean;
    custom_sensitive_key_count: number;
  };
  proxy: {
    default_listen_host: string;
    binding_policy: string;
    client_allowlist_required: boolean;
    port_policy: string;
  };
  analysis: {
    mobsf_configured: boolean;
    mobsf_url: string | null;
    semgrep_rules_path: string;
    catalog: Record<string, unknown>;
    archive_limits: {
      max_entries: number;
      max_uncompressed_mb: number;
      max_entry_mb: number;
      max_entry_ratio: number;
      max_total_ratio: number;
      max_nested_count: number;
      max_nested_mb: number;
    };
    external_tool_limits: { memory_mb: number; cpu_seconds: number };
  };
  tools: Array<{
    name: string;
    status: string;
    configured_path: string;
    resolved_path: string | null;
    install_hint: string;
  }>;
}

interface AdapterHealth {
  name: string;
  status: string;
  integration: string;
  version?: string | null;
  path?: string | null;
  install_hint?: string;
  actions?: Array<{ name: string; risk: string }>;
}

export default function SettingsPage() {
  const [settings, setSettings] = useState<SettingsData | null>(null);
  const [message, setMessage] = useState("");
  const [aiResult, setAIResult] = useState<Record<string, unknown> | null>(null);
  const [analysisHealth, setAnalysisHealth] = useState<AdapterHealth[]>([]);
  const [runtimeHealth, setRuntimeHealth] = useState<AdapterHealth[]>([]);

  useEffect(() => {
    void Promise.all([
      api<SettingsData>("/settings"),
      api<AdapterHealth[]>("/analysis/tools"),
      api<AdapterHealth[]>("/runtime/adapters"),
    ]).then(([configured, analyzers, runtime]) => {
      setSettings(configured);
      setAnalysisHealth(analyzers);
      setRuntimeHealth(runtime);
    });
  }, []);

  async function saveTools(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const tools = Object.fromEntries(
      settings?.tools.map((tool) => [tool.name, String(form.get(tool.name) ?? "")]) ?? [],
    );
    const result = await put<{ message: string }>("/settings/tools", { tools });
    setMessage(result.message);
  }

  async function testAI(mock: boolean, simulateFailure = false) {
    const result = await post<Record<string, unknown>>("/ai/test", {
      task: "모바일 진단 AI Provider 연결 테스트",
      context: { platform: "android", sample: "masked-demo-only" },
      use_mock: mock,
      simulate_nvidia_failure: simulateFailure,
    });
    setAIResult(result);
  }

  if (!settings) return <div className="loading-block">설정을 읽는 중…</div>;

  return (
    <div className="stack stack--xl">
      <SectionHeading
        eyebrow="LOCAL CONFIGURATION"
        title="경로와 전송 정책을 눈에 보이게 둡니다"
        description="API 키는 화면에 노출하지 않으며 .env 환경 변수에서만 읽습니다."
      />
      {message && <div className="inline-alert inline-alert--ok">{message}</div>}

      <section className="settings-section panel">
        <div className="settings-section__head">
          <div className="settings-icon">L</div>
          <div><span className="eyebrow">LOCAL SERVER</span><h2>로컬 실행 정보</h2></div>
        </div>
        <dl className="settings-facts">
          <div><dt>접속 주소</dt><dd>http://{settings.server.host}:{settings.server.port}</dd></div>
          <div><dt>데이터 저장소</dt><dd><code>{settings.server.data_dir}</code></dd></div>
          <div><dt>업로드 제한</dt><dd>{settings.server.max_upload_mb} MB</dd></div>
          <div><dt>외부 노출</dt><dd><StatusChip value="available" label="Loopback 기본값" /></dd></div>
          <div><dt>프록시 바인딩</dt><dd><code>{settings.proxy.default_listen_host}</code> · 단말 IP 허용목록 필수</dd></div>
          <div><dt>프록시 포트</dt><dd>진단마다 동적 할당</dd></div>
        </dl>
      </section>

      <section className="settings-section panel">
        <div className="settings-section__head">
          <div className="settings-icon">OSS</div>
          <div><span className="eyebrow">ADAPTER FEDERATION</span><h2>연결된 오픈소스 기능</h2></div>
        </div>
        <div className="adapter-health-grid">
          {[...analysisHealth, ...runtimeHealth].map((adapter) => (
            <article key={adapter.name}>
              <i className={`adapter-health__signal adapter-health__signal--${adapter.status}`} />
              <div>
                <strong>{adapter.name}</strong>
                <small>{adapter.integration} · {adapter.version || adapter.path || "not resolved"}</small>
                {adapter.actions && <em>{adapter.actions.length} gated actions</em>}
              </div>
              <StatusChip value={adapter.status} />
            </article>
          ))}
        </div>
        <dl className="settings-facts">
          <div><dt>Semgrep 규칙</dt><dd><code>{settings.analysis.semgrep_rules_path}</code></dd></div>
          <div><dt>MobSF REST</dt><dd><StatusChip value={settings.analysis.mobsf_configured ? "available" : "not_configured"} label={settings.analysis.mobsf_url || "URL/API key 필요"} /></dd></div>
          <div><dt>통제 카탈로그</dt><dd>{String(settings.analysis.catalog.name ?? "OWASP MASTG")}</dd></div>
          <div><dt>통합 정책</dt><dd>도구 원문·버전·해시 보존 / 실패 상태 명시</dd></div>
          <div><dt>압축 해제 상한</dt><dd>{settings.analysis.archive_limits.max_uncompressed_mb} MB · {settings.analysis.archive_limits.max_entries.toLocaleString()} entries</dd></div>
          <div><dt>외부 도구 제한</dt><dd>메모리 {settings.analysis.external_tool_limits.memory_mb} MB · CPU {settings.analysis.external_tool_limits.cpu_seconds}초</dd></div>
        </dl>
      </section>

      <section className="settings-section panel">
        <div className="settings-section__head">
          <div className="settings-icon">T</div>
          <div><span className="eyebrow">EXTERNAL TOOLCHAIN</span><h2>분석 도구 경로</h2></div>
        </div>
        <form onSubmit={saveTools}>
          <div className="tool-table">
            {settings.tools.map((tool) => (
              <div className="tool-row" key={tool.name}>
                <div>
                  <strong>{tool.name}</strong>
                  <StatusChip value={tool.status} />
                </div>
                <div className="field">
                  <label htmlFor={`tool-${tool.name}`}>실행 파일 경로 또는 명령</label>
                  <input id={`tool-${tool.name}`} name={tool.name} defaultValue={tool.configured_path} />
                  <small>{tool.resolved_path ?? tool.install_hint}</small>
                </div>
              </div>
            ))}
          </div>
          <div className="form-actions">
            <button className="button button--primary">도구 경로 저장</button>
            <small>경로 변경은 서버 재시작 후 적용됩니다.</small>
          </div>
        </form>
      </section>

      <section className="settings-section panel">
        <div className="settings-section__head">
          <div className="settings-icon">AI</div>
          <div><span className="eyebrow">PROVIDER POLICY</span><h2>AI Provider</h2></div>
        </div>
        <div className="provider-grid">
          <article className="provider-card">
            <div><strong>NVIDIA AI</strong><StatusChip value={settings.ai.nvidia_configured ? "available" : "not_configured"} /></div>
            <code>{settings.ai.nvidia_model}</code>
            <p>1차 Provider · OpenAI 호환 Chat Completions</p>
          </article>
          <article className="provider-card">
            <div><strong>Claude</strong><StatusChip value={settings.ai.claude_configured ? "available" : "not_configured"} /></div>
            <code>{settings.ai.claude_model}</code>
            <p>오류·속도 제한·품질 미달 시 fallback</p>
          </article>
          <article className="provider-card">
            <div><strong>전송 마스킹</strong><StatusChip value={settings.ai.mask_external_ai_data ? "available" : "manual_required"} /></div>
            <p>토큰, 쿠키, 이메일, 전화번호와 실제 도메인 후보를 전송 전에 치환합니다.</p>
          </article>
          <article className="provider-card">
            <div><strong>AI 원문 저장</strong><StatusChip value={settings.ai.store_raw_responses ? "manual_required" : "available"} label={settings.ai.store_raw_responses ? "명시적 활성화" : "기본 비활성화"} /></div>
            <p>사용자 정의 민감 키 {settings.ai.custom_sensitive_key_count}개 · 저장 시에도 마스킹합니다.</p>
          </article>
        </div>
        <div className="button-row">
          <button className="button button--primary" onClick={() => void testAI(true)}>Mock AI 테스트</button>
          <button className="button button--quiet" onClick={() => void testAI(false)}>실제 Provider 테스트</button>
          <button className="button button--quiet" onClick={() => void testAI(false, true)}>NVIDIA 장애·fallback 테스트</button>
        </div>
        {aiResult && <pre className="code-view">{JSON.stringify(aiResult, null, 2)}</pre>}
      </section>
    </div>
  );
}
