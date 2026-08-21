import { FormEvent, useEffect, useState } from "react";
import { Route, Routes } from "./router";
import {
  configureLanSession,
  getAuthenticationRequirement,
  loadAuthConfig,
  loginOrganization,
} from "./api";
import Layout from "./components/Layout";
import DashboardPage from "./pages/DashboardPage";
import ProjectsPage from "./pages/ProjectsPage";
import DevicesPage from "./pages/DevicesPage";
import DiagnosticSetupPage from "./pages/DiagnosticSetupPage";
import LiveRunPage from "./pages/LiveRunPage";
import FindingsPage from "./pages/FindingsPage";
import FindingDetailPage from "./pages/FindingDetailPage";
import ScriptsPage from "./pages/ScriptsPage";
import SettingsPage from "./pages/SettingsPage";
import CoveragePage from "./pages/CoveragePage";
import DataManagementPage from "./pages/DataManagementPage";
import AccessControlPage from "./pages/AccessControlPage";
import CapturesPage from "./pages/CapturesPage";

export default function App() {
  const [authRequired, setAuthRequired] = useState(getAuthenticationRequirement);
  const [authVersion, setAuthVersion] = useState(0);
  useEffect(() => {
    const required = () => setAuthRequired(getAuthenticationRequirement());
    const updated = () => {
      setAuthRequired(getAuthenticationRequirement());
      setAuthVersion((value) => value + 1);
    };
    window.addEventListener("msw-auth-required", required);
    window.addEventListener("msw-auth-updated", updated);
    return () => {
      window.removeEventListener("msw-auth-required", required);
      window.removeEventListener("msw-auth-updated", updated);
    };
  }, []);
  useEffect(() => {
    void loadAuthConfig()
      .then(() => setAuthRequired(getAuthenticationRequirement()))
      .catch(() => setAuthRequired(getAuthenticationRequirement()));
  }, [authVersion]);
  return (
    <>
      <Routes key={authVersion}>
        <Route element={<Layout />}>
          <Route index element={<DashboardPage />} />
          <Route path="projects" element={<ProjectsPage />} />
          <Route path="devices" element={<DevicesPage />} />
          <Route path="diagnostics/new" element={<DiagnosticSetupPage />} />
          <Route path="runs/:runId" element={<LiveRunPage />} />
          <Route path="findings" element={<FindingsPage />} />
          <Route path="findings/:findingId" element={<FindingDetailPage />} />
          <Route path="coverage" element={<CoveragePage />} />
          <Route path="data" element={<DataManagementPage />} />
          <Route path="captures" element={<CapturesPage />} />
          <Route path="access" element={<AccessControlPage />} />
          <Route path="scripts" element={<ScriptsPage />} />
          <Route path="settings" element={<SettingsPage />} />
        </Route>
      </Routes>
      {authRequired === "lan" && <LanSessionPrompt />}
      {authRequired === "organization" && <OrganizationLoginPrompt />}
    </>
  );
}

function OrganizationLoginPrompt() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      await loginOrganization(username, password);
      setPassword("");
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "조직 사용자 인증 실패");
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="auth-gate" role="dialog" aria-modal="true" aria-labelledby="organization-login-title">
      <form className="panel auth-gate__panel auth-gate__panel--organization" onSubmit={submit}>
        <span className="eyebrow">ORGANIZATION ACCESS CONTROL</span>
        <h2 id="organization-login-title">운영자 신원 확인</h2>
        <p>세션은 브라우저 메모리에만 유지됩니다. 역할에 따라 조회·진단 실행·관리 작업이 서버에서 구분됩니다.</p>
        <div className="field">
          <label htmlFor="organization-username">사용자명</label>
          <input id="organization-username" autoComplete="username" value={username} onChange={(event) => setUsername(event.target.value)} autoFocus required />
        </div>
        <div className="field">
          <label htmlFor="organization-password">비밀번호</label>
          <input id="organization-password" type="password" autoComplete="current-password" value={password} onChange={(event) => setPassword(event.target.value)} required />
        </div>
        {error && <div className="inline-alert">{error}</div>}
        <button className="button button--signal" disabled={busy}>{busy ? "확인 중…" : "워크벤치 접속"}</button>
      </form>
    </div>
  );
}

function LanSessionPrompt() {
  const [value, setValue] = useState("");
  const [error, setError] = useState("");
  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    try {
      configureLanSession(value);
      setValue("");
      setError("");
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "LAN 세션 인증 실패");
    }
  }
  return (
    <div className="auth-gate" role="dialog" aria-modal="true" aria-labelledby="lan-session-title">
      <form className="panel auth-gate__panel" onSubmit={submit}>
        <span className="eyebrow">LAN SESSION AUTHENTICATION</span>
        <h2 id="lan-session-title">LAN 세션 잠금 해제</h2>
        <p>실행 PowerShell이 클립보드에 복사한 임시 세션 문자열을 붙여넣으세요. 값은 메모리에만 유지되며 새로고침하면 사라집니다.</p>
        <div className="field">
          <label htmlFor="lan-session-token">API · 관리자 세션 문자열</label>
          <input
            id="lan-session-token"
            type="password"
            autoComplete="off"
            value={value}
            onChange={(event) => setValue(event.target.value)}
            autoFocus
            required
          />
        </div>
        {error && <div className="inline-alert">{error}</div>}
        <button className="button button--signal">세션 연결</button>
      </form>
    </div>
  );
}
