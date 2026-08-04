import { FormEvent, useEffect, useState } from "react";
import { Route, Routes } from "./router";
import { configureLanSession, isAuthenticationRequired } from "./api";
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

export default function App() {
  const [authRequired, setAuthRequired] = useState(isAuthenticationRequired);
  const [authVersion, setAuthVersion] = useState(0);
  useEffect(() => {
    const required = () => setAuthRequired(true);
    const updated = () => {
      setAuthRequired(false);
      setAuthVersion((value) => value + 1);
    };
    window.addEventListener("msw-auth-required", required);
    window.addEventListener("msw-auth-updated", updated);
    return () => {
      window.removeEventListener("msw-auth-required", required);
      window.removeEventListener("msw-auth-updated", updated);
    };
  }, []);
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
          <Route path="scripts" element={<ScriptsPage />} />
          <Route path="settings" element={<SettingsPage />} />
        </Route>
      </Routes>
      {authRequired && <LanSessionPrompt />}
    </>
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
