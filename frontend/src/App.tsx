import { Route, Routes } from "./router";
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
  return (
    <Routes>
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
  );
}
