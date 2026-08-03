import { NavLink, Outlet, useLocation } from "../router";
import { useEffect, useState } from "react";

const navigation = [
  { to: "/", label: "대시보드", mark: "D", end: true },
  { to: "/projects", label: "프로젝트", mark: "P" },
  { to: "/devices", label: "연결 단말", mark: "M" },
  { to: "/diagnostics/new", label: "진단 시작", mark: "R" },
  { to: "/findings", label: "발견항목", mark: "F" },
  { to: "/coverage", label: "통제 커버리지", mark: "V" },
  { to: "/scripts", label: "Frida 라이브러리", mark: "S" },
  { to: "/settings", label: "설정", mark: "C" },
];

const titles: Record<string, string> = {
  "/": "진단 현황",
  "/projects": "프로젝트와 앱",
  "/devices": "연결 단말",
  "/diagnostics/new": "진단 설정",
  "/findings": "발견항목",
  "/coverage": "보안통제 커버리지",
  "/scripts": "Frida 스크립트 라이브러리",
  "/settings": "도구와 AI 설정",
};

export default function Layout() {
  const location = useLocation();
  const [mobileOpen, setMobileOpen] = useState(false);
  const title =
    titles[location.pathname] ??
    (location.pathname.startsWith("/runs/")
      ? "실시간 진단"
      : location.pathname.startsWith("/findings/")
        ? "발견항목 상세"
        : "Mobile Security Workbench");

  useEffect(() => setMobileOpen(false), [location.pathname]);

  return (
    <div className="app-shell">
      <aside className={`sidebar ${mobileOpen ? "sidebar--open" : ""}`}>
        <div className="brand">
          <div className="brand__sigil" aria-hidden="true">
            <span />
            <span />
            <span />
          </div>
          <div>
            <strong>Workbench</strong>
            <small>Mobile security</small>
          </div>
        </div>
        <nav aria-label="주 탐색">
          {navigation.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              className={({ isActive }) =>
                `nav-item ${isActive ? "nav-item--active" : ""}`
              }
            >
              <span className="nav-item__mark">{item.mark}</span>
              <span>{item.label}</span>
            </NavLink>
          ))}
        </nav>
        <div className="sidebar__foot">
          <span className="pulse-dot" />
          <div>
            <strong>Local only</strong>
            <small>127.0.0.1</small>
          </div>
        </div>
      </aside>
      {mobileOpen && (
        <button
          className="sidebar-scrim"
          aria-label="탐색 닫기"
          onClick={() => setMobileOpen(false)}
        />
      )}
      <div className="workspace">
        <header className="topbar">
          <button
            className="menu-button"
            aria-label="탐색 열기"
            onClick={() => setMobileOpen((value) => !value)}
          >
            ≡
          </button>
          <div>
            <span className="topbar__context">AUTHORIZED DIAGNOSTICS</span>
            <h1>{title}</h1>
          </div>
          <div className="topbar__state">
            <span className="status-dot status-dot--ok" />
            로컬 서버 연결됨
          </div>
        </header>
        <main className="page">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
