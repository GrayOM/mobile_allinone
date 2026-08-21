import { FormEvent, useEffect, useState } from "react";
import {
  api,
  getCurrentIdentity,
  patch,
  post,
  type AuthConfig,
  type OrganizationIdentity,
} from "../api";
import { EmptyState, SectionHeading, StatusChip, formatDate } from "../components/UI";

interface OrganizationUser extends OrganizationIdentity {
  enabled: boolean;
  last_login_at: string | null;
  created_at: string;
}

interface AuditEntry {
  id: string;
  actor_username: string;
  actor_role: string;
  action: string;
  method: string;
  path: string;
  status_code: number;
  outcome: string;
  client_host: string;
  request_id: string;
  previous_hash: string;
  entry_hash: string;
  created_at: string;
}

interface ChainStatus {
  valid: boolean;
  checked_count: number;
  failed_entry_id: string | null;
}

export default function AccessControlPage() {
  const [config, setConfig] = useState<AuthConfig | null>(null);
  const [identity, setIdentity] = useState<OrganizationIdentity | null>(getCurrentIdentity);
  const [users, setUsers] = useState<OrganizationUser[]>([]);
  const [audit, setAudit] = useState<AuditEntry[]>([]);
  const [chain, setChain] = useState<ChainStatus | null>(null);
  const [username, setUsername] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [role, setRole] = useState<OrganizationIdentity["role"]>("viewer");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");

  async function loadAdminRegister() {
    try {
      const [userRows, auditRows, chainStatus] = await Promise.all([
        api<OrganizationUser[]>("/auth/users"),
        api<AuditEntry[]>("/audit-logs?limit=100"),
        api<ChainStatus>("/audit-logs/verify"),
      ]);
      setUsers(userRows);
      setAudit(auditRows);
      setChain(chainStatus);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "접근 원장 조회 실패");
    }
  }

  useEffect(() => {
    void api<AuthConfig>("/auth/config").then((value) => {
      setConfig(value);
      const actor = getCurrentIdentity();
      setIdentity(actor);
      if (value.enabled && actor?.role === "admin") void loadAdminRegister();
    }).catch((reason: Error) => setError(reason.message));
  }, []);

  async function createUser(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError("");
    setMessage("");
    try {
      await post<OrganizationUser>("/auth/users", {
        username,
        display_name: displayName,
        role,
        password,
      });
      setUsername("");
      setDisplayName("");
      setRole("viewer");
      setPassword("");
      setMessage("조직 사용자를 만들고 감사 원장에 기록했습니다.");
      await loadAdminRegister();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "사용자 생성 실패");
    } finally {
      setBusy(false);
    }
  }

  async function updateUser(user: OrganizationUser, values: { role?: string; enabled?: boolean }) {
    setError("");
    try {
      await patch<OrganizationUser>(`/auth/users/${user.id}`, values);
      await loadAdminRegister();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "사용자 변경 실패");
    }
  }

  if (config && !config.enabled) {
    return (
      <div className="stack stack--lg">
        <SectionHeading eyebrow="ORGANIZATION ACCESS" title="조직 인증은 선택 기능입니다" description="단독 로컬 운영은 기존 loopback 경계를 그대로 사용합니다. 여러 운영자가 함께 쓸 때 환경변수로 조직 인증을 활성화하세요." />
        <section className="panel access-disabled">
          <code>MSW_ORGANIZATION_AUTH=true</code>
          <code>MSW_BOOTSTRAP_ADMIN_PASSWORD=&lt;12자 이상&gt;</code>
          <p>최초 실행에서만 관리자 계정을 만들며 이후 비밀번호 원문은 저장하지 않습니다.</p>
        </section>
      </div>
    );
  }

  return (
    <div className="stack stack--lg access-page">
      <SectionHeading eyebrow="IDENTITY · ROLE · AUDIT" title="운영 권한과 변경 이력을 한 원장에서 봅니다" description="viewer는 조회, operator는 진단 작업, admin은 사용자·도구·보존정책을 관리합니다. 모든 상태 변경은 요청 본문 없이 해시 체인 감사 로그로 남습니다." />
      {message && <div className="inline-alert inline-alert--ok">{message}</div>}
      {error && <div className="inline-alert">{error}</div>}

      <section className="access-ledger" aria-label="현재 조직 접근 상태">
        <div><span>IDENTITY</span><strong>{identity?.username ?? "—"}</strong><small>{identity?.display_name ?? "로그인 필요"}</small></div>
        <div><span>ROLE</span><strong>{identity?.role ?? "—"}</strong><small>server enforced</small></div>
        <div><span>SESSION</span><strong>{config?.session_hours ?? "—"}H</strong><small>메모리 전용 토큰</small></div>
        <div className={chain?.valid ? "health-ok" : "health-warn"}><span>AUDIT CHAIN</span><strong>{chain ? (chain.valid ? "VERIFIED" : "BROKEN") : "—"}</strong><small>{chain?.checked_count ?? 0} entries</small></div>
      </section>

      {identity?.role !== "admin" ? (
        <EmptyState title="관리자 원장" description="사용자와 감사 로그 조회는 admin 역할에만 허용됩니다." />
      ) : (
        <>
          <section className="panel access-user-panel">
            <div className="access-user-panel__head"><div><span className="eyebrow">PRINCIPAL REGISTER</span><h2>조직 사용자</h2></div><small>마지막 활성 admin은 강등·비활성화할 수 없습니다.</small></div>
            <form className="access-user-form" onSubmit={createUser}>
              <div className="field"><label htmlFor="access-username">사용자명</label><input id="access-username" value={username} onChange={(event) => setUsername(event.target.value)} pattern="[a-z][a-z0-9_.-]{2,63}" required /></div>
              <div className="field"><label htmlFor="access-display">표시 이름</label><input id="access-display" value={displayName} onChange={(event) => setDisplayName(event.target.value)} maxLength={120} required /></div>
              <div className="field"><label htmlFor="access-role">역할</label><select id="access-role" value={role} onChange={(event) => setRole(event.target.value as OrganizationIdentity["role"])}><option value="viewer">viewer</option><option value="operator">operator</option><option value="admin">admin</option></select></div>
              <div className="field"><label htmlFor="access-password">초기 비밀번호</label><input id="access-password" type="password" autoComplete="new-password" minLength={12} maxLength={128} value={password} onChange={(event) => setPassword(event.target.value)} required /></div>
              <button className="button button--signal" disabled={busy}>{busy ? "생성 중…" : "사용자 추가"}</button>
            </form>
            <div className="access-user-register">
              {users.map((user) => (
                <div key={user.id}>
                  <span className="access-user-register__identity"><strong>{user.username}</strong><small>{user.display_name}</small></span>
                  <select aria-label={`${user.username} 역할`} value={user.role} onChange={(event) => void updateUser(user, { role: event.target.value })}><option value="viewer">viewer</option><option value="operator">operator</option><option value="admin">admin</option></select>
                  <StatusChip value={user.enabled ? "available" : "stopped"} label={user.enabled ? "enabled" : "disabled"} />
                  <small>{formatDate(user.last_login_at)}</small>
                  <button className="button button--small button--quiet" onClick={() => void updateUser(user, { enabled: !user.enabled })}>{user.enabled ? "비활성화" : "활성화"}</button>
                </div>
              ))}
            </div>
          </section>

          <section className="panel audit-register">
            <div className="audit-register__head"><div><span className="eyebrow">APPEND-ONLY REGISTER</span><h2>최근 감사 로그</h2></div><StatusChip value={chain?.valid ? "available" : "failed"} label={chain?.valid ? "hash chain valid" : "verification failed"} /></div>
            <div className="audit-table">
              <div className="audit-table__head"><span>시각 · 행위자</span><span>작업</span><span>경로</span><span>결과</span><span>체인</span></div>
              {audit.map((entry) => (
                <div className="audit-table__row" key={entry.id}>
                  <span><strong>{formatDate(entry.created_at)}</strong><small>{entry.actor_username} · {entry.actor_role}</small></span>
                  <code>{entry.action}</code>
                  <span><strong>{entry.method} {entry.status_code}</strong><small>{entry.path}</small></span>
                  <StatusChip value={entry.outcome === "success" ? "completed" : "failed"} label={entry.outcome} />
                  <code title={entry.entry_hash}>{entry.entry_hash.slice(0, 10)}</code>
                </div>
              ))}
            </div>
          </section>
        </>
      )}
    </div>
  );
}
