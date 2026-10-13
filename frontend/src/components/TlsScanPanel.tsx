import { FormEvent, useEffect, useState } from "react";
import { api, post } from "../api";
import type { CapabilityHealth, DiagnosticRun, TlsScanResponse } from "../types";
import { StatusChip } from "./UI";

const TLS_LABELS: Record<string, string> = {
  "EFI-MA-41": "취약한 HTTPS 프로토콜",
  "EFI-MA-42": "취약한 HTTPS 암호 알고리즘",
  "EFI-MA-43": "취약한 HTTPS 컴포넌트",
  "EFI-MA-44": "취약한 HTTPS 재협상",
  "TLS-ANY": "사용자 정의 TLS 검사 종합",
};

export function TlsScanPanel({
  run,
  recordable,
  onRecorded,
}: {
  run: DiagnosticRun;
  recordable: boolean;
  onRecorded: () => void;
}) {
  const scope = run.options.control_validation as { allowed_network_hosts?: string[]; enabled?: boolean } | undefined;
  const allowed = scope?.enabled ? scope.allowed_network_hosts ?? [] : [];
  const [health, setHealth] = useState<CapabilityHealth | null>(null);
  const [targets, setTargets] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState<TlsScanResponse | null>(null);
  const mock = run.run_mode === "mock";

  useEffect(() => {
    void api<CapabilityHealth>("/assessment/tls-scanner")
      .then(setHealth)
      .catch(() => setHealth(null));
  }, []);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      const response = await post<TlsScanResponse>(`/runs/${run.id}/tls-scan`, {
        targets: targets.split(/[\s,]+/).map((item) => item.trim()).filter(Boolean),
      });
      setResult(response);
      onRecorded();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "TLS 구성 점검을 완료하지 못했습니다.");
    } finally {
      setBusy(false);
    }
  }

  const blocked = !recordable || (!mock && (!allowed.length || health?.status !== "available"));
  return (
    <section className="tls-scan" aria-label="서버 TLS 구성 점검">
      <div className="tls-scan__head">
        <div>
          <span className="eyebrow">SERVER TLS CONFIGURATION</span>
          <strong>HTTPS 프로토콜·암호·컴포넌트·재협상 점검</strong>
          <small>
            sslyze로 승인 서버의 TLS 핸드셰이크만 확인하고 원본 JSON을 tls_scan 증적으로 남깁니다. 권고안의 INSECURE 조건만 취약으로 판정합니다.
          </small>
        </div>
        <StatusChip
          value={mock ? "manual_required" : health?.status ?? "not_configured"}
          label={mock ? "SYNTHETIC MOCK" : health?.version ? `sslyze ${health.version}` : "sslyze 미설정"}
        />
      </div>
      {!mock && (
        <p className="tls-scan__scope">
          허용 서버 {allowed.length ? allowed.join(", ") : "없음 · Live 점검에는 승인 통제 검증 범위가 필요합니다."}
        </p>
      )}
      <form onSubmit={(event) => void submit(event)} className="tls-scan__form">
        <input
          aria-label="TLS 점검 대상"
          value={targets}
          onChange={(event) => setTargets(event.target.value)}
          placeholder={mock ? "api.mock.test" : allowed[0] ?? "host 또는 host:port"}
          disabled={blocked}
        />
        <button className="button button--primary button--small" disabled={busy || blocked || !targets.trim()}>
          {busy ? "점검 중…" : "TLS 구성 점검"}
        </button>
      </form>
      {!recordable && <small className="tls-scan__note">안전 일시정지 또는 종료된 Run에서만 기록할 수 있습니다.</small>}
      {error && <div className="inline-alert">{error}</div>}
      {result && (
        <div className="tls-scan__results">
          {Object.entries(result.control_results).map(([controlId, item]) => (
            <article key={controlId} className={item.vulnerable ? "tls-scan__row tls-scan__row--vulnerable" : "tls-scan__row"}>
              <code>{controlId}</code>
              <div>
                <strong>{TLS_LABELS[controlId] ?? controlId}</strong>
                {(item.vulnerable ? item.reasons : item.observations).slice(0, 4).map((line) => <small key={line}>{line}</small>)}
                {!item.complete && <small>일부 점검이 완료되지 않아 양호로 판단하지 않습니다.</small>}
              </div>
              <StatusChip
                value={item.vulnerable ? "failed" : item.complete ? "available" : "manual_required"}
                label={item.vulnerable ? "취약 조건" : item.complete ? "조건 없음" : "미완료"}
              />
            </article>
          ))}
          <small>
            {result.synthetic ? "SYNTHETIC MOCK · " : ""}
            증적 {result.evidence_id.slice(0, 8)} · 자동 확정 {result.confirmed_controls.join(", ") || "없음"}
          </small>
        </div>
      )}
    </section>
  );
}
