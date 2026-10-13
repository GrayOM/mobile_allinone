import { useEffect, useState } from "react";
import { api, post } from "../api";
import type { AppArtifact, CapabilityHealth, IpaResignRecord } from "../types";
import { StatusChip, formatBytes, formatDate } from "./UI";

export function IpaResignPanel({
  app,
  mock,
  onUpdated,
}: {
  app: AppArtifact;
  mock: boolean;
  onUpdated: () => void;
}) {
  const [health, setHealth] = useState<CapabilityHealth | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [requestedBy, setRequestedBy] = useState(
    () => localStorage.getItem("msw.assessmentReviewer") ?? "",
  );
  const record = app.analysis_result.ios_resigned as IpaResignRecord | undefined;

  useEffect(() => {
    void api<CapabilityHealth>("/ios/signing").then(setHealth).catch(() => setHealth(null));
  }, []);

  async function resign() {
    if (!window.confirm(`이 IPA를 설정된 개발 인증서로 재서명할까요?\n\n원본 SHA-256: ${app.sha256}\n원본 업로드는 변경하지 않습니다.`)) return;
    setBusy(true);
    setError("");
    try {
      await post<IpaResignRecord>(`/apps/${app.id}/ios/resign`, {
        requested_by: requestedBy,
        confirm_original_sha256: app.sha256,
      });
      onUpdated();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "IPA 재서명을 완료하지 못했습니다.");
    } finally {
      setBusy(false);
    }
  }

  const ready = mock || health?.status === "available";
  return (
    <div className="ipa-resign">
      <div className="ipa-resign__head">
        <span className="panel-label">IPA 재서명 · macOS 불필요</span>
        <StatusChip
          value={mock ? "manual_required" : health?.status ?? "not_configured"}
          label={mock ? "SYNTHETIC MOCK" : health?.status === "available" ? `zsign ${health.version ?? ""}` : "설정 필요"}
        />
      </div>
      {!mock && health && health.status !== "available" && (
        <small>{health.message} {health.signing?.problems.join(" ")}</small>
      )}
      {record && (
        <small>
          최근 재서명 {formatDate(record.created_at)} · {formatBytes(record.size_bytes)} · SHA-256 {record.sha256?.slice(0, 16)}…
          {record.source_sha256 !== app.sha256 ? " · 원본과 불일치" : ""}
        </small>
      )}
      <div className="ipa-resign__actions">
        <input
          aria-label="재서명 요청자"
          value={requestedBy}
          onChange={(event) => setRequestedBy(event.target.value)}
          placeholder="요청자"
          maxLength={100}
        />
        <button
          type="button"
          className="button button--quiet button--small"
          onClick={() => void resign()}
          disabled={busy || !ready || !requestedBy.trim()}
        >
          {busy ? "재서명 중…" : "IPA 재서명"}
        </button>
      </div>
      {error && <div className="inline-alert">{error}</div>}
    </div>
  );
}
