import { useEffect, useState } from "react";
import { apiBlob, downloadAuthenticatedFile } from "../api";

export function AuthenticatedImage({ path, alt }: { path: string; alt: string }) {
  const [source, setSource] = useState("");
  const [error, setError] = useState("");

  useEffect(() => {
    let disposed = false;
    let objectUrl = "";
    setError("");
    void apiBlob(path)
      .then((blob) => {
        if (disposed) return;
        objectUrl = URL.createObjectURL(blob);
        setSource(objectUrl);
      })
      .catch((reason: Error) => {
        if (!disposed) setError(reason.message);
      });
    return () => {
      disposed = true;
      if (objectUrl) URL.revokeObjectURL(objectUrl);
    };
  }, [path]);

  return source ? <img src={source} alt={alt} /> : <div className="authenticated-image-loading">{error || "인증된 이미지 불러오는 중…"}</div>;
}

export function AuthenticatedDownload({
  path,
  filename,
  sha256,
}: {
  path: string;
  filename: string;
  sha256?: string | null;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  return (
    <button
      type="button"
      className="download-link"
      disabled={busy}
      onClick={async () => {
        setBusy(true);
        setError("");
        try {
          await downloadAuthenticatedFile(path, filename);
        } catch (reason) {
          setError(reason instanceof Error ? reason.message : "원본 내려받기 실패");
        } finally {
          setBusy(false);
        }
      }}
    >
      {error || (busy ? "내려받는 중…" : "원본 내려받기")} <span>SHA {sha256?.slice(0, 12)}…</span>
    </button>
  );
}
