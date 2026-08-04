const API_BASE = "/api";

let accessToken = "";
let adminToken = "";
let authenticationRequired = false;

export function configureLanSession(value: string): void {
  const [nextAccess, nextAdmin, ...extra] = value.trim().split("|");
  if (extra.length || !nextAccess || !nextAdmin || nextAccess.length < 32 || nextAdmin.length < 32) {
    throw new Error("PowerShell이 복사한 LAN 세션 문자열 형식이 올바르지 않습니다.");
  }
  accessToken = nextAccess;
  adminToken = nextAdmin;
  authenticationRequired = false;
  window.dispatchEvent(new Event("msw-auth-updated"));
}

export function isAuthenticationRequired(): boolean {
  return authenticationRequired;
}

function requestAuthentication(): void {
  authenticationRequired = true;
  window.setTimeout(() => window.dispatchEvent(new Event("msw-auth-required")), 0);
}

function applySecurityHeaders(headers: Headers): void {
  if (accessToken) headers.set("Authorization", `Bearer ${accessToken}`);
  if (adminToken) headers.set("X-MSW-Admin-Token", adminToken);
}

export class ApiError extends Error {
  status: number;

  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

async function parseError(response: Response): Promise<string> {
  try {
    const value = await response.json();
    return typeof value.detail === "string"
      ? value.detail
      : JSON.stringify(value.detail ?? value);
  } catch {
    return `${response.status} ${response.statusText}`;
  }
}

export async function api<T>(
  path: string,
  options: RequestInit = {},
): Promise<T> {
  const headers = new Headers(options.headers);
  applySecurityHeaders(headers);
  if (options.body && !(options.body instanceof FormData)) {
    headers.set("Content-Type", "application/json");
  }
  const response = await fetch(`${API_BASE}${path}`, { ...options, headers });
  if (!response.ok) {
    if (response.status === 401) requestAuthentication();
    throw new ApiError(response.status, await parseError(response));
  }
  return response.json() as Promise<T>;
}

export function post<T>(path: string, body?: unknown): Promise<T> {
  return api<T>(path, {
    method: "POST",
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

export function patch<T>(path: string, body: unknown): Promise<T> {
  return api<T>(path, { method: "PATCH", body: JSON.stringify(body) });
}

export function put<T>(path: string, body: unknown): Promise<T> {
  return api<T>(path, { method: "PUT", body: JSON.stringify(body) });
}

export function remove<T>(path: string): Promise<T> {
  return api<T>(path, { method: "DELETE" });
}

export async function upload<T>(
  path: string,
  file: File,
  onProgress?: (value: number) => void,
): Promise<T> {
  if (!onProgress) {
    const data = new FormData();
    data.append("file", file);
    return api<T>(path, { method: "POST", body: data });
  }
  return new Promise<T>((resolve, reject) => {
    const request = new XMLHttpRequest();
    const data = new FormData();
    data.append("file", file);
    request.open("POST", `${API_BASE}${path}`);
    if (accessToken) request.setRequestHeader("Authorization", `Bearer ${accessToken}`);
    if (adminToken) request.setRequestHeader("X-MSW-Admin-Token", adminToken);
    request.upload.onprogress = (event) => {
      if (event.lengthComputable) onProgress(Math.round((event.loaded / event.total) * 100));
    };
    request.onerror = () => reject(new Error("업로드 연결이 중단되었습니다."));
    request.onload = () => {
      if (request.status >= 200 && request.status < 300) {
        resolve(JSON.parse(request.responseText) as T);
      } else {
        if (request.status === 401) requestAuthentication();
        try {
          reject(new ApiError(request.status, JSON.parse(request.responseText).detail));
        } catch {
          reject(new ApiError(request.status, request.statusText));
        }
      }
    };
    request.send(data);
  });
}

export async function runWebSocket(runId: string): Promise<WebSocket> {
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const issued = await post<{ ticket: string }>("/ws-ticket", { run_id: runId });
  return new WebSocket(
    `${protocol}//${window.location.host}${API_BASE}/runs/${runId}/ws?ticket=${encodeURIComponent(issued.ticket)}`,
  );
}
