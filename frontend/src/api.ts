const API_BASE = "/api";

let accessToken = "";
let adminToken = "";
let organizationToken = "";
let organizationMode = false;
let currentIdentity: OrganizationIdentity | null = null;
let authenticationRequired: AuthenticationRequirement = null;

export type AuthenticationRequirement = "lan" | "organization" | null;

export interface AuthConfig {
  enabled: boolean;
  lan_access: boolean;
  session_hours: number;
}

export interface OrganizationIdentity {
  id: string;
  username: string;
  display_name: string;
  role: "viewer" | "operator" | "admin";
}

export function configureLanSession(value: string): void {
  const [nextAccess, nextAdmin, ...extra] = value.trim().split("|");
  if (extra.length || !nextAccess || !nextAdmin || nextAccess.length < 32 || nextAdmin.length < 32) {
    throw new Error("PowerShell이 복사한 LAN 세션 문자열 형식이 올바르지 않습니다.");
  }
  accessToken = nextAccess;
  adminToken = nextAdmin;
  authenticationRequired = null;
  window.dispatchEvent(new Event("msw-auth-updated"));
}

export function getAuthenticationRequirement(): AuthenticationRequirement {
  return authenticationRequired;
}

export function getCurrentIdentity(): OrganizationIdentity | null {
  return currentIdentity;
}

export function isOrganizationMode(): boolean {
  return organizationMode;
}

function requestAuthentication(kind?: Exclude<AuthenticationRequirement, null>): void {
  authenticationRequired = kind ?? (organizationMode ? "organization" : "lan");
  window.setTimeout(() => window.dispatchEvent(new Event("msw-auth-required")), 0);
}

function applySecurityHeaders(headers: Headers): void {
  if (accessToken) headers.set("X-MSW-Network-Token", accessToken);
  if (organizationToken) headers.set("Authorization", `Bearer ${organizationToken}`);
  else if (accessToken) headers.set("Authorization", `Bearer ${accessToken}`);
  if (adminToken && !organizationMode) headers.set("X-MSW-Admin-Token", adminToken);
}

export async function loadAuthConfig(): Promise<AuthConfig> {
  const config = await api<AuthConfig>("/auth/config");
  organizationMode = config.enabled;
  if (organizationMode && !organizationToken) requestAuthentication("organization");
  if (!organizationMode) {
    organizationToken = "";
    currentIdentity = null;
  }
  return config;
}

export async function loginOrganization(
  username: string,
  password: string,
): Promise<OrganizationIdentity> {
  const result = await api<{ token: string; expires_at: string; user: OrganizationIdentity }>(
    "/auth/login",
    { method: "POST", body: JSON.stringify({ username, password }) },
  );
  organizationToken = result.token;
  currentIdentity = result.user;
  authenticationRequired = null;
  window.dispatchEvent(new Event("msw-auth-updated"));
  return result.user;
}

export async function logoutOrganization(): Promise<void> {
  try {
    if (organizationToken) await post<{ status: string }>("/auth/logout");
  } finally {
    organizationToken = "";
    currentIdentity = null;
    if (organizationMode) requestAuthentication("organization");
    window.dispatchEvent(new Event("msw-auth-updated"));
  }
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

export async function apiBlob(path: string): Promise<Blob> {
  const headers = new Headers();
  applySecurityHeaders(headers);
  const response = await fetch(`${API_BASE}${path}`, { headers });
  if (!response.ok) {
    if (response.status === 401) requestAuthentication();
    throw new ApiError(response.status, await parseError(response));
  }
  return response.blob();
}

export async function downloadAuthenticatedFile(path: string, filename: string): Promise<void> {
  const blob = await apiBlob(path);
  const objectUrl = URL.createObjectURL(blob);
  try {
    const link = document.createElement("a");
    link.href = objectUrl;
    link.download = filename;
    link.rel = "noopener";
    document.body.appendChild(link);
    link.click();
    link.remove();
  } finally {
    window.setTimeout(() => URL.revokeObjectURL(objectUrl), 0);
  }
}

export async function openAuthenticatedFile(path: string): Promise<void> {
  const pending = window.open("about:blank", "_blank");
  if (pending) pending.opener = null;
  try {
    const blob = await apiBlob(path);
    const objectUrl = URL.createObjectURL(blob);
    if (pending) {
      pending.location.replace(objectUrl);
    } else {
      window.open(objectUrl, "_blank", "noopener,noreferrer");
    }
    window.setTimeout(() => URL.revokeObjectURL(objectUrl), 60_000);
  } catch (error) {
    pending?.close();
    throw error;
  }
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
    if (accessToken) request.setRequestHeader("X-MSW-Network-Token", accessToken);
    if (organizationToken) request.setRequestHeader("Authorization", `Bearer ${organizationToken}`);
    else if (accessToken) request.setRequestHeader("Authorization", `Bearer ${accessToken}`);
    if (adminToken && !organizationMode) request.setRequestHeader("X-MSW-Admin-Token", adminToken);
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
