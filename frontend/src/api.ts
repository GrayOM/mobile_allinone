const API_BASE = "/api";

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
  if (options.body && !(options.body instanceof FormData)) {
    headers.set("Content-Type", "application/json");
  }
  const response = await fetch(`${API_BASE}${path}`, { ...options, headers });
  if (!response.ok) {
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
    request.upload.onprogress = (event) => {
      if (event.lengthComputable) onProgress(Math.round((event.loaded / event.total) * 100));
    };
    request.onerror = () => reject(new Error("업로드 연결이 중단되었습니다."));
    request.onload = () => {
      if (request.status >= 200 && request.status < 300) {
        resolve(JSON.parse(request.responseText) as T);
      } else {
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

export function runWebSocket(runId: string): WebSocket {
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  return new WebSocket(
    `${protocol}//${window.location.host}${API_BASE}/runs/${runId}/ws`,
  );
}

