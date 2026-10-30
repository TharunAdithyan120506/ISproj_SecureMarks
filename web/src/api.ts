/* Thin client for the portal API. Every request carries this tab's X-Portal-Session id
   (sessionStorage), so two tabs are two devices with two separate SecureClients. */

function sessionId(): string {
  let sid = "";
  try {
    sid = sessionStorage.getItem("sm-session") || "";
    if (!sid) {
      sid = crypto.randomUUID().replace(/-/g, "");
      sessionStorage.setItem("sm-session", sid);
    }
  } catch {
    sid = (window as unknown as { __smSid?: string }).__smSid ||= Math.random().toString(36).slice(2) + Date.now().toString(36);
  }
  return sid;
}

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

async function handle<T>(r: Response): Promise<T> {
  if (!r.ok) {
    let msg = `${r.status} ${r.statusText}`;
    try {
      const j = await r.json();
      if (j?.detail) msg = typeof j.detail === "string" ? j.detail : JSON.stringify(j.detail);
    } catch {
      /* not JSON */
    }
    throw new ApiError(r.status, msg);
  }
  return r.json() as Promise<T>;
}

export function headers(extra: Record<string, string> = {}): Record<string, string> {
  return { "X-Portal-Session": sessionId(), ...extra };
}

export async function get<T = any>(path: string): Promise<T> {
  return handle<T>(await fetch(path, { headers: headers() }));
}

export async function post<T = any>(path: string, body?: unknown): Promise<T> {
  return handle<T>(await fetch(path, {
    method: "POST",
    headers: headers({ "Content-Type": "application/json" }),
    body: body === undefined ? undefined : JSON.stringify(body),
  }));
}

export async function postForm<T = any>(path: string, form: FormData): Promise<T> {
  return handle<T>(await fetch(path, { method: "POST", headers: headers(), body: form }));
}

/** POST and read a streamed text/plain response line by line. */
export async function stream(path: string, onText: (all: string) => void): Promise<string> {
  const r = await fetch(path, { method: "POST", headers: headers() });
  if (!r.ok || !r.body) throw new ApiError(r.status, `${r.status} ${r.statusText}`);
  const reader = r.body.getReader();
  const dec = new TextDecoder();
  let all = "";
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    all += dec.decode(value, { stream: true });
    onText(all);
  }
  return all;
}

/** Download a file the API produces (keeps the session header). */
export async function download(path: string, fallbackName: string, init?: RequestInit): Promise<void> {
  const r = await fetch(path, { ...init, headers: { ...headers(), ...(init?.headers || {}) } });
  if (!r.ok) throw new ApiError(r.status, `${r.status} ${r.statusText}`);
  const blob = await r.blob();
  const cd = r.headers.get("content-disposition") || "";
  const name = /filename="([^"]+)"/.exec(cd)?.[1] || fallbackName;
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function saveJson(data: unknown, name: string): void {
  const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: "application/json" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export const fileUrl = (p: string) => `/api/ops/file/${p}`;
