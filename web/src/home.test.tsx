import { render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { AuthProvider } from "./auth";
import Home from "./pages/Home";

const base = { courses: ["IT301"], device: "laptop", ip: "127.0.0.2", bound: true, token_expires_in: 800, session: null };
const USERS: Record<string, any> = {
  teacher: { ...base, username: "t104", role: "teacher", label: "Teacher" },
  student: { ...base, username: "s608", role: "student", label: "Student", roll_no: "240911608", courses: [] },
  ctrl: { ...base, username: "ctrl", role: "ctrl", label: "Exam controller", courses: [] },
  admin: { ...base, username: "admin", role: "admin", label: "Admin", courses: [] },
};
const audit = { chain_ok: true, broken_at: null, counts: { allowed: 10, denied: 2 },
  recent_refusals: [{ id: 7, ts: 1, device: "attacker", actor: "s612", action: "marks_view", code: "rate_limited" }] };
const DASH: Record<string, any> = {
  teacher: { role: "teacher", signing_key: { alg: "Ed25519", fingerprint: "ab12", status: "active" },
    last_publish: { ok: true, code: "ok", course: "IT301", roll_no: "240911608", total: 72, with_sheet: true, sign_ms: 0.2, record_id: 2 } },
  student: { role: "student", marks_ok: true, marks: [{ course: "IT301", midsem: 27, endsem: 45, total: 72, verified: true, signer: "t104", version: 1, sheet: true }] },
  ctrl: { role: "ctrl", audit },
  admin: { role: "admin", audit, keys: { data_keys: [{ version: 1, alg: "AES-256-GCM", status: "active", expires_at: "2027-01-01" }],
    signing_keys: [{ id: 1, username: "t104", alg: "Ed25519", status: "active" }] } },
};

function mockFetch(role: string | null) {
  return vi.fn(async (url: string) => {
    const body = url.startsWith("/api/me") ? { user: role ? USERS[role] : null }
      : url.startsWith("/api/dashboard") ? DASH[role!]
      : url.startsWith("/api/accounts") ? [{ username: "t104", password: "x", role: "teacher", label: "Teacher", detail: "IT301" }]
      : url.startsWith("/api/health") ? { middleware: { ok: true, sessions: 1, seen_request_ids: 2, demo_mode: true } } : {};
    return new Response(JSON.stringify(body), { status: 200, headers: { "Content-Type": "application/json" } });
  });
}

function renderHome() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={qc}><AuthProvider><MemoryRouter><Home /></MemoryRouter></AuthProvider></QueryClientProvider>);
}

describe("sign out", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("returns to the signed-out home and a new session id, even if the server call fails", async () => {
    let signedIn = true;
    const f = vi.fn(async (url: string, init?: RequestInit) => {
      if (url.startsWith("/api/logout")) {
        signedIn = false;
        throw new TypeError("network down");
      }
      const body = url.startsWith("/api/me") ? { user: signedIn ? USERS.teacher : null }
        : url.startsWith("/api/dashboard") ? DASH.teacher
        : url.startsWith("/api/accounts") ? [] : { middleware: null };
      void init;
      return new Response(JSON.stringify(body), { status: 200, headers: { "Content-Type": "application/json" } });
    });
    vi.stubGlobal("fetch", f);
    const { useAuth } = await import("./auth");
    function SignOut() {
      const { logout } = useAuth();
      return <button onClick={logout}>out</button>;
    }
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(<QueryClientProvider client={qc}><AuthProvider><MemoryRouter><SignOut /><Home /></MemoryRouter></AuthProvider></QueryClientProvider>);
    await screen.findByText("Last publish");
    const before = sessionStorage.getItem("sm-session");
    screen.getByText("out").click();
    expect(await screen.findByText("Sign in as a device")).toBeTruthy();
    expect(sessionStorage.getItem("sm-session")).not.toBe(before);
  });
});

describe("Home adapts to the viewer", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("signed out: offers devices to sign in as", async () => {
    vi.stubGlobal("fetch", mockFetch(null));
    renderHome();
    expect(await screen.findByText("Sign in as a device")).toBeTruthy();
    expect(await screen.findByLabelText(/Sign in as t104/)).toBeTruthy();
  });

  it.each([
    ["teacher", "Last publish"],
    ["student", "Your marks"],
    ["ctrl", "Recent refusals"],
    ["admin", "active data key"],
  ])("%s sees their own dashboard", async (role, heading) => {
    vi.stubGlobal("fetch", mockFetch(role));
    renderHome();
    await waitFor(() => expect(screen.getByText(heading)).toBeTruthy());
    expect(screen.getByText(new RegExp(`, ${USERS[role].username}$`))).toBeTruthy();
  });
});
