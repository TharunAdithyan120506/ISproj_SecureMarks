import { useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { BarChart3, FileText, Fingerprint, Hash, Image as ImageIcon, Radio, ShieldAlert, Users } from "lucide-react";
import { get } from "../api";
import { useAuth } from "../auth";
import { Card, DataTable, Metric, Notice, PageHead, Section, Spinner } from "../ui";

const ROLE_HOME: Record<string, { to: string; label: string }[]> = {
  teacher: [{ to: "/publish", label: "Publish marks" }],
  student: [{ to: "/marks", label: "My marks" }],
  ctrl: [{ to: "/verify", label: "Verify & audit" }],
  admin: [{ to: "/keys", label: "Keys" }, { to: "/verify", label: "Audit log" }],
};

const LABS = [
  { to: "/lab/text", title: "Text encryption", text: "Ciphertext as JSON, avalanche, confusion and diffusion, speed against length.", icon: <FileText size={19} />, color: "#0A5BD8" },
  { to: "/lab/image", title: "Image encryption", text: "RGB pixels in, cipher pixels out. NPCR, UACI, entropy, correlation, PSNR, MSE.", icon: <ImageIcon size={19} />, color: "#E08600" },
  { to: "/lab/hash", title: "Hashing", text: "Full digests, generation time, pre-image, second pre-image and collision resistance.", icon: <Hash size={19} />, color: "#1E8E4A" },
  { to: "/lab/signatures", title: "Digital signatures", text: "Generation and verification time, stored for every run, tamper detection.", icon: <Fingerprint size={19} />, color: "#5856D6" },
  { to: "/lab/kex", title: "Key agreement", text: "X25519: Alice and Bob agree, Eve on the wire cannot.", icon: <Users size={19} />, color: "#0A84A8" },
  { to: "/attacks", title: "Attack lab", text: "Ten attacks against the live server and the audit evidence for each.", icon: <ShieldAlert size={19} />, color: "#C4251C" },
  { to: "/traffic", title: "Traffic lab", text: "Packet capture, PyShark analysis, PCAP → SQLite and XML.", icon: <Radio size={19} />, color: "#2A78D6" },
  { to: "/report", title: "Analysis report", text: "Every security and performance result, with graphs.", icon: <BarChart3 size={19} />, color: "#6E6E73" },
];

const CHECKS = [
  ["1", "Concurrency cap (20 in flight)", "503 busy"],
  ["2", "Size cap (policy maximum, 5 MB hard cap)", "413 too_large"],
  ["3", "Token bucket per user (per IP before login)", "429 rate_limited"],
  ["4", "JWT valid and unexpired", "401 auth_failed"],
  ["5", "Session exists, same user, policy strong enough", "401 session_invalid · 403 policy_too_weak"],
  ["6", "Freshness: X-Timestamp within 30 s", "409 stale_request"],
  ["7", "Request ID never seen before", "409 replay_detected"],
  ["8", "AES-GCM decrypt with the session key and AAD", "400 integrity_failed"],
  ["9", "Role and ownership", "403 forbidden"],
  ["10", "Ed25519 signature, key not revoked, answer-sheet hash, 10 s timeout", "400 bad_signature · 403 key_revoked · 400 attachment_mismatch"],
].map(([n, check, code]) => ({ n, check, code }));

export default function Home() {
  const { user, login } = useAuth();
  const accounts = useQuery({ queryKey: ["accounts"], queryFn: () => get<any[]>("/api/accounts") });
  const health = useQuery({ queryKey: ["health"], queryFn: () => get("/api/health") });
  const [u, setU] = useState("");
  const [p, setP] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const [err, setErr] = useState("");

  const doLogin = async (name: string, pw: string) => {
    setBusy(name);
    setErr("");
    try {
      await login(name, pw);
    } catch (e: any) {
      setErr(e.message);
    } finally {
      setBusy(null);
    }
  };
  const submit = (e: FormEvent) => {
    e.preventDefault();
    doLogin(u.trim(), p);
  };
  const mw = health.data?.middleware;

  return (
    <>
      <PageHead eyebrow="Security middleware · Student marks portal" title="SecureMarks"
        sub="The app only says “confidential”. The middleware picks the algorithms, manages the keys, blocks replays and floods, and logs every decision, and the packet capture proves it."
        strip='{"course":"IT301","roll_no":"240911608","endsem":45}' />

      {!user ? (
        <div className="split">
          <Card title="Sign in" sub="Your role picks the simulated device: each role has its own loopback IP, so a capture shows separate hosts.">
            <form className="stack" onSubmit={submit}>
              <label className="field"><span>Username</span>
                <input className="input" value={u} onChange={(e) => setU(e.target.value)} placeholder="t104, s608, s612, ctrl or admin" autoComplete="username" required />
              </label>
              <label className="field"><span>Password</span>
                <input className="input" type="password" value={p} onChange={(e) => setP(e.target.value)} autoComplete="current-password" required />
              </label>
              <button className="btn primary block" type="submit" disabled={!!busy}>{busy && busy === u.trim() ? "Verifying with Argon2id…" : "Sign in"}</button>
              {err && <Notice tone="fail">{err}</Notice>}
            </form>
          </Card>
          <Card title="Demo accounts" sub="Demo-only passwords. One click signs this tab in as that device; open a second tab for a second device.">
            <div className="stack" style={{ gap: 8 }}>
              {(accounts.data || []).map((a) => (
                <div key={a.username} className="row" style={{ justifyContent: "space-between" }}>
                  <div className="row" style={{ gap: 12 }}>
                    <div className={`avatar ${a.role}`} aria-hidden="true">{a.username.slice(0, 2).toUpperCase()}</div>
                    <div>
                      <div className="profile-name">{a.username} <span className="muted" style={{ fontWeight: 400 }}>· {a.label}{a.detail ? ` · ${a.detail}` : ""}</span></div>
                      <div className="profile-meta mono">{a.password}</div>
                    </div>
                  </div>
                  <button className="btn sm" onClick={() => doLogin(a.username, a.password)} disabled={!!busy}>
                    {busy === a.username ? "Signing in…" : `Sign in as ${a.username}`}
                  </button>
                </div>
              ))}
              {accounts.isLoading && <Spinner label="Loading accounts" />}
            </div>
          </Card>
        </div>
      ) : (
        <Card>
          <div className="row" style={{ gap: 16 }}>
            <div className={`avatar lg ${user.role}`} aria-hidden="true">{user.username.slice(0, 2).toUpperCase()}</div>
            <div style={{ flex: 1, minWidth: 220 }}>
              <div style={{ fontSize: 20, fontWeight: 650, letterSpacing: "-0.01em" }}>Welcome, {user.username}</div>
              <div className="muted">{user.label} on {user.device} · <span className="mono">{user.ip}</span>
                {user.bound ? "" : " · loopback binding unavailable, the X-Device header identifies this device"}</div>
            </div>
            {ROLE_HOME[user.role].map((l) => <Link key={l.to} className="btn primary" to={l.to}>{l.label}</Link>)}
          </div>
        </Card>
      )}

      <Section title="Labs" sub="Security and performance analysis of every primitive the middleware uses. No sign-in needed.">
        <div className="grid g4">
          {LABS.map((l) => (
            <Link key={l.to} to={l.to} className="tile">
              <div className="tile-icon" style={{ background: l.color }} aria-hidden="true">{l.icon}</div>
              <div className="tile-title">{l.title}</div>
              <div className="tile-text">{l.text}</div>
            </Link>
          ))}
        </div>
      </Section>

      <Section title="Status">
        <div className="grid g4">
          <Metric label="Middleware" value={mw ? "Online" : "Offline"} tone={mw ? "pass" : "fail"} foot={mw ? "127.0.0.1:8000" : "run python scripts\\run_demo.py"} />
          <Metric label="Open sessions" value={mw?.sessions ?? "–"} foot="X25519 + HKDF session keys" />
          <Metric label="Seen request IDs" value={mw?.seen_request_ids ?? "–"} foot="replay protection set" />
          <Metric label="Demo mode" value={mw ? (mw.demo_mode ? "On" : "Off") : "–"} foot="traces + plain baseline" />
        </div>
      </Section>

      <Section title="How a protected call is checked" sub="Every outcome is written to the hash-chained audit log; in demo mode every step is also traced.">
        <Card className="flush">
          <DataTable rows={CHECKS} columns={[{ key: "n", label: "#" }, { key: "check", label: "Check" }, { key: "code", label: "Refused with", code: true }]} />
        </Card>
      </Section>
    </>
  );
}
