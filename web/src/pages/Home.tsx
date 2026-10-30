/* Home adapts to who is viewing, using iOS patterns:
     large title  ->  quick actions  ->  glanceable widgets  ->  inset grouped lists, details behind disclosure.
   signed out  -> what SecureMarks is, and one list to sign in as any device
   teacher     -> signing key, last publish        student -> own marks, verified on this device
   controller  -> audit chain and refusals         admin   -> key inventory and audit chain */
import { useState, type FormEvent, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import {
  Activity, BarChart3, ChevronRight, Cpu, FileSignature, FileText, Fingerprint, Gauge, Hash, Image as ImageIcon,
  KeyRound, Link2, Lock, Radio, ScrollText, ShieldAlert, ShieldCheck, Users,
} from "lucide-react";
import { get } from "../api";
import { useAuth, type User } from "../auth";
import { CipherStrip, Notice, Pill, Spinner, fmt } from "../ui";

type Action = { to: string; title: string; text: string; icon: ReactNode; primary?: boolean };

const LABS: Action[] = [
  { to: "/lab/text", title: "Text encryption", text: "Ciphertext JSON, avalanche, confusion, diffusion, speed", icon: <FileText size={17} /> },
  { to: "/lab/image", title: "Image encryption", text: "Cipher pixels, NPCR, UACI, entropy, correlation, PSNR", icon: <ImageIcon size={17} /> },
  { to: "/lab/hash", title: "Hashing", text: "Full digests and the three resistance properties", icon: <Hash size={17} /> },
  { to: "/lab/signatures", title: "Digital signatures", text: "Generation and verification time, stored per run", icon: <Fingerprint size={17} /> },
  { to: "/lab/kex", title: "Key agreement", text: "X25519: Alice and Bob agree, Eve cannot", icon: <Users size={17} /> },
  { to: "/attacks", title: "Attack lab", text: "Eleven attacks and their audit evidence", icon: <ShieldAlert size={17} /> },
  { to: "/traffic", title: "Traffic lab", text: "Packet capture, analysis, PCAP → SQLite and XML", icon: <Radio size={17} /> },
  { to: "/report", title: "Analysis report", text: "Every result and graph in one place", icon: <BarChart3 size={17} /> },
];

const ACTIONS: Record<User["role"], Action[]> = {
  teacher: [
    { to: "/publish", title: "Publish marks", text: "Sign and send, with an answer sheet", icon: <FileSignature size={18} />, primary: true },
    { to: "/lab/signatures", title: "Signature timings", text: "Sign and verify, measured", icon: <Fingerprint size={18} /> },
    { to: "/attacks", title: "Attack lab", text: "Try to forge or replay", icon: <ShieldAlert size={18} /> },
    { to: "/report", title: "Analysis report", text: "All results and graphs", icon: <BarChart3 size={18} /> },
  ],
  student: [
    { to: "/marks", title: "My marks", text: "Decrypt and verify", icon: <ScrollText size={18} />, primary: true },
    { to: "/lab/text", title: "Text encryption", text: "See your record encrypted", icon: <FileText size={18} /> },
    { to: "/lab/image", title: "Image encryption", text: "How answer sheets are protected", icon: <ImageIcon size={18} /> },
    { to: "/report", title: "Analysis report", text: "All results and graphs", icon: <BarChart3 size={18} /> },
  ],
  ctrl: [
    { to: "/verify", title: "Verify a record", text: "Hash and signature, no marks", icon: <ShieldCheck size={18} />, primary: true },
    { to: "/attacks", title: "Attack evidence", text: "Refused requests and traces", icon: <ShieldAlert size={18} /> },
    { to: "/traffic", title: "Traffic lab", text: "Join packets to the audit log", icon: <Radio size={18} /> },
    { to: "/report", title: "Analysis report", text: "All results and graphs", icon: <BarChart3 size={18} /> },
  ],
  admin: [
    { to: "/keys", title: "Manage keys", text: "Rotate, revoke, inspect", icon: <KeyRound size={18} />, primary: true },
    { to: "/verify", title: "Audit log", text: "Every decision, hash-chained", icon: <ShieldCheck size={18} /> },
    { to: "/attacks", title: "Attack lab", text: "Run the attack catalogue", icon: <ShieldAlert size={18} /> },
    { to: "/benchmarks", title: "Benchmarks", text: "Cost of every check", icon: <Gauge size={18} /> },
  ],
};

const INTRO: Record<User["role"], string> = {
  teacher: "Publish signed marks and answer sheets for your courses.",
  student: "Your marks, decrypted and checked against the teacher's signature on this device.",
  ctrl: "Verify records and read the audit log, without ever seeing a mark.",
  admin: "Manage data keys and signing keys, and watch the audit log.",
};

const CHECKS: [string, string][] = [
  ["Concurrency cap: 20 requests in flight", "503 busy"],
  ["Size cap: policy maximum, 5 MB hard cap", "413 too_large"],
  ["Token bucket per user (per IP before sign-in)", "429 rate_limited"],
  ["JWT valid and unexpired", "401 auth_failed"],
  ["Session exists, same user, policy strong enough", "401 · 403 policy_too_weak"],
  ["Freshness: timestamp within 30 s", "409 stale_request"],
  ["Request ID never seen before", "409 replay_detected"],
  ["AES-GCM decrypt with the session key and AAD", "400 integrity_failed"],
  ["Role and ownership", "403 forbidden"],
  ["Signature, key status, answer-sheet hash, 10 s timeout", "400 · 403 · 504"],
];

const greeting = () => {
  const h = new Date().getHours();
  return h < 12 ? "Good morning" : h < 18 ? "Good afternoon" : "Good evening";
};
const useHealth = () => useQuery({ queryKey: ["health"], queryFn: () => get("/api/health"), refetchInterval: 5000 });

export default function Home() {
  const { user, loading } = useAuth();
  if (loading) return <Spinner label="Loading" />;
  return (
    <>
      {user ? <Dashboard user={user} /> : <Welcome />}
      <h2 className="group-title">Labs <span className="muted" style={{ fontWeight: 400 }}>No sign-in needed</span></h2>
      <div className="list cols">
        {LABS.map((l) => (
          <Link key={l.to} to={l.to} className="list-row">
            <span className="sq" aria-hidden="true">{l.icon}</span>
            <span className="grow"><span className="title">{l.title}</span><span className="meta">{l.text}</span></span>
            <ChevronRight size={16} className="chev" aria-hidden="true" />
          </Link>
        ))}
      </div>
      <h2 className="group-title">How a protected request is checked</h2>
      <div className="list">
        <details className="disclose" style={{ padding: "12px 16px" }}>
          <summary><ChevronRight size={15} aria-hidden="true" /> Show the ten checks, in order</summary>
          <p className="muted small" style={{ margin: "6px 0 10px" }}>Every outcome, allowed or refused, is written to the hash-chained audit log.</p>
          <ol className="pipeline" style={{ margin: "0 -16px -12px" }}>
            {CHECKS.map(([check, code]) => <li key={check}><span>{check}</span><code>{code}</code></li>)}
          </ol>
        </details>
      </div>
    </>
  );
}

/* --- signed out ------------------------------------------------------------------------------------ */

function Welcome() {
  const { login } = useAuth();
  const accounts = useQuery({ queryKey: ["accounts"], queryFn: () => get<any[]>("/api/accounts") });
  const mw = useHealth().data?.middleware;
  const [busy, setBusy] = useState<string | null>(null);
  const [err, setErr] = useState("");
  const [u, setU] = useState("");
  const [p, setP] = useState("");

  const signIn = async (name: string, pw: string) => {
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
    signIn(u.trim(), p);
  };

  return (
    <section className="hero">
      <div>
        <div className="eyebrow">Security middleware · student marks portal</div>
        <h1 className="hero-title">Marks that stay <em>private</em>,<br />signed and provable.</h1>
        <p className="hero-sub">
          The app only says “confidential”. The middleware picks the algorithms, manages the keys, blocks replays and
          floods, and logs every decision, and the packet capture shows it on the wire.
        </p>
        <CipherStrip text='{"course":"IT301","roll_no":"240911608","endsem":45}' />
        <div className="facts">
          <span className="fact"><Lock size={13} aria-hidden="true" /> AES-256-GCM in transit and at rest</span>
          <span className="fact"><Fingerprint size={13} aria-hidden="true" /> Ed25519 signed records</span>
          <span className="fact"><KeyRound size={13} aria-hidden="true" /> X25519 session keys</span>
          <span className="fact"><Link2 size={13} aria-hidden="true" /> Hash-chained audit log</span>
          <span className="fact"><span className={`dot${mw ? "" : " off"}`} aria-hidden="true" /> {mw ? "Middleware online" : "Middleware offline"}</span>
        </div>
      </div>

      <div className="list" aria-labelledby="signin-title">
        <div className="list-head">
          <h2 id="signin-title" className="card-title">Sign in as a device</h2>
          <div className="card-sub">Each role has its own loopback address, so a capture shows separate hosts. Open another tab to be a second device.</div>
        </div>
        {(accounts.data || []).map((a) => (
          <button key={a.username} className="list-row" onClick={() => signIn(a.username, a.password)} disabled={!!busy}
            aria-label={`Sign in as ${a.username}, ${a.label}`}>
            <span className={`avatar ${a.role}`} aria-hidden="true">{a.username.slice(0, 2).toUpperCase()}</span>
            <span className="grow">
              <span className="title">{a.username} <span className="muted" style={{ fontWeight: 400 }}>· {a.label}{a.detail ? ` · ${a.detail}` : ""}</span></span>
              <span className="meta mono">{a.password}</span>
            </span>
            {busy === a.username ? <Spinner label="Verifying" /> : <ChevronRight size={16} className="chev" aria-hidden="true" />}
          </button>
        ))}
        {accounts.isLoading && <div style={{ padding: 18 }}><Spinner label="Loading accounts" /></div>}
        <div className="list-foot">
          <details className="disclose">
            <summary><ChevronRight size={15} aria-hidden="true" /> Use a username and password</summary>
            <form className="stack" style={{ marginTop: 10 }} onSubmit={submit}>
              <label className="field"><span>Username</span>
                <input className="input" value={u} onChange={(e) => setU(e.target.value)} autoComplete="username" required />
              </label>
              <label className="field"><span>Password</span>
                <input className="input" type="password" value={p} onChange={(e) => setP(e.target.value)} autoComplete="current-password" required />
              </label>
              <button className="btn primary" type="submit" disabled={!!busy}>{busy && busy === u.trim() ? "Verifying with Argon2id…" : "Sign in"}</button>
            </form>
          </details>
          {err && <div style={{ marginTop: 10 }}><Notice tone="fail">{err}</Notice></div>}
          <div className="muted small" style={{ marginTop: 8 }}>Demo-only passwords. Checked with Argon2id; you get a 15-minute token.</div>
        </div>
      </div>
    </section>
  );
}

/* --- signed in: one dashboard per role ------------------------------------------------------------ */

function Dashboard({ user }: { user: User }) {
  const d = useQuery({ queryKey: ["dashboard", user.username], queryFn: () => get("/api/dashboard"), refetchOnMount: "always" });
  const mins = Math.floor(user.token_expires_in / 60);
  return (
    <section>
      <div className="home-head">
        <span className={`avatar lg ${user.role}`} aria-hidden="true">{user.username.slice(0, 2).toUpperCase()}</span>
        <div className="grow">
          <div className="eyebrow">{user.label} · {user.device}</div>
          <h1 className="large-title">{greeting()}, {user.username}</h1>
          <div className="home-sub">{INTRO[user.role]}</div>
        </div>
      </div>

      <div className="actions">
        {ACTIONS[user.role].map((a) => (
          <Link key={a.title} to={a.to} className={`action${a.primary ? " primary" : ""}`}>
            <span className="sq" aria-hidden="true">{a.icon}</span>
            <b>{a.title}</b>
            <span>{a.text}</span>
          </Link>
        ))}
      </div>

      <h2 className="group-title">Overview {d.isFetching && <Spinner label="Updating" />}</h2>
      {d.error && <Notice tone="warn">{(d.error as Error).message}</Notice>}
      {d.data?.error && <Notice tone="warn">Some details could not be loaded: {d.data.error}</Notice>}
      <div className="widgets fade-in">
        {d.data && user.role === "teacher" && <TeacherWidgets d={d.data} user={user} />}
        {d.data && user.role === "student" && <StudentWidgets d={d.data} />}
        {d.data && (user.role === "ctrl" || user.role === "admin") && <AuditWidgets d={d.data} admin={user.role === "admin"} />}
        <div className="widget">
          <div className="widget-head"><Cpu size={14} aria-hidden="true" /> This device</div>
          <dl className="kv">
            <dt>Address</dt><dd className="mono">{user.ip}{user.bound ? "" : " (header)"}</dd>
            <dt>Token</dt><dd>{mins} min left</dd>
            <dt>Session</dt><dd>{user.session ? `${user.session.kex} · ${user.session.policy}` : "opens on first call"}</dd>
          </dl>
          <SystemFoot />
        </div>
      </div>
    </section>
  );
}

function SystemFoot() {
  const mw = useHealth().data?.middleware;
  return (
    <div className="widget-foot row" style={{ gap: 7 }}>
      <span className={`dot${mw ? "" : " off"}`} aria-hidden="true" />
      {mw ? <>Middleware online · {mw.sessions} sessions · {mw.seen_request_ids} request IDs seen</> : "Middleware offline"}
    </div>
  );
}

function TeacherWidgets({ d, user }: { d: any; user: User }) {
  const k = d.signing_key || {};
  const last = d.last_publish;
  return (
    <>
      <div className="widget">
        <div className="widget-head"><Fingerprint size={14} aria-hidden="true" /> Signing key
          <span className="end">{k.status === "active" ? <Pill tone="pass">active</Pill> : k.status ? <Pill tone="fail">{k.status}</Pill> : null}</span></div>
        <div className="widget-big mono" style={{ fontSize: 22 }}>{k.fingerprint || "–"}</div>
        <div className="muted small" style={{ marginTop: 4 }}>{k.alg || "Ed25519"} · courses {user.courses.join(", ") || "–"}</div>
        <div className="widget-foot">{k.status === "revoked"
          ? <span style={{ color: "var(--fail)" }}>Revoked: publishing is blocked until an admin re-keys you.</span>
          : "The private half never leaves this device."}</div>
      </div>
      <div className="widget">
        <div className="widget-head"><FileSignature size={14} aria-hidden="true" /> Last publish
          <span className="end">{last ? (last.ok ? <Pill tone="pass">published</Pill> : <Pill tone="fail">{last.code}</Pill>) : null}</span></div>
        {last ? (
          <>
            <div className="widget-big">{last.total}<span className="muted" style={{ fontSize: 15, fontWeight: 500 }}> / 150</span></div>
            <div className="muted small" style={{ marginTop: 4 }}>{last.course} · roll <span className="mono">{last.roll_no}</span>{last.record_id ? ` · record #${last.record_id}` : ""}</div>
            <div className="widget-foot">{last.with_sheet ? "Answer sheet attached · " : ""}signed in {fmt(last.sign_ms, 3)} ms</div>
          </>
        ) : (
          <>
            <div className="muted">Nothing published from this tab yet.</div>
            <div className="widget-foot"><Link to="/publish">Publish marks</Link></div>
          </>
        )}
      </div>
    </>
  );
}

function StudentWidgets({ d }: { d: any }) {
  const marks: any[] = d.marks || [];
  const verified = marks.filter((m) => m.verified).length;
  return (
    <>
      <div className="widget span2">
        <div className="widget-head"><ScrollText size={14} aria-hidden="true" /> Your marks
          <span className="end"><Link to="/marks">Details</Link></span></div>
        {!d.marks_ok && <Notice tone="warn">{d.marks_error}</Notice>}
        {d.marks_ok && !marks.length && <div className="muted">No marks have been published for you yet.</div>}
        <div>
          {marks.map((m) => (
            <div key={m.course} className="mark-row">
              <div><div style={{ fontWeight: 600 }}>{m.course}</div><div className="l">v{m.version} · {m.signer}{m.sheet ? " · answer sheet" : ""}</div></div>
              <div><div className="l">Midsem</div><div className="n">{m.midsem}</div></div>
              <div><div className="l">Endsem</div><div className="n">{m.endsem}</div></div>
              <div><div className="l">Total</div><div className="n">{m.total}</div></div>
              <div>{m.verified ? <Pill tone="pass">Verified</Pill> : <Pill tone="fail">Signature invalid</Pill>}</div>
            </div>
          ))}
        </div>
      </div>
      {marks.length > 0 && (
        <div className="widget">
          <div className="widget-head"><ShieldCheck size={14} aria-hidden="true" /> Integrity</div>
          <div className="widget-big">{verified}<span className="muted" style={{ fontSize: 15, fontWeight: 500 }}> of {marks.length} verified</span></div>
          <div className="widget-foot">{verified === marks.length ? "Every record matches the teacher's signature." : "A record changed after it was signed: do not trust it."}</div>
        </div>
      )}
    </>
  );
}

function AuditWidgets({ d, admin }: { d: any; admin: boolean }) {
  const a = d.audit;
  const keys = d.keys;
  const active = keys?.data_keys.find((x: any) => x.status === "active");
  return (
    <>
      {admin && keys && (
        <div className="widget">
          <div className="widget-head"><KeyRound size={14} aria-hidden="true" /> Keys <span className="end"><Link to="/keys">Manage</Link></span></div>
          <div className="widget-big">v{active?.version ?? "–"}<span className="muted" style={{ fontSize: 15, fontWeight: 500 }}> active data key</span></div>
          <div className="row" style={{ gap: 6, marginTop: 10 }}>
            {keys.signing_keys.map((s: any) => <Pill key={s.id} tone={s.status === "active" ? "pass" : "fail"}>{s.username} · {s.alg}</Pill>)}
          </div>
          <div className="widget-foot">{keys.data_keys.length} data keys, wrapped by the master key</div>
        </div>
      )}
      {a ? (
        <>
          <div className="widget">
            <div className="widget-head"><Link2 size={14} aria-hidden="true" /> Audit chain
              <span className="end">{a.chain_ok ? <Pill tone="pass">intact</Pill> : <Pill tone="fail">broken at #{a.broken_at}</Pill>}</span></div>
            <div className="counts">
              <div><b>{a.counts.allowed || 0}</b><span>allowed</span></div>
              <div><b style={{ color: a.counts.denied ? "var(--fail)" : undefined }}>{a.counts.denied || 0}</b><span>denied</span></div>
              <div><b>{a.counts.error || 0}</b><span>errors</span></div>
            </div>
            <div className="widget-foot">Last 300 decisions · <Link to="/verify">Open the log</Link></div>
          </div>
          {!admin && (
            <div className="widget">
              <div className="widget-head"><Activity size={14} aria-hidden="true" /> Recent refusals</div>
              {a.recent_refusals.length ? a.recent_refusals.slice(0, 4).map((r: any) => (
                <div key={r.id} className="row" style={{ justifyContent: "space-between", padding: "5px 0", borderTop: "1px solid var(--sep)" }}>
                  <span className="small">{r.action} · {r.actor || "anonymous"}</span><Pill tone="fail">{r.code}</Pill>
                </div>
              )) : <div className="muted">None yet. Run an attack from the Attack lab.</div>}
            </div>
          )}
        </>
      ) : <Notice tone="warn">The audit log could not be loaded.</Notice>}
    </>
  );
}
