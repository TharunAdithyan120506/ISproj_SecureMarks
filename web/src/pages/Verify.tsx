import { useEffect, useState } from "react";
import { post } from "../api";
import { RequireRole, useAuth } from "../auth";
import { Inspector, Outcome, type Call } from "../parts";
import { Card, DataTable, Metric, OkPill, PageHead, Pill, Spinner } from "../ui";

const ACTIONS = ["", "login", "session_open", "marks_publish", "marks_view", "attachment_view", "idor_blocked", "marks_verify",
  "audit_list", "keys_list", "keys_rotate", "signing_revoke", "plain_publish", "plain_view", "demo_echo"];

export default function Verify() {
  return (
    <>
      <PageHead eyebrow="Exam controller · ctrl-pc" title="Verify & audit"
        sub="Verification runs server-side and returns only booleans: the marks never reach this screen. The audit log is hash-chained, so editing any row breaks every later hash." />
      <RequireRole roles={["ctrl", "admin"]}><Body /></RequireRole>
    </>
  );
}

function Body() {
  const { user } = useAuth();
  const [id, setId] = useState(1);
  const [v, setV] = useState<Call | null>(null);
  const [audit, setAudit] = useState<Call | null>(null);
  const [action, setAction] = useState("");
  const [outcome, setOutcome] = useState("");
  const [limit, setLimit] = useState(100);
  const [busy, setBusy] = useState(false);

  const loadAudit = async () => {
    setBusy(true);
    try {
      setAudit(await post("/api/audit", { action, outcome, limit }));
    } finally {
      setBusy(false);
    }
  };
  useEffect(() => { loadAudit(); }, [action, outcome, limit]);

  const p = v?.payload;
  const entries: any[] = audit?.payload?.entries || [];
  const counts: Record<string, number> = {};
  entries.forEach((e) => { counts[e.outcome] = (counts[e.outcome] || 0) + 1; });

  return (
    <div className="stack" style={{ gap: 18 }}>
      {user?.role === "ctrl" && (
        <Card title="Verify a record" sub="Record IDs appear in the teacher's publish result and in the audit log details below.">
          <div className="row">
            <input className="input" type="number" min={1} value={id} onChange={(e) => setId(+e.target.value)} style={{ maxWidth: 140 }} aria-label="Record ID" />
            <button className="btn primary" onClick={async () => setV(await post("/api/verify", { record_id: id }))}>Verify</button>
          </div>
          {v && (
            <div style={{ marginTop: 14 }} className="stack">
              {v.ok ? (
                <Card tone={p.sha256_ok && p.signature_ok ? "ok" : "bad"} title={`Record ${p.record_id} · ${p.course} · roll ${p.roll_no} · version ${p.version}`}>
                  <div className="row">
                    <OkPill ok={p.sha256_ok} yes="SHA-256 matches" no="SHA-256 mismatch" />
                    <OkPill ok={p.signature_ok} yes="Signature valid" no="Signature invalid" />
                    <span className="muted small">signed by {p.signer} ({p.sig_alg}, key {p.key_fingerprint}, {p.key_status})</span>
                  </div>
                  <div className="muted small" style={{ marginTop: 8 }}>No marks were returned to this device: the response carries only booleans and metadata.</div>
                </Card>
              ) : <Outcome res={v} />}
              <Inspector res={v} role="ctrl" title="Inspector · verify" />
            </div>
          )}
        </Card>
      )}

      <Card title="Audit log" actions={audit?.ok && (audit.payload.chain_ok
        ? <Pill tone="pass">Hash chain intact</Pill>
        : <Pill tone="fail">Hash chain broken at entry #{audit.payload.chain_broken_at}</Pill>)}
        sub="entry_hash = SHA-256(prev_hash + canonical entry), recomputed on every request">
        <div className="row" style={{ marginBottom: 14 }}>
          <label className="field"><span>Action</span>
            <select className="select" value={action} onChange={(e) => setAction(e.target.value)}>{ACTIONS.map((a) => <option key={a} value={a}>{a || "(any)"}</option>)}</select>
          </label>
          <label className="field"><span>Outcome</span>
            <select className="select" value={outcome} onChange={(e) => setOutcome(e.target.value)}>{["", "allowed", "denied", "error"].map((a) => <option key={a} value={a}>{a || "(any)"}</option>)}</select>
          </label>
          <label className="field"><span>Rows</span>
            <select className="select" value={limit} onChange={(e) => setLimit(+e.target.value)}>{[50, 100, 250, 500].map((a) => <option key={a}>{a}</option>)}</select>
          </label>
          <button className="btn" style={{ alignSelf: "flex-end" }} onClick={loadAudit}>Refresh</button>
          {busy && <Spinner label="Loading" />}
        </div>
        {audit && !audit.ok && <Outcome res={audit} />}
        <div className="grid g3" style={{ marginBottom: 14 }}>
          <Metric label="Allowed" value={counts.allowed || 0} />
          <Metric label="Denied" value={counts.denied || 0} tone={counts.denied ? "fail" : undefined} />
          <Metric label="Error" value={counts.error || 0} />
        </div>
        <DataTable rows={entries} rowClass={(r) => (r.outcome !== "allowed" ? "bad" : undefined)} columns={[
          { key: "id", label: "#" },
          { key: "ts", label: "Time", render: (r) => new Date(r.ts * 1000).toLocaleTimeString() },
          { key: "device", label: "Device" }, { key: "src_ip", label: "Source IP", code: true }, { key: "actor", label: "Actor" },
          { key: "action", label: "Action", code: true },
          { key: "outcome", label: "Outcome", render: (r) => <Pill tone={r.outcome === "allowed" ? "pass" : r.outcome === "denied" ? "fail" : "warn"}>{r.outcome}</Pill> },
          { key: "code", label: "Code", code: true }, { key: "detail", label: "Detail" },
          { key: "entry_hash", label: "Entry hash", code: true, render: (r) => r.entry_hash.slice(0, 12) + "…" },
        ]} />
      </Card>
    </div>
  );
}
