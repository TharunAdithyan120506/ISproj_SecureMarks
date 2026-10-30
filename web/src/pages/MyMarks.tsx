import { useEffect, useState } from "react";
import { Image as ImageIcon } from "lucide-react";
import { download, post } from "../api";
import { RequireRole, useAuth } from "../auth";
import { Inspector, Outcome, WireView, type Call } from "../parts";
import { Card, Empty, Notice, PageHead, Pill, Spinner, bytes, fmt } from "../ui";

export default function MyMarks() {
  return (
    <>
      <PageHead eyebrow="Student · student-laptop" title="My marks"
        sub="Only your own roll number is ever returned. Every record, and its answer sheet, is checked on this device against the teacher's signature." />
      <RequireRole roles={["student"]}><Marks /></RequireRole>
    </>
  );
}

function Marks() {
  const { user } = useAuth();
  const [res, setRes] = useState<Call | null>(null);
  const [busy, setBusy] = useState(false);
  const [plain, setPlain] = useState<any>(null);
  const [other, setOther] = useState("240911612");
  const [idor, setIdor] = useState<Call | null>(null);
  const [sheets, setSheets] = useState<Record<string, any>>({});
  const [inspect, setInspect] = useState<"view" | "idor" | string>("view");

  const load = async () => {
    setBusy(true);
    try {
      setRes(await post("/api/marks", {}));
      setInspect("view");
    } finally {
      setBusy(false);
    }
  };
  useEffect(() => { load(); }, []);

  const openSheet = async (course: string) => {
    setSheets((s) => ({ ...s, [course]: { loading: true } }));
    const r = await post("/api/marks/sheet", { course });
    setSheets((s) => ({ ...s, [course]: r }));
    setInspect(`sheet:${course}`);
  };

  const records: any[] = res?.payload?.records || [];
  const shown = inspect === "idor" ? idor : inspect.startsWith("sheet:") ? sheets[inspect.slice(6)] : res;

  return (
    <div className="stack" style={{ gap: 18 }}>
      <div className="row">
        <button className="btn primary" onClick={load} disabled={busy}>Reload my marks</button>
        <button className="btn" onClick={async () => setPlain(await post("/api/marks/plain"))}>Fetch the plain baseline</button>
        {busy && <Spinner label="Decrypting and verifying" />}
        <span className="spacer" />
        <span className="muted">Roll <b className="mono">{user?.roll_no}</b></span>
      </div>

      {res && !res.ok && <Outcome res={res} />}
      {res?.ok && !records.length && <Card><Empty icon={<ImageIcon size={28} />} title="No marks published yet">Ask the teacher (t104) to publish from the Publish page.</Empty></Card>}

      {records.map((r) => {
        const rec = r.record;
        const sheet = sheets[rec.course];
        return (
          <Card key={r.record_id} tone={r.verified ? "ok" : "bad"} className="fade-in"
            title={<>{rec.course}</>}
            actions={r.verified
              ? <Pill tone="pass">Verified · signed by {r.signer} · {r.signer_fingerprint || r.key_fingerprint}</Pill>
              : <Pill tone="fail">Signature invalid · {r.sha_ok ? "signature does not match" : "hash mismatch"}</Pill>}>
            <div className="row" style={{ gap: 40 }}>
              {[["Midsem", rec.midsem, 50], ["Endsem", rec.endsem, 100], ["Total", rec.total, 150]].map(([l, v, max]) => (
                <div key={l as string}><div className="muted small">{l}</div><div className="big">{v}<span className="muted" style={{ fontSize: 16 }}> / {max}</span></div></div>
              ))}
            </div>
            <div className="muted small" style={{ marginTop: 10 }}>
              Published {rec.published_at} by {rec.teacher} · version {r.version} · record {r.record_id} · SHA-256 <span className="mono">{r.sha256.slice(0, 16)}…</span>
              {r.sign_ms != null && <> · signed in {fmt(r.sign_ms, 4)} ms · verified by the server in {fmt(r.verify_ms, 4)} ms</>}
            </div>
            {!r.verified && <div style={{ marginTop: 8 }}><Notice tone="fail"><b>Do not trust these numbers:</b> they were changed after the teacher signed them.</Notice></div>}
            {r.key_status === "revoked" && <div style={{ marginTop: 8 }}><Notice tone="warn">{r.signer}'s key was revoked on {r.key_revoked_at}; this record was signed before the revocation.</Notice></div>}
            {r.attachment && (
              <div style={{ marginTop: 14 }}>
                <div className="hr" />
                <div className="row">
                  <b>Answer sheet</b>
                  <span className="muted small">{r.attachment.mime} · {bytes(r.attachment.size_bytes)} · {r.attachment.width}×{r.attachment.height} · stored as {bytes(r.attachment.ciphertext_bytes)} ciphertext</span>
                  <span className="spacer" />
                  <button className="btn sm" onClick={() => openSheet(rec.course)} disabled={sheet?.loading}>{sheet?.loading ? "Decrypting…" : sheet ? "Reload" : "Decrypt and view"}</button>
                </div>
                {sheet && !sheet.loading && (sheet.ok ? (
                  <div className="row" style={{ alignItems: "flex-start", marginTop: 10, gap: 16 }}>
                    <img src={sheet.image} alt={`Answer sheet for ${rec.course}`} style={{ maxWidth: 360, width: "100%", borderRadius: 12, boxShadow: "var(--shadow)" }} />
                    <div className="stack" style={{ gap: 6, minWidth: 220, flex: 1 }}>
                      {sheet.payload.verified ? <Pill tone="pass">Verified · hash matches the signed record</Pill> : <Pill tone="fail">Image does not match the signed hash</Pill>}
                      <div className="small muted">Signed SHA-256 <span className="mono">{rec.attachment_sha256?.slice(0, 24)}…</span></div>
                      <div className="small muted">Computed here <span className="mono">{sheet.payload.computed_sha256.slice(0, 24)}…</span></div>
                      {!sheet.payload.verified && <Notice tone="fail">The image was replaced after the teacher signed. Do not trust it.</Notice>}
                    </div>
                  </div>
                ) : <div style={{ marginTop: 8 }}><Outcome res={sheet} /></div>)}
              </div>
            )}
          </Card>
        );
      })}

      {plain && (
        <Card title="Baseline /plain/marks" sub="No checks, no encryption: what anyone on the network reads."
          actions={<Pill tone={plain.status === 200 ? "warn" : "neutral"}>{plain.status} {plain.code}</Pill>}>
          <pre className="json">{JSON.stringify(plain.payload, null, 1) ?? "no plain record published"}</pre>
        </Card>
      )}

      <Card title="Try another roll number" sub="Authorisation demo: the roll number travels encrypted, and the server compares it with the roll in your token.">
        <div className="row">
          <input className="input mono" style={{ maxWidth: 220 }} value={other} onChange={(e) => setOther(e.target.value)} aria-label="Roll number" />
          <button className="btn" onClick={async () => { setIdor(await post("/api/marks", { roll_no: other.trim() })); setInspect("idor"); }}>View this roll</button>
          {idor && <Outcome res={idor} okText="returned marks" />}
        </div>
      </Card>

      {shown && shown.steps && (
        <div className="split">
          <WireView wire={shown.wire} onDownload={() => download(`/api/wire/${inspect === "view" ? "view" : inspect === "idor" ? "view" : "sheet"}`, "securemarks_wire.json")} />
          <Inspector res={shown} role="student" title={inspect === "idor" ? "Inspector · another roll" : inspect.startsWith("sheet:") ? "Inspector · answer sheet" : "Inspector · my marks"} />
        </div>
      )}
    </div>
  );
}
