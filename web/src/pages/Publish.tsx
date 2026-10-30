import { useRef, useState, type FormEvent } from "react";
import { ImagePlus, X } from "lucide-react";
import { download, postForm } from "../api";
import { RequireRole, useAuth } from "../auth";
import { Inspector, Outcome, WireView, type Call } from "../parts";
import { Card, Hex, Metric, Notice, PageHead, Pill, Segmented, Spinner, bytes, fmt } from "../ui";

export default function Publish() {
  return (
    <>
      <PageHead eyebrow="Teacher · teacher-laptop" title="Publish marks"
        sub="The record, and the answer-sheet image if you attach one, is hashed and signed with your Ed25519 key on this device, then sent inside an X25519 + AES-GCM envelope." />
      <RequireRole roles={["teacher"]}><PublishForm /></RequireRole>
    </>
  );
}

function PublishForm() {
  const { user } = useAuth();
  const [course, setCourse] = useState(user?.courses[0] || "IT301");
  const [roll, setRoll] = useState("240911608");
  const [mid, setMid] = useState(27);
  const [end, setEnd] = useState(45);
  const [policy, setPolicy] = useState<"confidential" | "legacy-rsa">("confidential");
  const [baseline, setBaseline] = useState(false);
  const [file, setFile] = useState<File | null>(null);
  const [preview, setPreview] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [res, setRes] = useState<(Call & Record<string, any>) | null>(null);
  const input = useRef<HTMLInputElement>(null);

  const pick = (f: File | null) => {
    setFile(f);
    if (preview) URL.revokeObjectURL(preview);
    setPreview(f ? URL.createObjectURL(f) : null);
  };

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setErr("");
    const fd = new FormData();
    fd.append("course", course);
    fd.append("roll_no", roll);
    fd.append("midsem", String(mid));
    fd.append("endsem", String(end));
    fd.append("policy", policy);
    fd.append("baseline", String(baseline));
    if (file) fd.append("sheet", file);
    try {
      setRes(await postForm("/api/publish", fd));
    } catch (e: any) {
      setErr(e.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="stack" style={{ gap: 18 }}>
      <Card>
        <form className="stack" onSubmit={submit}>
          <div className="grid g4">
            <label className="field"><span>Course</span>
              <select className="select" value={course} onChange={(e) => setCourse(e.target.value)}>
                {(user?.courses.length ? user.courses : ["IT301"]).map((c) => <option key={c}>{c}</option>)}
              </select>
            </label>
            <label className="field"><span>Roll number</span><input className="input mono" value={roll} onChange={(e) => setRoll(e.target.value)} inputMode="numeric" required /></label>
            <label className="field"><span>Midsem (out of 50)</span><input className="input" type="number" min={0} max={50} value={mid} onChange={(e) => setMid(+e.target.value)} /></label>
            <label className="field"><span>Endsem (out of 100)</span><input className="input" type="number" min={0} max={100} value={end} onChange={(e) => setEnd(+e.target.value)} /></label>
          </div>
          <div className="grid g2" style={{ alignItems: "start" }}>
            <div className="stack" style={{ gap: 10 }}>
              <div className="field"><span>Security policy</span>
                <Segmented label="Policy" value={policy} onChange={setPolicy}
                  options={[{ value: "confidential", label: "Confidential · X25519 + Ed25519" }, { value: "legacy-rsa", label: "Legacy · RSA-OAEP + RSA-PSS" }]} />
              </div>
              <label className="check"><input type="checkbox" checked={baseline} onChange={(e) => setBaseline(e.target.checked)} />
                Also send the same marks to /plain/publish (unprotected baseline for experiment 1)</label>
            </div>
            <div className="field"><span>Answer sheet (optional image, signed and encrypted)</span>
              {file ? (
                <div className="row" style={{ alignItems: "center" }}>
                  {preview && <img src={preview} alt="Selected answer sheet" style={{ width: 64, height: 64, objectFit: "cover", borderRadius: 10 }} />}
                  <div className="small"><b>{file.name}</b><div className="muted">{bytes(file.size)} · photos are resized to ≤ 350 KB</div></div>
                  <button type="button" className="btn plain sm" onClick={() => pick(null)}><X size={14} /> Remove</button>
                </div>
              ) : (
                <button type="button" className="drop" onClick={() => input.current?.click()}><ImagePlus size={18} style={{ verticalAlign: -4 }} /> Choose an image (PNG, JPEG or WebP)</button>
              )}
              <input ref={input} type="file" accept="image/*" hidden onChange={(e) => pick(e.target.files?.[0] || null)} />
            </div>
          </div>
          <div className="row end">
            {busy && <Spinner label="Signing, encrypting, sending" />}
            <button className="btn primary" type="submit" disabled={busy}>Sign and publish</button>
          </div>
        </form>
      </Card>

      {err && <Notice tone="fail">{err}</Notice>}
      {!res && !err && <Notice>Fill in the form and publish. Then open a second tab, sign in as s608 and open <b>My marks</b>.</Notice>}

      {res && (
        <div className="stack fade-in" style={{ gap: 16 }}>
          <Card tone={res.ok ? "ok" : "bad"} title={res.ok ? "Published" : "Refused"} actions={<Outcome res={res} okText="" />}>
            {res.ok ? (
              <div className="stack" style={{ gap: 8 }}>
                <div className="muted">Record {res.payload.record_id} · version {res.payload.version} · stored as AES-256-GCM ciphertext under the data key</div>
                <Hex label="SHA-256 of the canonical record" hex={res.payload.sha256} short />
                <Hex label={`${policy === "legacy-rsa" ? "RSA-PSS" : "Ed25519"} signature`} hex={res.signature_hex || ""} short />
              </div>
            ) : <div>{res.detail}</div>}
          </Card>
          <div className="grid g4">
            <Metric label="Signature generation" value={fmt(res.sign_ms, 4)} unit="ms" foot="on this device, stored with the record" />
            <Metric label="Signature verification" value={fmt(res.payload?.verify_ms, 4)} unit="ms" foot="by the server, stored with the record" />
            <Metric label="Round trip" value={fmt(res.elapsed_ms, 1)} unit="ms" foot="encrypt → 10 checks → encrypted reply" />
            <Metric label="Request on the wire" value={bytes(res.wire?.request.body_bytes || 0)} foot={res.sheet ? `includes a ${bytes(res.sheet.bytes)} answer sheet` : "ciphertext + 16 B tag"} />
          </div>
          {res.sheet && (
            <Notice tone="pass">Answer sheet {res.sheet.mime} {bytes(res.sheet.bytes)}{res.sheet.original && res.sheet.original.bytes !== res.sheet.bytes ? ` (resized from ${bytes(res.sheet.original.bytes)})` : ""}.
              Its SHA-256 <span className="mono">{res.sheet.sha256.slice(0, 16)}…</span> is inside the signed record, so the signature covers the image too.</Notice>
          )}
          {res.baseline && (
            <Card title="Baseline /plain/publish" actions={<Pill tone={res.baseline.status === 200 ? "warn" : "fail"}>{res.baseline.status} {res.baseline.code}</Pill>}
              sub="The same marks, readable by anyone on the wire. This is what experiment 1 contrasts against.">
              <pre className="json">{JSON.stringify(res.baseline.body)}</pre>
            </Card>
          )}
          <div className="split">
            <WireView wire={res.wire} onDownload={() => download("/api/wire/publish", "securemarks_publish.json")} />
            <Inspector res={res} role="teacher" />
          </div>
        </div>
      )}
    </div>
  );
}
