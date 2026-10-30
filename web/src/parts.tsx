/* Domain components: call outcome, the inspector, the on-the-wire envelope, streamed consoles. */
import { useState, type ReactNode } from "react";
import { Terminal } from "lucide-react";
import { stream } from "./api";
import { Card, CopyButton, Hex, JsonView, Pill, Segmented, Spinner, cx, fmt } from "./ui";

export type Step = { side: string; step: string; detail: string; ok: boolean | null; t_ms: number };
export type Call = {
  ok: boolean; status: number; code: string; error?: string; detail?: string; elapsed_ms: number; request_id: string;
  trace_id?: string; path: string; payload: any; steps: Step[]; wire: any;
};

export function Outcome({ res, okText }: { res: Call; okText?: string }) {
  return (
    <div className="row">
      {res.ok ? <Pill tone="pass">{res.status} OK</Pill> : <Pill tone="fail">{res.status || "–"} {res.code}</Pill>}
      <span className={res.ok ? "" : "muted"}>{res.ok ? okText : res.detail}</span>
      <span className="muted small">· {fmt(res.elapsed_ms, 1)} ms · request {res.request_id?.slice(0, 8)}…</span>
    </div>
  );
}

const SIDE_LABEL: Record<string, string> = { teacher: "Teacher SDK", student: "Student SDK", ctrl: "Controller SDK", admin: "Admin SDK" };

export function Inspector({ res, role, title = "Inspector" }: { res: Call; role?: string; title?: string }) {
  const steps = res.steps || [];
  const server = steps.filter((s) => s.side === "server").length;
  const fails = steps.filter((s) => s.ok === false).length;
  return (
    <Card className="flush" title={undefined}>
      <div style={{ padding: "16px 18px 10px" }}>
        <h3 className="card-title">{title}</h3>
        <div className="card-sub">
          Request <span className="mono">{res.request_id}</span> · {steps.length - server} client steps · {server} server steps
          {fails ? ` · ${fails} failed` : ""} · keys shown as first 4 … last 4 bytes
        </div>
      </div>
      <div className="table-wrap" style={{ maxHeight: 560, borderRadius: 0 }}>
        <table className="t">
          <thead><tr><th>#</th><th>Side</th><th>Step</th><th>Value</th><th className="num">t+</th><th>Result</th></tr></thead>
          <tbody>
            {steps.map((s, i) => (
              <tr key={i} className={s.ok === false ? "bad" : undefined}>
                <td className="muted">{i + 1}</td>
                <td><span className={cx("tag", s.side === "server" ? "side-server" : "side-client")}>{s.side === "server" ? "Server" : SIDE_LABEL[role || ""] || "Client SDK"}</span></td>
                <td className="step-name">{s.step}</td>
                <td className="step-val" title={s.detail}>{s.detail.length > 170 ? s.detail.slice(0, 169) + "…" : s.detail}</td>
                <td className="num muted">{fmt(s.t_ms, 1)} ms</td>
                <td>{s.ok === null ? <Pill tone="neutral">skip</Pill> : s.ok ? <Pill tone="pass">pass</Pill> : <Pill tone="fail">fail</Pill>}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  );
}

/** The protected request exactly as it crossed the network: headers, AAD, nonce, ciphertext, tag. */
export function WireView({ wire, onDownload, extra }: { wire: any; onDownload?: () => void; extra?: ReactNode }) {
  const [view, setView] = useState<"envelope" | "json">("envelope");
  if (!wire) return null;
  const req = wire.request;
  return (
    <Card title="On the wire" sub={`${wire.cipher} · policy ${wire.policy} · what Wireshark sees`}
      actions={<>
        <Segmented label="View" value={view} onChange={setView} options={[{ value: "envelope", label: "Envelope" }, { value: "json", label: "JSON" }]} />
        {onDownload && <button className="btn sm" onClick={onDownload}>Download full JSON</button>}
      </>}>
      {view === "json" ? <JsonView data={wire} /> : (
        <div className="stack" style={{ gap: 4 }}>
          <div className="hex short" style={{ whiteSpace: "pre-wrap" }}>
            {`${req.method} ${req.path} HTTP/1.1\n` + Object.entries(req.headers).map(([k, v]) => `${k}: ${v}`).join("\n")}
          </div>
          <Hex label="AAD (authenticated, not encrypted)" hex={new TextEncoder().encode(req.aad).reduce((s, b) => s + b.toString(16).padStart(2, "0"), "")}
            note={req.aad} short />
          <Hex label="Nonce" hex={req.nonce_hex} short />
          <Hex label="Ciphertext body" hex={req.body_hex}
            note={`${req.body_bytes.toLocaleString()} B incl. 16 B tag${req.truncated ? ", first 512 B shown" : ""}`} />
          <Hex label="GCM tag" hex={req.tag_hex} short />
          <div className="hexlabel"><span><b>Response</b> · {wire.response.status} · {wire.response.body_bytes.toLocaleString()} B ciphertext · nonce {wire.response.nonce_b64}</span></div>
          {extra}
        </div>
      )}
    </Card>
  );
}

/** Runs a streamed job (attack, experiment, benchmark) and shows its console. */
export function StreamRunner({ path, label, onDone, primary }: { path: string; label: string; onDone?: (out: string) => void; primary?: boolean }) {
  const [out, setOut] = useState("");
  const [busy, setBusy] = useState(false);
  const run = async () => {
    setBusy(true);
    setOut("");
    try {
      const all = await stream(path, setOut);
      onDone?.(all);
    } catch (e: any) {
      setOut((o) => o + `\n${e.message}`);
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="stack">
      <div className="row">
        <button className={cx("btn", primary && "primary")} onClick={run} disabled={busy}><Terminal size={15} aria-hidden="true" /> {label}</button>
        {busy && <Spinner label="Running" />}
        {out && !busy && <CopyButton text={out} label="Copy output" />}
      </div>
      {out && <pre className="console" aria-live="polite">{out}</pre>}
    </div>
  );
}
