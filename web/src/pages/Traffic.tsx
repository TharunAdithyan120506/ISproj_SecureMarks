import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Radio } from "lucide-react";
import { fileUrl, get, post } from "../api";
import { StreamRunner } from "../parts";
import { Card, DataTable, Empty, Metric, Notice, PageHead, Pill, Section, Spinner, TabView, bytes, fmt } from "../ui";

export default function Traffic() {
  const st = useQuery({ queryKey: ["capture"], queryFn: () => get("/api/ops/capture"), refetchInterval: 3000 });
  const [name, setName] = useState("exp_live");
  const [sel, setSel] = useState<string>("");
  const [out, setOut] = useState("");
  const [busy, setBusy] = useState("");
  const caps: any[] = st.data?.captures || [];
  useEffect(() => { if (!sel && caps.length) setSel(caps[0].name); }, [caps, sel]);
  const res = useQuery({ queryKey: ["cap-results", sel], enabled: !!sel, retry: false, queryFn: () => get(`/api/ops/capture/${sel}/results`) });

  const act = async (label: string, path: string, body?: unknown) => {
    setBusy(label);
    try {
      setOut((await post(path, body)).output);
    } catch (e: any) {
      setOut(e.message);
    } finally {
      setBusy("");
      st.refetch();
      res.refetch();
    }
  };
  const modes = st.data?.modes || {};
  const cur = st.data?.current;

  return (
    <>
      <PageHead eyebrow="Traffic analysis · packet capture" title="Traffic lab"
        sub="Capture the traffic between the five devices and the middleware, then analyse it in a separate process: rebuild every HTTP message, measure entropy, overhead and latency, flag replays and floods, and join each flag to its audit row (PCAP → SQLite, PCAP → XML)."
        strip="tcp.port == 8000" />

      <div className="grid g2">
        <Card title="Capture" sub="Packets between the devices and the middleware on port 8000">
          <div className="stack">
            <div className="row">
              <Pill tone={modes.dumpcap ? "pass" : "neutral"}>dumpcap {modes.dumpcap ? "ready" : "not installed"}</Pill>
              <Pill tone={modes.tap ? "pass" : "warn"}>tap relay {modes.tap ? "running on :8000 → :8001" : "not running"}</Pill>
            </div>
            {cur ? (
              <div className="row">
                <Pill tone="info">Capturing {cur.name} · {cur.mode} · {cur.elapsed_s} s · {bytes(cur.bytes || 0)}</Pill>
                <button className="btn primary" onClick={() => act("stop", "/api/ops/capture/stop")}>Stop capture</button>
              </div>
            ) : (
              <div className="row">
                <input className="input mono" style={{ maxWidth: 220 }} value={name} onChange={(e) => setName(e.target.value)} aria-label="Capture name" />
                <button className="btn primary" disabled={!(modes.dumpcap || modes.tap)} onClick={() => act("start", "/api/ops/capture/start", { name })}>Start capture</button>
              </div>
            )}
            {!(modes.dumpcap || modes.tap) && <Notice tone="warn">No capture method: install Wireshark with Npcap (loopback support), or start the demo with <span className="mono">python scripts\run_demo.py --tap</span>.</Notice>}
          </div>
        </Card>
        <Card title="Scripted experiments" sub="Each starts its own capture, drives the devices, stops and analyses">
          <div className="stack" style={{ gap: 8 }}>
            {(st.data?.experiments || []).map((e: any) => (
              <details key={e.key}>
                <summary style={{ cursor: "pointer", fontWeight: 600, padding: "4px 0" }}>{e.key} · {e.title}</summary>
                <div style={{ padding: "8px 0 4px" }}><StreamRunner path={`/api/ops/experiments/${e.key}/run`} label={`Run ${e.key}`} onDone={() => st.refetch()} /></div>
              </details>
            ))}
          </div>
        </Card>
      </div>

      <Section title="Saved captures" actions={caps.length ? (
        <select className="select" style={{ width: "auto" }} value={sel} onChange={(e) => setSel(e.target.value)} aria-label="Capture">
          {caps.map((c) => <option key={c.name} value={c.name}>{c.name} · {bytes(c.bytes)}{c.analysed ? " · analysed" : ""}</option>)}
        </select>) : undefined}>
        {!caps.length ? <Card><Empty icon={<Radio size={28} />} title="No captures yet">Start one above, or run an experiment.</Empty></Card> : (
          <div className="stack">
            <div className="row">
              <button className="btn primary" onClick={() => act("analyse", `/api/ops/capture/${sel}/analyse`)} disabled={!!busy}>Run analyser</button>
              <button className="btn" onClick={() => act("sqlite", `/api/ops/capture/${sel}/sqlite`)} disabled={!!busy}>PCAP → SQLite</button>
              <button className="btn" onClick={() => act("xml", `/api/ops/capture/${sel}/xml`)} disabled={!!busy}>Export XML</button>
              <button className="btn" onClick={() => act("wireshark", `/api/ops/capture/${sel}/wireshark`)} disabled={!!busy || !st.data?.wireshark}>Open in Wireshark</button>
              {busy && <Spinner label={busy === "analyse" ? "Analysing in a separate process" : "Working"} />}
            </div>
            {out && <pre className="console">{out}</pre>}
            {res.data ? <Results r={res.data} /> : res.isFetched && <Notice>Run the analyser to see results for this capture.</Notice>}
          </div>
        )}
      </Section>
    </>
  );
}

function Results({ r }: { r: any }) {
  const s = r.summary;
  const e = s.entropy_mean || {};
  return (
    <div className="stack fade-in">
      <div className="grid g4">
        <Metric label="Packets" value={s.packets?.toLocaleString()} foot={`engine ${s.engine}`} />
        <Metric label="HTTP requests" value={s.http_requests} foot={Object.entries(s.status_counts || {}).map(([k, v]) => `${k}×${v}`).join(" · ")} />
        <Metric label="Entropy, plain ≥ 1 KB" value={fmt(e.plain_ge_1KB, 3)} unit="bits/B" foot="readable JSON" />
        <Metric label="Entropy, protected ≥ 1 KB" value={fmt(e.protected_ge_1KB, 3)} unit="bits/B" foot="AES-GCM ciphertext" />
      </div>
      <div className="row muted small">Devices: {(s.devices || []).join(", ")} · flags {JSON.stringify(s.flags)} · {s.flags_matched_in_audit} matched in the audit log, {s.flags_without_audit} without</div>
      <div className="grid g2">
        {r.figures.map((f: string) => (
          <Card key={f} className="tight"><img src={fileUrl(f)} alt={f.split("/").pop()} style={{ width: "100%", borderRadius: 10, display: "block" }} /></Card>
        ))}
      </div>
      <TabView tabs={["messages", "flows", "flags", "audit_join"].map((t) => ({
        value: t, label: t === "audit_join" ? "SQL join" : `${t}.csv`,
        content: (
          <Card className="flush">
            <DataTable rows={r.tables[t]} max={420} />
            {t === "audit_join" && <pre className="json" style={{ margin: 12 }}>{`ATTACH 'data/securemarks.db' AS app;
SELECT m.ts, m.device, m.request_id, m.status, a.action, a.outcome, a.code
FROM http_messages m
LEFT JOIN app.audit_log a ON a.request_id = m.request_id
WHERE m.flag IN ('replay', 'flood')
ORDER BY m.ts;`}</pre>}
          </Card>
        ),
      }))} />
    </div>
  );
}
