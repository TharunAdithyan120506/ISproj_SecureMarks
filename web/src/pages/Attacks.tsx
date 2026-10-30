import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { get, post } from "../api";
import { StreamRunner } from "../parts";
import { Card, DataTable, Metric, Notice, PageHead, Pill, Section } from "../ui";

export default function Attacks() {
  const cat = useQuery({ queryKey: ["attacks"], queryFn: () => get<any[]>("/api/ops/attacks") });
  const [device, setDevice] = useState("");
  const ev = useQuery({ queryKey: ["evidence", device], queryFn: () => get(`/api/ops/evidence?limit=100${device ? `&device=${device}` : ""}`), refetchInterval: 5000 });
  const [pick, setPick] = useState<string | null>(null);
  const trace = useQuery({ queryKey: ["trace", pick], enabled: !!pick, queryFn: () => get<any[]>(`/api/ops/trace/${pick}`) });
  const [restoreOut, setRestoreOut] = useState("");

  return (
    <>
      <PageHead eyebrow="Security analysis · against the live server" title="Attack lab"
        sub="Each attack runs from the attacker device (127.0.0.66) as its own process. The script prints the expected and actual result, the audit row with the same request ID, and the server's trace; the evidence table below fills in as you go."
        strip="X-Request-ID: replayed" />
      <Section title="Catalogue" sub="Run any attack here, or copy its command to a terminal (venv active).">
        <div className="stack">
          {(cat.data || []).map((a) => (
            <Card key={a.key} title={a.title} sub={<>Goal: {a.goal} · expected <span className="mono">{a.expected}</span> · <span className="mono">{a.command}</span></>}>
              <StreamRunner path={`/api/ops/attacks/${a.key}/run`} label="Run attack" onDone={() => ev.refetch()} />
            </Card>
          ))}
        </div>
        <div className="row" style={{ marginTop: 14 }}>
          <button className="btn" onClick={async () => setRestoreOut((await post("/api/ops/attacks/restore")).output)}>Undo database tampering</button>
          <span className="muted small">Other undo helpers: <span className="mono">python scripts\setup_demo.py --rekey t104</span> after a revocation; <span className="mono">--reset</span> (server stopped) for a clean slate.</span>
        </div>
        {restoreOut && <pre className="console" style={{ marginTop: 10 }}>{restoreOut}</pre>}
      </Section>

      <Section title="Evidence: refused requests in the audit log" actions={
        <select className="select" style={{ width: "auto" }} value={device} onChange={(e) => setDevice(e.target.value)} aria-label="Device">
          {["", "attacker", "teacher-laptop", "student-laptop", "ctrl-pc", "admin-pc"].map((d) => <option key={d} value={d}>{d || "all devices"}</option>)}
        </select>}>
        {ev.error && <Notice tone="warn">{String((ev.error as Error).message)}</Notice>}
        {ev.data && (
          <div className="stack">
            <div className="grid g6">
              {Object.entries(ev.data.counts as Record<string, number>).slice(0, 6).map(([code, n]) => <Metric key={code} label={<span className="mono">{code}</span>} value={n} />)}
            </div>
            <Card className="flush">
              <DataTable rows={ev.data.rows} max={420} rowClass={(r) => (r.request_id === pick ? "hl" : undefined)} columns={[
                { key: "id", label: "#" }, { key: "ts", label: "Time", render: (r) => new Date(r.ts * 1000).toLocaleTimeString() },
                { key: "device", label: "Device" }, { key: "src_ip", label: "Source", code: true }, { key: "actor", label: "Actor" },
                { key: "action", label: "Action", code: true },
                { key: "code", label: "Code", render: (r) => <Pill tone={r.outcome === "denied" ? "fail" : "warn"}>{r.code}</Pill> },
                { key: "detail", label: "Detail" },
                { key: "request_id", label: "Trace", render: (r) => <button className="btn plain sm" onClick={() => setPick(r.request_id)}>Show trace</button> },
              ]} />
            </Card>
            {pick && (
              <Card title="Server trace for one request" sub={<span className="mono">{pick}</span>} className="flush">
                <DataTable rows={(trace.data || []).map((s) => ({ ...s, result: s.ok === 1 ? "PASS" : s.ok === 0 ? "FAIL" : "SKIP" }))} columns={[
                  { key: "step", label: "Step", code: true },
                  { key: "result", label: "Result", render: (s) => <Pill tone={s.result === "PASS" ? "pass" : s.result === "FAIL" ? "fail" : "neutral"}>{s.result}</Pill> },
                  { key: "detail", label: "Detail" }]} />
              </Card>
            )}
          </div>
        )}
      </Section>
    </>
  );
}
