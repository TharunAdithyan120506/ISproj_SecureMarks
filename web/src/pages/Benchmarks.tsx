import { useQuery } from "@tanstack/react-query";
import { fileUrl, get } from "../api";
import { StreamRunner } from "../parts";
import { Card, DataTable, Metric, Notice, PageHead, Section, fmt } from "../ui";

const MB = 1048576;

export default function Benchmarks() {
  const q = useQuery({ queryKey: ["bench"], queryFn: () => get("/api/ops/bench") });
  const rows: any[] = q.data?.rows || [];
  const val = (group: string, name: string, metric: string, size?: number) => {
    const r = rows.find((x) => x.group === group && x.name === name && x.metric === metric && (size === undefined || String(x.size_bytes) === String(size)));
    return r ? Number(r.value) : undefined;
  };
  const probe: any[] = (q.data?.flood_probe || []).filter((p: any) => p.status === "200");
  const med = (xs: number[]) => (xs.length ? xs.sort((a, b) => a - b)[Math.floor(xs.length / 2)] : undefined);
  const base = med(probe.filter((p) => p.phase === "baseline").map((p) => +p.latency_ms));
  const during = med(probe.filter((p) => p.phase === "flood").map((p) => +p.latency_ms));
  const matrix = [
    ["Confidentiality", "X25519 + AES-GCM in transit, AES-256-GCM at rest", "plain vs protected capture (exp1)", `AES-256-GCM ${fmt(val("symmetric", "AES-256-GCM", "encrypt_MBps", MB), 0)} MB/s @ 1 MB`],
    ["Integrity", "GCM tag, SHA-256 record hash, AAD binding, signed answer-sheet hash", "tamper_cipher → 400; tamper_db → signature invalid; --sheet → sheet invalid", `SHA-256 ${fmt(val("hash", "SHA-256", "hash_MBps", MB), 0)} MB/s @ 1 MB`],
    ["Authentication", "Argon2id, 15-min JWT, Ed25519 signatures", "bad_login, forge_sig → 400, revoked_key → 403", `Ed25519 sign ${fmt(val("signature", "Ed25519", "sign_ms"), 3)} ms vs RSA-2048 ${fmt(val("signature", "RSA-PSS-2048", "sign_ms"), 3)} ms; Argon2id ${fmt(val("passwords", "Argon2id", "hash_ms"), 1)} ms`],
    ["Accountability", "hash-chained audit log + trace events", "every attack has an audit row (SQL join)", `audit write ${fmt(val("checks", "audit write (hash-chained, WAL)", "us"), 0)} µs`],
    ["Availability", "token bucket, size cap, 10 s timeout, 20-slot cap", "flood → 429s while the student keeps loading", base ? `s608 p50 ${fmt(base, 1)} ms → ${fmt(during, 1)} ms during flood` : "run the flood attack with --probe"],
    ["Authorisation", "role + ownership checks", "idor → 403 forbidden", `RBAC ${fmt(val("checks", "RBAC role + ownership", "us"), 2)} µs`],
    ["Replay resistance", "request ID + timestamp in AAD, seen-ID set", "replay → 409 replay_detected / stale_request", `seen-set lookup ${fmt(val("checks", "replay seen-set lookup", "us"), 2)} µs`],
  ].map(([goal, mechanism, test, cost]) => ({ goal, mechanism, test, cost }));

  return (
    <>
      <PageHead eyebrow="Results · efficiency analysis" title="Benchmarks"
        sub="Every algorithm across payload sizes, the middleware's cost per check, and end-to-end latency of a protected call against the plain baseline." strip="time.perf_counter()" />
      <Card title="Run the quick benchmark" sub="About 30–60 s. End-to-end numbers need the middleware running.">
        <StreamRunner path="/api/ops/bench/run" label="Run benchmark" primary onDone={() => q.refetch()} />
      </Card>
      {!rows.length ? <div className="section"><Notice>No results yet: run the quick benchmark.</Notice></div> : (
        <>
          <Section title="Goal matrix" sub={`Each security goal, its mechanism, the attack that tests it, and its measured cost · ${q.data.meta.cpu || ""} · ${q.data.meta.mode} run`}>
            <Card className="flush"><DataTable rows={matrix} columns={[{ key: "goal", label: "Goal" }, { key: "mechanism", label: "Mechanism" }, { key: "test", label: "Security test" }, { key: "cost", label: "Measured cost" }]} /></Card>
            <div className="grid g4" style={{ marginTop: 16 }}>
              <Metric label="X25519 handshake" value={fmt(val("key_exchange", "X25519", "handshake_ms"), 3)} unit="ms" />
              <Metric label="RSA-OAEP-2048 handshake" value={fmt(val("key_exchange", "RSA-OAEP-2048", "handshake_ms"), 3)} unit="ms" />
              <Metric label="Protected publish p50" value={fmt(val("end_to_end", "protected publish", "p50_ms"), 2)} unit="ms" />
              <Metric label="Plain publish p50" value={fmt(val("end_to_end", "plain publish", "p50_ms"), 2)} unit="ms" />
            </div>
          </Section>
          <Section title="Graphs">
            <div className="grid g2">
              {q.data.figures.map((f: string) => <Card key={f} className="tight"><img src={fileUrl(f)} alt={f} style={{ width: "100%", borderRadius: 10, display: "block" }} /></Card>)}
            </div>
          </Section>
          <Section title="All results"><Card className="flush"><DataTable rows={rows} max={480} /></Card></Section>
        </>
      )}
    </>
  );
}
