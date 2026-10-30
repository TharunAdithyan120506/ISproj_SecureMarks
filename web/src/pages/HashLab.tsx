import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { get, post } from "../api";
import { BarBox, LineBox, SCHEME_KEY, useColors } from "../charts";
import { Card, CopyButton, DataTable, Metric, Notice, PageHead, Pill, Spinner, TabView, cx, fmt } from "../ui";

export default function HashLab() {
  return (
    <>
      <PageHead eyebrow="Crypto analysis · integrity" title="Hashing"
        sub="The complete digest under seven hash functions with generation time, the avalanche effect, and the three security properties (pre-image, second pre-image and collision resistance) demonstrated by actually attacking truncated digests."
        strip="IT301 · 240911608 · endsem 45" />
      <TabView tabs={[
        { value: "dig", label: "Digests & avalanche", content: <DigestTab /> },
        { value: "res", label: "Resistance analysis", content: <ResistanceTab /> },
        { value: "perf", label: "Performance", content: <PerfTab /> },
        { value: "lab5", label: "Lab 5 experiments", content: <Lab5Tab /> },
      ]} />
    </>
  );
}

function DigestTab() {
  const [msg, setMsg] = useState("IT301 · 240911608 · midsem 27 · endsem 45");
  const [other, setOther] = useState("IT301 · 240911608 · midsem 27 · endsem 95");
  const [alg, setAlg] = useState("SHA-256");
  const [r, setR] = useState<any>(null);
  const [busy, setBusy] = useState(false);
  const c = useColors();
  const run = async () => {
    setBusy(true);
    try {
      setR(await post("/api/lab/hash/digest", { message: msg, other, algorithm: alg }));
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="stack" style={{ gap: 16 }}>
      <Card>
        <div className="grid g2">
          <label className="field"><span>Message A</span><input className="input mono" value={msg} onChange={(e) => setMsg(e.target.value)} /></label>
          <label className="field"><span>Message B (one character changed)</span><input className="input mono" value={other} onChange={(e) => setOther(e.target.value)} /></label>
        </div>
        <div className="row" style={{ marginTop: 12 }}>
          <label className="field" style={{ width: 200 }}><span>Compare A and B with</span>
            <select className="select" value={alg} onChange={(e) => setAlg(e.target.value)}>
              {["MD5", "SHA-1", "SHA-256", "SHA-512", "SHA3-256", "BLAKE2b", "djb2"].map((a) => <option key={a}>{a}</option>)}
            </select>
          </label>
          <button className="btn primary" style={{ alignSelf: "flex-end" }} onClick={run} disabled={busy}>Hash</button>
          {busy && <Spinner />}
        </div>
      </Card>
      {r && (
        <>
          <Card title="Complete digests of message A" sub={`${r.bytes} bytes in · generation time is the median of 300 runs`} className="flush">
            <div className="table-wrap">
              <table className="t">
                <thead><tr><th>Algorithm</th><th>Bits</th><th>Digest (hex, complete)</th><th className="num">Time</th><th>Status</th></tr></thead>
                <tbody>
                  {r.digests.map((d: any) => (
                    <tr key={d.algorithm}>
                      <td><b>{d.algorithm}</b></td>
                      <td>{d.bits}</td>
                      <td className="code" style={{ wordBreak: "break-all", minWidth: 280 }}>{d.hex} <CopyButton text={d.hex} /></td>
                      <td className="num">{fmt(d.time_us, 2)} µs</td>
                      <td><Pill tone={d.status.startsWith("secure") ? "pass" : d.status.startsWith("broken") ? "fail" : "warn"}>{d.status.split(":")[0].split(" (")[0]}</Pill></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>
          {r.compare && (
            <Card title={`Avalanche: ${r.compare.algorithm}(A) vs ${r.compare.algorithm}(B)`}
              sub={`${r.compare.differing_bits} of ${r.compare.total_bits} output bits differ (${fmt(r.compare.pct, 1)} %) · ideal 50 %`}
              actions={Math.abs(r.compare.pct - 50) < 10 ? <Pill tone="pass">avalanche</Pill> : <Pill tone="fail">weak mixing</Pill>}>
              <div className="stack" style={{ gap: 6 }}>
                <div className="hex short">{r.compare.a_hex}</div>
                <div className="hex short">{r.compare.b_hex}</div>
                <div className="bitgrid" style={{ marginTop: 8 }} role="img" aria-label={`${r.compare.differing_bits} differing bits shown in red`}>
                  {r.compare.grid.map((b: boolean, i: number) => <span key={i} className={cx("bit", b && "on")} title={`bit ${i}`} />)}
                </div>
                <div className="muted small">One cell per output bit, red = differs.</div>
              </div>
            </Card>
          )}
          <Card title="Avalanche of every algorithm" sub="Mean share of output bits changed by flipping one input bit (48 trials)">
            <BarBox data={r.avalanche} x="algorithm" series={[{ key: "bit_pct", name: "bits changed" }]} unit=" %" domain={[0, 60]}
              colorBy={(x) => c[SCHEME_KEY[x.algorithm]]} refY={[{ y: 50, label: "ideal 50 %" }]} height={260} />
          </Card>
        </>
      )}
    </div>
  );
}

function ResistanceTab() {
  const [alg, setAlg] = useState("SHA-256");
  const [pre, setPre] = useState(16);
  const [col, setCol] = useState(28);
  const [trials, setTrials] = useState(5);
  const [r, setR] = useState<any>(null);
  const [busy, setBusy] = useState(false);
  const c = useColors();
  const extras = useQuery({ queryKey: ["hash-extras"], queryFn: () => get("/api/lab/hash/extras") });
  const run = async () => {
    setBusy(true);
    try {
      setR(await post("/api/lab/hash/resistance", { algorithm: alg, max_preimage_bits: pre, max_collision_bits: col, trials }));
    } finally {
      setBusy(false);
    }
  };
  const chart = (key: string) => r[key].rows.map((x: any) => ({ bits: x.bits, measured: x.log2_mean, theory: x.log2_theory }));
  return (
    <div className="stack" style={{ gap: 16 }}>
      <div className="grid g3">
        <Card title="Pre-image resistance" sub="Given a digest h, find any m with H(m) = h. Brute force needs ~2ⁿ tries."><span /></Card>
        <Card title="Second pre-image resistance" sub="Given m₁, find m₂ ≠ m₁ with the same digest. Also ~2ⁿ tries."><span /></Card>
        <Card title="Collision resistance" sub="Find any m₁ ≠ m₂ with the same digest. The birthday bound makes it ~2ⁿᐟ² tries."><span /></Card>
      </div>
      <Card>
        <div className="row">
          <label className="field" style={{ width: 160 }}><span>Algorithm</span>
            <select className="select" value={alg} onChange={(e) => setAlg(e.target.value)}>{["SHA-256", "SHA-512", "SHA3-256", "BLAKE2b", "SHA-1", "MD5"].map((a) => <option key={a}>{a}</option>)}</select>
          </label>
          <label className="field" style={{ width: 170 }}><span>Pre-image: up to k bits</span>
            <select className="select" value={pre} onChange={(e) => setPre(+e.target.value)}>{[12, 14, 16, 18, 20].map((a) => <option key={a}>{a}</option>)}</select>
          </label>
          <label className="field" style={{ width: 170 }}><span>Collision: up to k bits</span>
            <select className="select" value={col} onChange={(e) => setCol(+e.target.value)}>{[16, 20, 24, 28, 32, 36].map((a) => <option key={a}>{a}</option>)}</select>
          </label>
          <label className="field" style={{ width: 110 }}><span>Trials</span>
            <input className="input" type="number" min={1} max={20} value={trials} onChange={(e) => setTrials(+e.target.value)} />
          </label>
          <button className="btn primary" style={{ alignSelf: "flex-end" }} onClick={run} disabled={busy}>Attack truncated digests</button>
          {busy && <Spinner label="Brute-forcing" />}
        </div>
        <p className="muted small" style={{ marginTop: 10 }}>A 256-bit digest cannot be attacked, so the experiment attacks only its first k bits, measures the tries, and checks them against theory. The same scaling then gives the effort for the full digest.</p>
      </Card>
      {r && (
        <>
          <div className="grid g3">
            {[["preimage", "Pre-image", c.c1], ["second_preimage", "Second pre-image", c.c2], ["collision", "Collision (birthday)", c.c3]].map(([k, t, col]) => (
              <Card key={k} title={t} sub="log₂(tries) against the number of bits attacked">
                <LineBox data={chart(k)} x="bits" height={230} xFmt={(v) => `${v}`}
                  series={[{ key: "measured", name: "measured", color: col }, { key: "theory", name: "theory", color: c["label-2"] }]} />
              </Card>
            ))}
          </div>
          <div className="grid g4">
            <Metric label="Hash rate here" value={fmt(r.hashes_per_second / 1e6, 2)} unit="M/s" foot={`${r.algorithm}, single core`} />
            {r.extrapolation.map((e: any) => <Metric key={e.attack} label={`Full ${r.digest_bits}-bit ${e.attack}`} value={e.tries} foot={`≈ ${e.years} at this rate`} />)}
          </div>
          <Card className="flush"><DataTable rows={[...r.preimage.rows.map((x: any) => ({ attack: "pre-image", ...x })),
            ...r.second_preimage.rows.map((x: any) => ({ attack: "second pre-image", ...x })), ...r.collision.rows.map((x: any) => ({ attack: "collision", ...x }))]}
            columns={[{ key: "attack", label: "Attack" }, { key: "bits", label: "k bits", num: true }, { key: "mean_tries", label: "Mean tries", num: true },
              { key: "theory", label: "Theory", num: true }, { key: "min", label: "Min", num: true }, { key: "max", label: "Max", num: true },
              { key: "log2_mean", label: "log₂ measured", num: true }, { key: "log2_theory", label: "log₂ theory", num: true }]} /></Card>
        </>
      )}
      {extras.data && (
        <Card title="Full-length effort by algorithm" sub="Generic brute-force bound at this machine's rate. MD5 and SHA-1 are broken by smarter attacks far below these bounds." className="flush">
          <DataTable rows={Object.entries(extras.data.extrapolation).flatMap(([a, rows]: any) => rows.map((x: any) => ({ algorithm: a, ...x, status: extras.data.status[a] })))}
            columns={[{ key: "algorithm", label: "Algorithm" }, { key: "attack", label: "Attack" }, { key: "tries", label: "Tries" }, { key: "years", label: "Time at this rate" }, { key: "status", label: "Real-world status" }]} />
        </Card>
      )}
    </div>
  );
}

function PerfTab() {
  const [rows, setRows] = useState<any[] | null>(null);
  const [busy, setBusy] = useState(false);
  const c = useColors();
  const run = async () => {
    setBusy(true);
    try {
      setRows(await post("/api/lab/hash/perf"));
    } finally {
      setBusy(false);
    }
  };
  const sizes = rows ? Array.from(new Set(rows.map((r) => r.size))) : [];
  const algs = rows ? Array.from(new Set(rows.map((r) => r.algorithm))) : [];
  const pivot = (m: string) => sizes.map((s) => Object.fromEntries([["size", s], ...rows!.filter((r) => r.size === s).map((r) => [r.algorithm, r[m]])]));
  return (
    <div className="stack" style={{ gap: 16 }}>
      <div className="row"><button className="btn primary" onClick={run} disabled={busy}>Measure 64 B → 1 MB</button>{busy && <Spinner />}</div>
      {rows && (
        <div className="grid g2">
          <Card title="Generation time" sub="ms, log scale">
            <LineBox data={pivot("time_ms")} x="size" logY height={300} series={algs.map((a) => ({ key: a, name: a, color: c[SCHEME_KEY[a]] }))} />
          </Card>
          <Card title="Throughput" sub="MB/s">
            <LineBox data={pivot("MBps")} x="size" height={300} series={algs.map((a) => ({ key: a, name: a, color: c[SCHEME_KEY[a]] }))} />
          </Card>
        </div>
      )}
    </div>
  );
}

function Lab5Tab() {
  const q = useQuery({ queryKey: ["hash-extras"], queryFn: () => get("/api/lab/hash/extras") });
  if (!q.data) return <Spinner label="Running" />;
  const { lab5, djb2 } = q.data;
  return (
    <div className="stack" style={{ gap: 16 }}>
      <Notice>Lab 5, exercise 1 (djb2: start at 5381, ×33 + character, 32-bit mask) and exercise 3 (time MD5, SHA-1 and SHA-256 on 50–100 random strings and look for collisions).</Notice>
      <Card title={`Exercise 3 · ${lab5.strings} random strings`} className="flush">
        <DataTable rows={lab5.rows} columns={[{ key: "algorithm", label: "Algorithm" }, { key: "total_ms", label: "Total ms", num: true },
          { key: "per_hash_us", label: "Per hash µs", num: true }, { key: "collisions", label: "Collisions", num: true }]} />
      </Card>
      <Card title="Exercise 1 · why djb2 is not a cryptographic hash" sub="Birthday search on the full 32-bit output"
        actions={djb2.found ? <Pill tone="fail">collision found</Pill> : <Pill tone="pass">none found</Pill>}>
        {djb2.found && (
          <div className="grid g4">
            <Metric label="String A" value={<span className="mono" style={{ fontSize: 18 }}>{djb2.a}</span>} />
            <Metric label="String B" value={<span className="mono" style={{ fontSize: 18 }}>{djb2.b}</span>} />
            <Metric label="Same djb2" value={<span className="mono" style={{ fontSize: 18 }}>{djb2.hash}</span>} />
            <Metric label="Tries / time" value={djb2.tries.toLocaleString()} foot={`${djb2.ms} ms · theory ≈ ${djb2.theory.toLocaleString()}`} />
          </div>
        )}
      </Card>
    </div>
  );
}
