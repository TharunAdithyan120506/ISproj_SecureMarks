import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { get, post } from "../api";
import { BarBox, LineBox, SCHEME_KEY, useColors } from "../charts";
import { Card, DataTable, Hex, Metric, Notice, OkPill, PageHead, Spinner, TabView, fmt } from "../ui";

const ALGS = ["Ed25519", "ECDSA-P256", "RSA-PSS-2048", "RSA-PSS-3072"];

export default function SignLab() {
  return (
    <>
      <PageHead eyebrow="Crypto analysis · authentication and non-repudiation" title="Digital signatures"
        sub="Sign the SHA-256 of a message, verify it, tamper with it. Generation and verification time are shown for every run and stored in data/cryptolab.db, and teacher-signed marks store theirs with the record."
        strip="sign(SHA-256(record), private key)" />
      <TabView tabs={[
        { value: "sign", label: "Sign & verify", content: <SignTab /> },
        { value: "bench", label: "Timing analysis", content: <BenchTab /> },
        { value: "hist", label: "Stored history", content: <HistoryTab /> },
      ]} />
    </>
  );
}

function SignTab() {
  const [alg, setAlg] = useState("Ed25519");
  const [msg, setMsg] = useState("IT301 · 240911608 · midsem 27 · endsem 45 · total 72");
  const [tampered, setTampered] = useState("IT301 · 240911608 · midsem 27 · endsem 95 · total 122");
  const [r, setR] = useState<any>(null);
  const [busy, setBusy] = useState(false);
  const qc = useQueryClient();
  const run = async () => {
    setBusy(true);
    try {
      setR(await post("/api/lab/sign/once", { algorithm: alg, message: msg, tampered }));
      qc.invalidateQueries({ queryKey: ["sig-history"] });
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="split">
      <Card title="Message">
        <div className="stack">
          <label className="field"><span>Algorithm</span>
            <select className="select" value={alg} onChange={(e) => setAlg(e.target.value)}>{ALGS.map((a) => <option key={a}>{a}</option>)}</select>
          </label>
          <label className="field"><span>Signed message</span><textarea className="textarea mono" rows={3} value={msg} onChange={(e) => setMsg(e.target.value)} /></label>
          <label className="field"><span>Message the verifier receives (edit it to tamper)</span><textarea className="textarea mono" rows={3} value={tampered} onChange={(e) => setTampered(e.target.value)} /></label>
          <div className="row"><button className="btn primary" onClick={run} disabled={busy}>Generate key, sign, verify</button>{busy && <Spinner />}</div>
        </div>
      </Card>
      <div className="stack">
        {!r ? <Card><div className="muted">Run it to see the keys, the signature and the three timings.</div></Card> : (
          <>
            <div className="grid g3">
              <Metric label="Key generation" value={fmt(r.keygen_ms, 3)} unit="ms" />
              <Metric label="Signature generation" value={fmt(r.sign_ms, 4)} unit="ms" foot="stored" />
              <Metric label="Signature verification" value={fmt(r.verify_ms, 4)} unit="ms" foot="stored" />
            </div>
            <Card title={r.algorithm} sub={`${r.family} · ${r.security_bits}-bit security`}>
              <div className="row" style={{ marginBottom: 6 }}>
                <OkPill ok={r.valid} yes="Original message: signature valid" no="Original: invalid" />
                <OkPill ok={r.tampered_valid === false} yes="Tampered message: rejected" no="Tampered message accepted!" />
              </div>
              <Hex label="SHA-256 of the message (what is signed)" hex={r.sha256} short />
              <Hex label="Signature" hex={r.signature_hex} />
              <Hex label="Public key" hex={r.public_key_hex} />
            </Card>
          </>
        )}
      </div>
    </div>
  );
}

function BenchTab() {
  const [rows, setRows] = useState<any[] | null>(null);
  const [one, setOne] = useState<any>(null);
  const [busy, setBusy] = useState(false);
  const c = useColors();
  const qc = useQueryClient();
  const run = async () => {
    setBusy(true);
    try {
      setRows(await post("/api/lab/sign/compare"));
      setOne(await post("/api/lab/sign/benchmark", { algorithm: "Ed25519", runs: 300 }));
      qc.invalidateQueries({ queryKey: ["sig-history"] });
    } finally {
      setBusy(false);
    }
  };
  const data = rows?.map((r) => ({ algorithm: r.algorithm, sign: r.sign_ms.median, verify: r.verify_ms.median, keygen: r.keygen_ms.median,
    sig: r.signature_bytes, pub: r.public_key_bytes }));
  return (
    <div className="stack" style={{ gap: 16 }}>
      <div className="row"><button className="btn primary" onClick={run} disabled={busy}>Benchmark all four algorithms</button>{busy && <Spinner label="100 signs and verifies each" />}</div>
      {!rows && <Notice>Related lab exercise · Lab 6 (digital signatures with RSA, then other schemes) and Lab 3's RSA vs ECC performance comparison.</Notice>}
      {data && (
        <>
          <div className="grid g2">
            <Card title="Generation vs verification time" sub="median ms, log scale">
              <BarBox data={data} x="algorithm" logY series={[{ key: "sign", name: "sign", color: c.c1 }, { key: "verify", name: "verify", color: c.c2 }]} unit=" ms" />
            </Card>
            <Card title="Key generation time" sub="median ms, log scale">
              <BarBox data={data} x="algorithm" logY series={[{ key: "keygen", name: "keygen" }]} colorBy={(r) => c[SCHEME_KEY[r.algorithm]]} unit=" ms" />
            </Card>
            <Card title="Sizes" sub="bytes on the wire">
              <BarBox data={data} x="algorithm" series={[{ key: "sig", name: "signature", color: c.c1 }, { key: "pub", name: "public key", color: c.c3 }]} unit=" B" />
            </Card>
            {one && (
              <Card title="Ed25519: every run" sub="300 individual sign and verify timings (ms)">
                <LineBox data={one.sign_samples.map((s: number, i: number) => ({ i, sign: s, verify: one.verify_samples[i] }))} x="i"
                  series={[{ key: "sign", name: "sign", color: c.c1 }, { key: "verify", name: "verify", color: c.c2 }]} height={280} />
              </Card>
            )}
          </div>
          <Card className="flush"><DataTable rows={rows!.map((r) => ({ ...r, sign_med: r.sign_ms.median, sign_p95: r.sign_ms.p95, verify_med: r.verify_ms.median,
            verify_p95: r.verify_ms.p95, keygen_med: r.keygen_ms.median }))} columns={[
            { key: "algorithm", label: "Algorithm" }, { key: "security_bits", label: "Security bits", num: true },
            { key: "sign_med", label: "Sign ms", num: true }, { key: "sign_p95", label: "Sign p95", num: true },
            { key: "verify_med", label: "Verify ms", num: true }, { key: "verify_p95", label: "Verify p95", num: true },
            { key: "keygen_med", label: "Keygen ms", num: true }, { key: "signs_per_second", label: "Signs/s", num: true },
            { key: "signature_bytes", label: "Sig B", num: true }, { key: "public_key_bytes", label: "Pub B", num: true },
          ]} /></Card>
          <Notice>RSA verifies faster than it signs because the public exponent is tiny (65537); Ed25519 signs fastest and has the smallest keys and signatures, which is why SecureMarks uses it.</Notice>
        </>
      )}
    </div>
  );
}

function HistoryTab() {
  const q = useQuery({ queryKey: ["sig-history"], queryFn: () => get<any[]>("/api/lab/history?kind=signature&limit=200") });
  const rows = (q.data || []).map((r) => ({ id: r.id, time: new Date(r.ts * 1000).toLocaleString(), algorithm: r.scheme, source: r.params.source,
    sign_ms: r.metrics.sign_ms, verify_ms: r.metrics.verify_ms, keygen_ms: r.metrics.keygen_ms, sig_bytes: r.metrics.signature_bytes }));
  return (
    <Card title="Stored signature timings" sub="Every run from this lab, the report CLI and benchmarks, persisted in data/cryptolab.db"
      actions={<a className="btn sm" href="/api/lab/history.csv?kind=signature">Export CSV</a>} className="flush">
      <DataTable rows={rows} columns={[{ key: "id", label: "#" }, { key: "time", label: "Time" }, { key: "algorithm", label: "Algorithm" },
        { key: "source", label: "Source" }, { key: "sign_ms", label: "Sign ms", num: true }, { key: "verify_ms", label: "Verify ms", num: true },
        { key: "keygen_ms", label: "Keygen ms", num: true }, { key: "sig_bytes", label: "Sig B", num: true }]} />
    </Card>
  );
}
