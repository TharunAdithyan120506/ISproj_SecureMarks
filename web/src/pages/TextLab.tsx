import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { get, post, saveJson } from "../api";
import { BarBox, Heatmap, LineBox, SCHEME_KEY, short, useColors } from "../charts";
import { Card, DataTable, DownloadButton, Hex, JsonView, Metric, Notice, OkPill, PageHead, Pill, Spinner, TabView, bytes, fmt } from "../ui";

const DEFAULT = '{"course":"IT301","roll_no":"240911608","midsem":27,"endsem":45,"total":72,"teacher":"t104","published_at":"2026-10-31T09:30:00Z"}';

function SchemePicker({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  const q = useQuery({ queryKey: ["schemes"], queryFn: () => get<any[]>("/api/lab/schemes") });
  return (
    <label className="field"><span>Scheme</span>
      <select className="select" value={value} onChange={(e) => onChange(e.target.value)}>
        {(q.data || [{ name: value, kind: "" }]).map((s) => <option key={s.name} value={s.name}>{s.name}{s.kind ? ` · ${s.kind}` : ""}</option>)}
      </select>
    </label>
  );
}

export default function TextLab() {
  return (
    <>
      <PageHead eyebrow="Crypto analysis · confidentiality and integrity" title="Text encryption"
        sub="Encrypt any text, see the plaintext, key, nonce, ciphertext and tag, export the ciphertext as JSON, then measure confusion, diffusion and the avalanche effect, and time it against plaintext length."
        strip={DEFAULT} />
      <TabView tabs={[
        { value: "enc", label: "Encrypt & decrypt", content: <EncryptTab /> },
        { value: "sec", label: "Security analysis", content: <SecurityTab /> },
        { value: "cmp", label: "Mode comparison", content: <CompareTab /> },
        { value: "perf", label: "Performance", content: <PerfTab /> },
      ]} />
    </>
  );
}

/* --- 1. encrypt / decrypt ------------------------------------------------------------------------- */

function EncryptTab() {
  const [text, setText] = useState(DEFAULT);
  const [scheme, setScheme] = useState("AES-256-GCM-SIV");
  const [aad, setAad] = useState("marks|IT301|240911608");
  const [key, setKey] = useState("");
  const [tamper, setTamper] = useState(false);
  const [r, setR] = useState<any>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  const run = async (newKey = false) => {
    setBusy(true);
    setErr("");
    try {
      const out = await post("/api/lab/text/encrypt", { plaintext: text, scheme, aad, tamper, key_hex: newKey ? null : key || null });
      setR(out);
      setKey(out.key_hex);
    } catch (e: any) {
      setErr(e.message);
    } finally {
      setBusy(false);
    }
  };
  const env = r?.envelope;

  return (
    <div className="split">
      <Card title="Input">
        <div className="stack">
          <label className="field"><span>Plaintext ({bytes(new TextEncoder().encode(text).length)})</span>
            <textarea className="textarea mono" rows={6} value={text} onChange={(e) => setText(e.target.value)} />
          </label>
          <SchemePicker value={scheme} onChange={setScheme} />
          <label className="field"><span>Associated data (authenticated, not encrypted; AEAD schemes only)</span>
            <input className="input mono" value={aad} onChange={(e) => setAad(e.target.value)} />
          </label>
          <label className="field"><span>Key (256-bit hex; leave empty for a random key)</span>
            <input className="input mono" value={key} onChange={(e) => setKey(e.target.value)} placeholder="random" />
          </label>
          <label className="check"><input type="checkbox" checked={tamper} onChange={(e) => setTamper(e.target.checked)} />
            Flip one ciphertext bit before decrypting (integrity test)</label>
          <div className="row">
            <button className="btn primary" onClick={() => run(false)} disabled={busy}>Encrypt and decrypt</button>
            <button className="btn" onClick={() => run(true)} disabled={busy}>New random key</button>
            {busy && <Spinner />}
          </div>
          {err && <Notice tone="fail">{err}</Notice>}
          <Notice>Same plaintext + new nonce = a completely different ciphertext every time (except ECB and the fixed-key logistic map, which are deterministic per nonce).</Notice>
        </div>
      </Card>

      <div className="stack">
        {!r ? <Card><div className="muted">Press <b>Encrypt and decrypt</b> to see every value.</div></Card> : (
          <>
            <Card title={r.scheme} sub={env.kind} actions={<DownloadButton onClick={() => saveJson(env, `ciphertext_${r.scheme}.json`)}>Ciphertext JSON</DownloadButton>}>
              <Hex label="Plaintext" hex={r.plaintext_hex} note="UTF-8" />
              <Hex label="Key" hex={r.key_hex} note={`fingerprint ${env.key_fingerprint}`} short />
              <Hex label={r.scheme === "AES-256-ECB" ? "Nonce / IV (none)" : "Nonce / IV"} hex={env.nonce_hex} short />
              <Hex label="Ciphertext" hex={env.ciphertext_hex} note={`Base64 ${env.ciphertext_b64.length} chars`} />
              {env.tag_hex && <Hex label="Authentication tag" hex={env.tag_hex} short />}
              <div className="row" style={{ marginTop: 14 }}>
                <OkPill ok={r.decrypt_ok && (r.matches ?? true)} yes="Decrypted back to the original" no={r.decrypt_ok ? "Decrypted to the WRONG text" : "Decryption refused"} />
                {r.tampered && <Pill tone="warn">1 bit flipped in transit</Pill>}
              </div>
              {r.error && <div style={{ marginTop: 10 }}><Notice tone={r.decrypt_ok ? "warn" : "pass"}>{r.error}</Notice></div>}
              {r.decrypted != null && <div className="hex short" style={{ marginTop: 10 }}>{r.decrypted}</div>}
            </Card>
            <div className="grid g4">
              <Metric label="Encrypt" value={fmt(r.encrypt_ms * 1000, 1)} unit="µs" foot="median of 50 runs" />
              <Metric label="Decrypt" value={fmt(r.decrypt_ms * 1000, 1)} unit="µs" foot="median of 50 runs" />
              <Metric label="Ciphertext entropy" value={fmt(r.ciphertext_entropy, 3)} unit="bits/B" foot={`max ${fmt(r.max_entropy_for_length, 2)} for ${env.ciphertext_bytes + env.tag_hex.length / 2} B`} />
              <Metric label="Overhead" value={env.overhead_bytes} unit="B" foot="nonce + tag + padding" />
            </div>
            <Card title="Ciphertext envelope (JSON)" sub="Exactly what a receiver needs, except the key."><JsonView data={env} /></Card>
          </>
        )}
      </div>
    </div>
  );
}

/* --- 2. security analysis ---------------------------------------------------------------------------- */

function SecurityTab() {
  const [text, setText] = useState(DEFAULT);
  const [scheme, setScheme] = useState("AES-256-GCM-SIV");
  const [trials, setTrials] = useState(64);
  const [r, setR] = useState<any>(null);
  const [busy, setBusy] = useState(false);
  const c = useColors();

  const run = async () => {
    setBusy(true);
    try {
      setR(await post("/api/lab/text/security", { plaintext: text, scheme, trials }));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="stack" style={{ gap: 16 }}>
      <Card>
        <div className="grid g3" style={{ alignItems: "end" }}>
          <label className="field"><span>Plaintext</span><input className="input mono" value={text} onChange={(e) => setText(e.target.value)} /></label>
          <SchemePicker value={scheme} onChange={setScheme} />
          <div className="row">
            <label className="field" style={{ width: 110 }}><span>Trials</span>
              <input className="input" type="number" min={8} max={256} value={trials} onChange={(e) => setTrials(+e.target.value)} /></label>
            <button className="btn primary" style={{ alignSelf: "flex-end" }} onClick={run} disabled={busy}>Run analysis</button>
            {busy && <Spinner />}
          </div>
        </div>
        <p className="muted small" style={{ marginTop: 10 }}>
          Each trial flips one random bit (same key, same nonce, so only that bit differs) and compares the two ciphertexts.
          Ideal: 50 % of ciphertext bits change and ≈100 % of bytes (characters) change (255/256 = 99.61 %).
        </p>
      </Card>

      {r && (
        <div className="stack fade-in" style={{ gap: 16 }}>
          <div className="grid g4">
            <Metric label="Avalanche · bit level" value={fmt(r.avalanche.bit_pct, 2)} unit="%" pct={r.avalanche.bit_pct} ideal={50}
              foot={<>ideal 50 % · σ {fmt(r.avalanche.bit_sd, 2)} {Math.abs(r.avalanche.bit_pct - 50) < 3 ? <Pill tone="pass">ideal</Pill> : <Pill tone="fail">weak</Pill>}</>} />
            <Metric label="Avalanche · character level" value={fmt(r.avalanche.char_pct, 2)} unit="%" pct={r.avalanche.char_pct} ideal={99.61}
              foot={<>ideal ≈100 % {r.avalanche.char_pct > 98 ? <Pill tone="pass">ideal</Pill> : <Pill tone="fail">weak</Pill>}</>} />
            <Metric label="Confusion · key sensitivity" value={fmt(r.key_sensitivity.bit_pct, 2)} unit="%" pct={r.key_sensitivity.bit_pct} ideal={50}
              foot={<>1 key bit flipped · ideal 50 % {Math.abs(r.key_sensitivity.bit_pct - 50) < 3 ? <Pill tone="pass">ideal</Pill> : <Pill tone="fail">weak</Pill>}</>} />
            <Metric label="Ciphertext entropy (4 KB)" value={fmt(r.stats.ciphertext_entropy, 4)} unit="bits/B" pct={(r.stats.ciphertext_entropy / 8) * 100}
              foot={<>plaintext {fmt(r.stats.plaintext_entropy, 3)} · χ² {fmt(r.stats.chi_square, 1)} (≤ 293 uniform)</>} />
          </div>

          <div className="grid g2">
            <Card title="Avalanche per trial" sub="Share of ciphertext bits changed by each single-bit flip">
              <BarBox data={r.avalanche.samples.map((v: number, i: number) => ({ trial: i + 1, pct: v }))} x="trial"
                series={[{ key: "pct", name: "bits changed", color: c[SCHEME_KEY[r.scheme]] }]} unit=" %" height={240} domain={[0, 100]}
                refY={[{ y: 50, label: "ideal 50 %" }]} />
            </Card>
            <Card title="Diffusion map" sub={`One row per flipped input bit (16-byte block) · one column per output byte · mean ${fmt(r.diffusion.mean * 100, 1)} % bits flip`}>
              <Heatmap matrix={r.diffusion.matrix} height={240} />
            </Card>
          </div>

          <div className="grid g2">
            <Card title="Byte histogram" sub="4 KB of the same text: plaintext is skewed, ciphertext is flat">
              <BarBox data={r.stats.plaintext_histogram.map((p: number, i: number) => ({ b: i, plain: p, cipher: r.stats.ciphertext_histogram[i] }))}
                x="b" series={[{ key: "plain", name: "plaintext", color: c.c4 }, { key: "cipher", name: "ciphertext", color: c.c1 }]} height={240} />
            </Card>
            <Card title="What the numbers mean">
              <div className="stack small">
                <div><b>Confusion</b> (Shannon): the key–ciphertext relationship is complex. Measured by flipping one key bit: every scheme here, even ECB, changes ~50 % of the output, because AES itself is a strong permutation.</div>
                <div><b>Diffusion</b>: one plaintext bit influences many ciphertext bits. This is where the <i>modes</i> differ: CTR and GCM XOR a keystream, so one flipped plaintext bit flips exactly one ciphertext bit (plus GCM's tag). GCM-SIV derives its IV from the whole message, so every bit changes.</div>
                <div><b>Entropy</b> below 8 is expected: a sample of n bytes cannot reach 8 bits/byte until n ≫ 256 (finite-sample bias ≈ 255 / (2n ln 2)).</div>
                <div><b>ECB pattern test</b>: {r.ecb.plaintext_blocks} identical plaintext blocks → {r.ecb.distinct_ciphertext_blocks} distinct ciphertext blocks {r.ecb.leaks_pattern ? <Pill tone="fail">leaks the pattern</Pill> : <Pill tone="pass">no leak</Pill>}</div>
              </div>
            </Card>
          </div>
        </div>
      )}
    </div>
  );
}

/* --- 3. compare schemes ------------------------------------------------------------------------------ */

function CompareTab() {
  const [rows, setRows] = useState<any[] | null>(null);
  const [busy, setBusy] = useState(false);
  const c = useColors();
  const run = async () => {
    setBusy(true);
    try {
      setRows(await post("/api/lab/text/compare", { plaintext: DEFAULT, trials: 48 }));
    } finally {
      setBusy(false);
    }
  };
  const data = rows?.map((r) => ({ ...r, name: short(r.scheme) }));
  return (
    <div className="stack" style={{ gap: 16 }}>
      <div className="row">
        <button className="btn primary" onClick={run} disabled={busy}>Compare all six schemes</button>
        {busy && <Spinner label="Running avalanche, key sensitivity, statistics and timing" />}
      </div>
      {!rows && <Notice>Answers “AES-GCM vs ECB vs CTR vs CBC” with measurements on the same plaintext and the same conditions.</Notice>}
      {data && (
        <>
          <div className="grid g2">
            <Card title="Plaintext avalanche (diffusion)" sub="% of ciphertext bits changed by one flipped plaintext bit">
              <BarBox data={data} x="name" series={[{ key: "avalanche_bit_pct", name: "bits changed" }]} unit=" %" domain={[0, 60]}
                colorBy={(r) => c[SCHEME_KEY[r.scheme]]} refY={[{ y: 50, label: "ideal 50 %" }]} />
            </Card>
            <Card title="Key sensitivity (confusion)" sub="% of ciphertext bits changed by one flipped key bit">
              <BarBox data={data} x="name" series={[{ key: "key_sens_bit_pct", name: "bits changed" }]} unit=" %" domain={[0, 60]}
                colorBy={(r) => c[SCHEME_KEY[r.scheme]]} refY={[{ y: 50, label: "ideal 50 %" }]} />
            </Card>
          </div>
          <Card className="flush">
            <DataTable rows={rows!} columns={[
              { key: "scheme", label: "Scheme", render: (r) => <b>{r.scheme}</b> },
              { key: "authenticated", label: "Integrity", render: (r) => r.authenticated ? <Pill tone="pass">tag</Pill> : <Pill tone="fail">none</Pill> },
              { key: "avalanche_bit_pct", label: "Avalanche bits %", num: true },
              { key: "avalanche_char_pct", label: "Avalanche chars %", num: true },
              { key: "key_sens_bit_pct", label: "Key sens. bits %", num: true },
              { key: "ciphertext_entropy_4k", label: "Entropy 4 KB", num: true },
              { key: "chi_square_4k", label: "χ² 4 KB", num: true },
              { key: "encrypt_us", label: "Encrypt µs", num: true },
              { key: "decrypt_us", label: "Decrypt µs", num: true },
              { key: "overhead_bytes", label: "Overhead B", num: true },
              { key: "leaks_pattern", label: "Block pattern", render: (r) => r.leaks_pattern ? <Pill tone="fail">leaks</Pill> : <Pill tone="pass">hidden</Pill> },
            ]} />
          </Card>
        </>
      )}
    </div>
  );
}

/* --- 4. performance ---------------------------------------------------------------------------------- */

function PerfTab() {
  const [rows, setRows] = useState<any[] | null>(null);
  const [busy, setBusy] = useState(false);
  const [metric, setMetric] = useState("encrypt_ms");
  const c = useColors();
  const run = async () => {
    setBusy(true);
    try {
      setRows(await post("/api/lab/text/perf", { max_size: 1048576 }));
    } finally {
      setBusy(false);
    }
  };
  const sizes = rows ? Array.from(new Set(rows.map((r) => r.size_bytes))) : [];
  const schemes = rows ? Array.from(new Set(rows.map((r) => r.scheme))) : [];
  const data = sizes.map((s) => {
    const row: any = { size: s };
    rows!.filter((r) => r.size_bytes === s).forEach((r) => (row[r.scheme] = r[metric]));
    return row;
  });
  const label = (s: number) => (s >= 1048576 ? `${s / 1048576} MB` : s >= 1024 ? `${s / 1024} KB` : `${s} B`);
  return (
    <div className="stack" style={{ gap: 16 }}>
      <div className="row">
        <button className="btn primary" onClick={run} disabled={busy}>Measure 16 B → 1 MB</button>
        {busy && <Spinner label="Timing every scheme at nine plaintext lengths" />}
        <span className="spacer" />
        {rows && (
          <select className="select" style={{ width: "auto" }} value={metric} onChange={(e) => setMetric(e.target.value)} aria-label="Metric">
            <option value="encrypt_ms">Encryption time (ms)</option>
            <option value="decrypt_ms">Decryption time (ms)</option>
            <option value="encrypt_MBps">Encryption speed (MB/s)</option>
            <option value="decrypt_MBps">Decryption speed (MB/s)</option>
            <option value="overhead_bytes">Overhead (bytes)</option>
          </select>
        )}
      </div>
      {!rows && <Notice>Graphical analysis of encryption against plaintext length: median of repeated runs with <span className="mono">time.perf_counter()</span>. The logistic map is pure Python, so it is capped at 256 KB.</Notice>}
      {rows && (
        <>
          <Card title={{ encrypt_ms: "Encryption time", decrypt_ms: "Decryption time", encrypt_MBps: "Encryption speed", decrypt_MBps: "Decryption speed", overhead_bytes: "Ciphertext overhead" }[metric]}
            sub="x: plaintext length (log scale)">
            <LineBox data={data} x="size" logX logY={metric.endsWith("_ms")} xFmt={label} height={360}
              series={schemes.map((s) => ({ key: s, name: short(s), color: c[SCHEME_KEY[s]] }))} />
          </Card>
          <Card className="flush"><DataTable rows={rows} max={420} columns={[
            { key: "scheme", label: "Scheme" }, { key: "size", label: "Plaintext" },
            { key: "encrypt_ms", label: "Encrypt ms", num: true }, { key: "decrypt_ms", label: "Decrypt ms", num: true },
            { key: "encrypt_MBps", label: "Encrypt MB/s", num: true }, { key: "decrypt_MBps", label: "Decrypt MB/s", num: true },
            { key: "overhead_bytes", label: "Overhead B", num: true }, { key: "runs", label: "Runs", num: true },
          ]} /></Card>
        </>
      )}
      <Notice>Related lab exercise · Lab 2, additional exercise 1: encrypt messages with AES under different modes of operation,
        plot the execution time of each technique and compare the modes. This tab does that for AES-256 across six schemes and nine message lengths.</Notice>
    </div>
  );
}
