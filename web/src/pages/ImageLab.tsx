import { useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { ImagePlus } from "lucide-react";
import { download, get, postForm } from "../api";
import { BarBox, Histogram, LineBox, SCHEME_KEY, ScatterBox, short, useColors } from "../charts";
import { Card, DataTable, DownloadButton, Metric, Notice, PageHead, Pill, Segmented, Spinner, TabView, fmt } from "../ui";

type Source = { sample: string | null; file: File | null };

function form(src: Source, extra: Record<string, string>) {
  const fd = new FormData();
  Object.entries(extra).forEach(([k, v]) => fd.append(k, v));
  if (src.file) fd.append("file", src.file);
  else fd.append("sample", src.sample || "photo");
  return fd;
}

export default function ImageLab() {
  const samples = useQuery({ queryKey: ["samples"], queryFn: () => get<any[]>("/api/lab/image/samples") });
  const [src, setSrc] = useState<Source>({ sample: "photo", file: null });
  const [scheme, setScheme] = useState("AES-256-GCM-SIV");
  const [side, setSide] = useState("256");
  const [r, setR] = useState<any>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const input = useRef<HTMLInputElement>(null);

  const analyze = async () => {
    setBusy(true);
    setErr("");
    try {
      setR(await postForm("/api/lab/image/analyze", form(src, { scheme, side })));
    } catch (e: any) {
      setErr(e.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <PageHead eyebrow="Crypto analysis · image confidentiality" title="Image encryption"
        sub="The RGB pixel buffer is encrypted as bytes and the ciphertext is shown as an image of the same size. Then the standard image-cipher metrics: NPCR, UACI, information entropy, correlation coefficient, PSNR and MSE, plus encryption and decryption speed."
        strip="R:212 G:186 B:160 R:208 G:181 B:157" />

      <Card>
        <div className="grid g3" style={{ alignItems: "end" }}>
          <div className="field"><span>Image</span>
            <div className="sample-pick">
              {(samples.data || []).map((s) => (
                <button key={s.name} type="button" className="sample" aria-pressed={!src.file && src.sample === s.name} onClick={() => setSrc({ sample: s.name, file: null })} title={s.label}>
                  <img src={s.thumb} alt="" />{s.name}
                </button>
              ))}
              <button type="button" className="sample" aria-pressed={!!src.file} onClick={() => input.current?.click()} title="Upload your own image">
                <span style={{ width: 64, height: 64, borderRadius: 10, display: "grid", placeItems: "center", background: "var(--fill)" }}><ImagePlus size={22} /></span>
                {src.file ? src.file.name.slice(0, 10) : "upload"}
              </button>
              <input ref={input} type="file" accept="image/*" hidden onChange={(e) => e.target.files?.[0] && setSrc({ sample: null, file: e.target.files[0] })} />
            </div>
          </div>
          <div className="stack" style={{ gap: 10 }}>
            <label className="field"><span>Scheme</span>
              <select className="select" value={scheme} onChange={(e) => setScheme(e.target.value)}>
                {["AES-256-GCM-SIV", "AES-256-GCM", "AES-256-CTR", "AES-256-CBC", "AES-256-ECB", "Logistic-map"].map((s) => <option key={s}>{s}</option>)}
              </select>
            </label>
            <div className="field"><span>Analysis size (longest side, px)</span>
              <Segmented label="Size" value={side} onChange={setSide} options={["128", "256", "512"].map((v) => ({ value: v, label: v }))} />
            </div>
          </div>
          <div className="row end">
            {busy && <Spinner label="Encrypting and measuring" />}
            <button className="btn primary" onClick={analyze} disabled={busy}>Encrypt and analyse</button>
          </div>
        </div>
        {err && <div style={{ marginTop: 12 }}><Notice tone="fail">{err}</Notice></div>}
      </Card>

      <div style={{ marginTop: 18 }}>
        <TabView tabs={[
          { value: "pix", label: "Pixels", content: r ? <PixelsTab r={r} src={src} scheme={scheme} side={side} /> : <Hint /> },
          { value: "sec", label: "Security metrics", content: r ? <SecurityTab r={r} /> : <Hint /> },
          { value: "cmp", label: "Compare schemes", content: <CompareTab src={src} /> },
          { value: "perf", label: "Performance", content: <PerfTab src={src} /> },
        ]} />
      </div>
    </>
  );
}

const Hint = () => <Notice>Pick an image and press <b>Encrypt and analyse</b>.</Notice>;

function Tile({ src, label, note }: { src: string | null; label: string; note?: string }) {
  return (
    <figure className="img-tile" style={{ margin: 0 }}>
      {src ? <img src={src} alt={label} /> : <div className="hex" style={{ aspectRatio: "1", display: "grid", placeItems: "center" }}>refused</div>}
      <figcaption className="cap">{label}{note && <span>{note}</span>}</figcaption>
    </figure>
  );
}

function PixelGrid({ grid, title }: { grid: number[][][]; title: string }) {
  return (
    <div>
      <div className="small" style={{ fontWeight: 600, marginBottom: 6 }}>{title}</div>
      <div className="pixgrid" role="table" aria-label={`${title}: 8 by 8 pixel values`}>
        {grid.flat().map(([r, g, b], i) => {
          const light = 0.299 * r + 0.587 * g + 0.114 * b > 140;
          return (
            <div key={i} className="pix" role="cell" style={{ background: `rgb(${r},${g},${b})`, color: light ? "#000" : "#fff" }} title={`R ${r} G ${g} B ${b}`}>
              <span>{r}</span><span>{g}</span><span>{b}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function PixelsTab({ r, src, scheme, side }: { r: any; src: Source; scheme: string; side: string }) {
  const im = r.images;
  return (
    <div className="stack" style={{ gap: 16 }}>
      <Card title="Plain image and its RGB channels" sub={`${r.width} × ${r.height} px · ${r.bytes.toLocaleString()} bytes of R, G, B values`}>
        <div className="grid g4">
          <Tile src={im.plain} label="Plain (RGB)" />
          <Tile src={im.plain_channels.R} label="R channel" />
          <Tile src={im.plain_channels.G} label="G channel" />
          <Tile src={im.plain_channels.B} label="B channel" />
        </div>
      </Card>
      <Card title={`Encrypted with ${r.scheme}`} sub="Ciphertext bytes laid back onto the same pixel grid"
        actions={<DownloadButton onClick={() => download("/api/lab/image/envelope", `encrypted_image_${scheme}.json`, { method: "POST", body: form(src, { scheme, side }) })}>Encrypted image JSON</DownloadButton>}>
        <div className="grid g4">
          <Tile src={im.cipher} label="Cipher image" note={`key ${r.key_fingerprint.slice(0, 8)}…`} />
          <Tile src={im.cipher_channels.R} label="Cipher R" />
          <Tile src={im.cipher_channels.G} label="Cipher G" />
          <Tile src={im.cipher_channels.B} label="Cipher B" />
        </div>
      </Card>
      <div className="grid g3">
        <Card title="Decrypted" sub={r.lossless ? "identical to the original, pixel for pixel" : "differs from the original"}>
          <Tile src={im.decrypted} label="Decrypted" note={r.lossless ? "MSE 0 · PSNR ∞" : ""} />
        </Card>
        <Card title="Wrong key (1 bit flipped)" sub={r.key_sensitivity.result}>
          <Tile src={im.wrong_key} label="Decrypted with wrong key" note={r.key_sensitivity.pixels_differ_pct != null ? `${fmt(r.key_sensitivity.pixels_differ_pct, 2)} % differ` : ""} />
        </Card>
        <Card title="One plain pixel changed" sub={`pixel (${r.changed_pixel.x}, ${r.changed_pixel.y}) ${r.changed_pixel.channel} + 1 → white = cipher pixel changed`}>
          <Tile src={im.diff} label="Changed cipher pixels" note={`NPCR ${fmt(r.npcr, 2)} %`} />
        </Card>
      </div>
      <Card title="Pixels as numbers" sub={`8 × 8 block at (${r.grid.x}, ${r.grid.y}): each cell shows R, G, B (0–255). Hover for exact values.`}>
        <div className="grid g3">
          <PixelGrid grid={r.grid.plain} title="Plain" />
          <PixelGrid grid={r.grid.cipher} title="Cipher" />
          <PixelGrid grid={r.grid.decrypted} title="Decrypted" />
        </div>
      </Card>
    </div>
  );
}

function SecurityTab({ r }: { r: any }) {
  const c = useColors();
  const v = r.verdict;
  const ok = (b: boolean) => (b ? <Pill tone="pass">pass</Pill> : <Pill tone="fail">fail</Pill>);
  const dirs = ["horizontal", "vertical", "diagonal"] as const;
  return (
    <div className="stack" style={{ gap: 16 }}>
      <div className="grid g4">
        <Metric label="NPCR" value={fmt(r.npcr, 4)} unit="%" pct={r.npcr} ideal={r.npcr_ideal}
          foot={<>ideal {r.npcr_ideal} · pass ≥ {fmt(r.npcr_critical, 4)} {ok(v.npcr)}</>} />
        <Metric label="UACI" value={fmt(r.uaci, 4)} unit="%" pct={(r.uaci / 50) * 100} ideal={(r.uaci_ideal / 50) * 100}
          foot={<>ideal {r.uaci_ideal} · pass {fmt(r.uaci_interval[0], 3)}–{fmt(r.uaci_interval[1], 3)} {ok(v.uaci)}</>} />
        <Metric label="Information entropy (cipher)" value={fmt(r.entropy_cipher.all, 4)} unit="bits" pct={(r.entropy_cipher.all / 8) * 100} ideal={100}
          foot={<>ideal 8 · plain {fmt(r.entropy_plain.all, 4)} {ok(v.entropy)}</>} />
        <Metric label="Correlation (cipher, H)" value={fmt(r.corr_cipher.horizontal.mean, 4)}
          foot={<>ideal 0 · plain {fmt(r.corr_plain.horizontal.mean, 4)} {ok(v.correlation)}</>} />
        <Metric label="MSE (plain vs cipher)" value={fmt(r.mse_plain_cipher, 1)} foot="higher = more different; random ≈ 10,900" />
        <Metric label="PSNR (plain vs cipher)" value={fmt(r.psnr_plain_cipher, 3)} unit="dB" foot={<>below 10 dB = no visual similarity {ok(v.psnr)}</>} />
        <Metric label="MSE / PSNR (plain vs decrypted)" value={`${fmt(r.mse_plain_decrypted, 1)} / ${r.psnr_plain_decrypted === "inf" ? "∞" : fmt(r.psnr_plain_decrypted, 2)}`}
          foot={<>lossless decryption {ok(v.lossless)}</>} />
        <Metric label="Encrypt / decrypt" value={`${fmt(r.timing.encrypt_ms, 2)} / ${fmt(r.timing.decrypt_ms, 2)}`} unit="ms"
          foot={`${fmt(r.timing.encrypt_MBps, 0)} / ${fmt(r.timing.decrypt_MBps, 0)} MB/s`} />
      </div>

      <div className="grid g2">
        <Card title="Histogram · plain image" sub="Pixel values cluster: the image's structure shows through">
          <Histogram hist={r.hist_plain} />
        </Card>
        <Card title="Histogram · cipher image" sub="Flat: every value 0–255 is equally likely, so the histogram reveals nothing">
          <Histogram hist={r.hist_cipher} />
        </Card>
      </div>

      <Card title="Adjacent-pixel correlation" sub="R channel, 1,200 random pixel/neighbour pairs; r is computed over every pair in the image">
        <div className="grid g3">
          {dirs.map((d) => <ScatterBox key={`p${d}`} points={r.scatter_plain[d]} color={c.c1} title={`${d}, plain · r = ${fmt(r.corr_plain[d].R, 4)}`} />)}
          {dirs.map((d) => <ScatterBox key={`c${d}`} points={r.scatter_cipher[d]} color={c.c2} title={`${d}, cipher · r = ${fmt(r.corr_cipher[d].R, 4)}`} />)}
        </div>
      </Card>

      <div className="grid g2">
        <Card title="Per-channel results" className="flush">
          <DataTable rows={["R", "G", "B"].map((ch) => ({
            channel: ch, npcr: r.npcr_per_channel[ch], uaci: r.uaci_per_channel[ch],
            ent_p: r.entropy_plain[ch], ent_c: r.entropy_cipher[ch],
            h: r.corr_cipher.horizontal[ch], v: r.corr_cipher.vertical[ch], d: r.corr_cipher.diagonal[ch],
          }))} columns={[
            { key: "channel", label: "Ch" }, { key: "npcr", label: "NPCR %", num: true }, { key: "uaci", label: "UACI %", num: true },
            { key: "ent_p", label: "H plain", num: true }, { key: "ent_c", label: "H cipher", num: true },
            { key: "h", label: "r H", num: true }, { key: "v", label: "r V", num: true }, { key: "d", label: "r D", num: true },
          ]} />
        </Card>
        <Card title="Correlation by direction" sub="Plain image vs cipher image (mean of R, G, B)">
          <BarBox data={dirs.map((d) => ({ d, plain: r.corr_plain[d].mean, cipher: r.corr_cipher[d].mean }))} x="d" domain={[-0.1, 1]}
            series={[{ key: "plain", name: "plain", color: c.c1 }, { key: "cipher", name: "cipher", color: c.c2 }]} height={230} />
        </Card>
      </div>

      <Card title="How these are computed">
        <div className="grid g2 small">
          <div><b>NPCR</b> = (1/N) Σ D(i,j) × 100, where D = 1 if C₁(i,j) ≠ C₂(i,j). C₁ and C₂ encrypt two plain images that differ in one pixel, same key and nonce. Ideal 99.6094 %.</div>
          <div><b>UACI</b> = (1/N) Σ |C₁(i,j) − C₂(i,j)| / 255 × 100. Ideal 33.4635 %. Pass bands are from Wu et al. (2011) at α = 0.05 for this image size.</div>
          <div><b>Entropy</b> H = −Σ p(v) log₂ p(v) over the 256 values. A finite image cannot reach exactly 8: for N samples the expected maximum is ≈ 8 − 255/(2N ln 2).</div>
          <div><b>Correlation</b> r = cov(x, y) / (σx σy) over every neighbouring pair. Natural images: 0.9+. A good cipher image: ≈ 0.</div>
          <div><b>MSE</b> = (1/N) Σ (P − C)². <b>PSNR</b> = 10 log₁₀(255² / MSE) dB. Plain vs cipher should be ~7–9 dB; plain vs decrypted must be ∞ (identical).</div>
          <div><b>Why GCM/CTR fail NPCR:</b> they XOR a keystream, so changing one plain pixel changes exactly one cipher pixel. GCM-SIV derives its IV from the whole image, so one pixel re-randomises every pixel.</div>
        </div>
      </Card>
    </div>
  );
}

function CompareTab({ src }: { src: Source }) {
  const [r, setR] = useState<any>(null);
  const [busy, setBusy] = useState(false);
  const c = useColors();
  const run = async () => {
    setBusy(true);
    try {
      setR(await postForm("/api/lab/image/compare", form(src, { side: "192" })));
    } finally {
      setBusy(false);
    }
  };
  const data = r?.rows.map((x: any) => ({ ...x, name: short(x.scheme) }));
  return (
    <div className="stack" style={{ gap: 16 }}>
      <div className="row">
        <button className="btn primary" onClick={run} disabled={busy}>Encrypt with all six schemes</button>
        {busy && <Spinner />}
        <span className="muted small">Tip: the “logo” sample shows ECB's pattern leak most clearly.</span>
      </div>
      {r && (
        <>
          <Card title="Cipher images side by side">
            <div className="grid g6" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(140px, 1fr))" }}>
              <Tile src={r.plain} label="Plain" />
              {r.rows.map((x: any) => <Tile key={x.scheme} src={x.image} label={short(x.scheme)} note={`${x.passes}/${x.checks}`} />)}
            </div>
          </Card>
          <div className="grid g2">
            <Card title="NPCR by scheme" sub="ideal 99.61 %">
              <BarBox data={data} x="name" series={[{ key: "npcr", name: "NPCR" }]} unit=" %" colorBy={(x) => c[SCHEME_KEY[x.scheme]]} refY={[{ y: 99.61, label: "ideal" }]} height={250} />
            </Card>
            <Card title="UACI by scheme" sub="ideal 33.46 %">
              <BarBox data={data} x="name" series={[{ key: "uaci", name: "UACI" }]} unit=" %" colorBy={(x) => c[SCHEME_KEY[x.scheme]]} refY={[{ y: 33.46, label: "ideal" }]} height={250} />
            </Card>
          </div>
          <Card className="flush"><DataTable rows={r.rows} columns={[
            { key: "scheme", label: "Scheme", render: (x) => <b>{x.scheme}</b> },
            { key: "npcr", label: "NPCR %", num: true }, { key: "uaci", label: "UACI %", num: true }, { key: "entropy", label: "Entropy", num: true },
            { key: "corr_h", label: "r H", num: true }, { key: "corr_v", label: "r V", num: true }, { key: "corr_d", label: "r D", num: true },
            { key: "mse", label: "MSE", num: true }, { key: "psnr", label: "PSNR dB", num: true },
            { key: "encrypt_ms", label: "Enc ms", num: true }, { key: "decrypt_ms", label: "Dec ms", num: true },
            { key: "passes", label: "Checks", render: (x) => <Pill tone={x.passes === x.checks ? "pass" : "fail"}>{x.passes}/{x.checks}</Pill> },
          ]} /></Card>
        </>
      )}
    </div>
  );
}

function PerfTab({ src }: { src: Source }) {
  const [rows, setRows] = useState<any[] | null>(null);
  const [busy, setBusy] = useState(false);
  const [metric, setMetric] = useState("encrypt_ms");
  const c = useColors();
  const run = async () => {
    setBusy(true);
    try {
      setRows(await postForm("/api/lab/image/perf", form(src, {})));
    } finally {
      setBusy(false);
    }
  };
  const sides = rows ? Array.from(new Set(rows.map((r) => r.side))) : [];
  const schemes = rows ? Array.from(new Set(rows.map((r) => r.scheme))) : [];
  const data = sides.map((s) => {
    const row: any = { side: `${s}×${s}` };
    rows!.filter((r) => r.side === s).forEach((r) => (row[r.scheme] = r[metric]));
    return row;
  });
  return (
    <div className="stack" style={{ gap: 16 }}>
      <div className="row">
        <button className="btn primary" onClick={run} disabled={busy}>Time 64² → 512² images</button>
        {busy && <Spinner />}
        <span className="spacer" />
        {rows && (
          <Segmented label="Metric" value={metric} onChange={setMetric} options={[
            { value: "encrypt_ms", label: "Encrypt ms" }, { value: "decrypt_ms", label: "Decrypt ms" },
            { value: "encrypt_MBps", label: "Encrypt MB/s" }, { value: "decrypt_MBps", label: "Decrypt MB/s" }]} />
        )}
      </div>
      {rows && (
        <>
          <Card title="Image encryption performance" sub="RGB, 3 bytes per pixel; logistic map capped at 256²">
            <LineBox data={data} x="side" logY={metric.endsWith("_ms")} height={340}
              series={schemes.map((s) => ({ key: s, name: short(s), color: c[SCHEME_KEY[s]] }))} />
          </Card>
          <Card className="flush"><DataTable rows={rows} columns={[
            { key: "scheme", label: "Scheme" }, { key: "side", label: "Side px", num: true }, { key: "bytes", label: "Bytes", num: true },
            { key: "encrypt_ms", label: "Encrypt ms", num: true }, { key: "decrypt_ms", label: "Decrypt ms", num: true },
            { key: "encrypt_MBps", label: "Encrypt MB/s", num: true }, { key: "decrypt_MBps", label: "Decrypt MB/s", num: true },
          ]} /></Card>
        </>
      )}
    </div>
  );
}
