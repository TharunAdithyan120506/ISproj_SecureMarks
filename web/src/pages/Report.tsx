import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { BarChart3 } from "lucide-react";
import { fileUrl, get } from "../api";
import { StreamRunner } from "../parts";
import { Card, DataTable, Empty, Metric, PageHead, Pill, Section, fmt } from "../ui";

const REQUIREMENTS = [
  ["Confidentiality, integrity, authentication", "AES-256-GCM-SIV / GCM envelopes, SHA-256 + Ed25519 signed records, Argon2id + JWT", "Text, Image, Signatures labs · marks portal"],
  ["Text encrypt / decrypt, plaintext and ciphertext shown", "Text lab › Encrypt & decrypt (hex, Base64, JSON envelope download)", "/lab/text"],
  ["Confusion, diffusion, avalanche (50 % bit, ~100 % char)", "Text lab › Security analysis and Mode comparison", "/lab/text"],
  ["Encryption / decryption time and speed, with graphs", "Text lab › Performance (16 B → 1 MB, six schemes)", "/lab/text"],
  ["Hash: complete digest, pre-image, second pre-image, collision, time", "Hashing lab › Digests, Resistance analysis, Performance", "/lab/hash"],
  ["Signature: generation and verification time, displayed and stored", "Signatures lab + marks table (sign_ms, verify_ms) + data/cryptolab.db", "/lab/signatures"],
  ["Image: RGB and encrypted pixels", "Image lab › Pixels (channels, cipher image, 8×8 value grids)", "/lab/image"],
  ["Image: NPCR, UACI, entropy, correlation, PSNR, MSE", "Image lab › Security metrics and Compare schemes", "/lab/image"],
  ["Image: encryption / decryption time", "Image lab › Performance (64² → 512²)", "/lab/image"],
  ["Packet capture", "Traffic lab (dumpcap or tap), experiments 1–6, PCAP → SQLite / XML", "/traffic"],
].map(([req, where, page]) => ({ req, where, page }));

export default function Report() {
  const q = useQuery({ queryKey: ["report"], queryFn: () => get("/api/ops/report"), retry: false });
  const r = q.data;
  const p = r?.image_primary;
  const siv = r?.text_compare?.find((x: any) => x.scheme === "AES-256-GCM-SIV");
  const ed = r?.signatures?.find((x: any) => x.algorithm === "Ed25519");
  return (
    <>
      <PageHead eyebrow="Results · security and performance analysis" title="Analysis report"
        sub="Every measurement from python -m cryptolab.report in one place: what was required, where it is shown, the numbers and the graphs."
        strip="NPCR 99.61 · UACI 33.46 · H 7.999" />
      <Card title="Regenerate" sub="Runs every text, image, hash and signature analysis (about 15 s) and refreshes the figures in docs/figures.">
        <StreamRunner path="/api/ops/report/run" label="Run the full analysis" primary onDone={() => q.refetch()} />
      </Card>

      <Section title="Requirements coverage">
        <Card className="flush"><DataTable rows={REQUIREMENTS} columns={[
          { key: "req", label: "Requirement" }, { key: "where", label: "Where it is shown" },
          { key: "page", label: "Page", render: (x) => (x.page.startsWith("/") ? <Link to={x.page}>{x.page}</Link> : x.page) },
          { key: "status", label: "Status", render: () => <Pill tone="pass">done</Pill> }]} /></Card>
      </Section>

      {!r ? (
        <Card className="section"><Empty icon={<BarChart3 size={28} />} title="No report yet">Run the full analysis above.</Empty></Card>
      ) : (
        <>
          <Section title="Headline results" sub={`Generated ${r.generated_at} · ${r.cpu} · Python ${r.python} · ${r.seconds} s`}>
            <div className="grid g4">
              <Metric label="Text avalanche (GCM-SIV)" value={fmt(siv?.avalanche_bit_pct, 2)} unit="%" foot={`${fmt(siv?.avalanche_char_pct, 2)} % of characters · ideal 50 / ~100`} />
              <Metric label="Key sensitivity (GCM-SIV)" value={fmt(siv?.key_sens_bit_pct, 2)} unit="%" foot="ideal 50 %" />
              <Metric label="Image NPCR" value={fmt(p?.npcr, 4)} unit="%" foot={`ideal ${p?.npcr_ideal}`} />
              <Metric label="Image UACI" value={fmt(p?.uaci, 4)} unit="%" foot={`ideal ${p?.uaci_ideal}`} />
              <Metric label="Cipher image entropy" value={fmt(p?.entropy_cipher.all, 4)} unit="bits" foot={`plain ${fmt(p?.entropy_plain.all, 3)}`} />
              <Metric label="Correlation (H)" value={fmt(p?.corr_cipher.horizontal.mean, 4)} foot={`plain ${fmt(p?.corr_plain.horizontal.mean, 3)}`} />
              <Metric label="PSNR plain vs cipher" value={fmt(p?.psnr_plain_cipher, 2)} unit="dB" foot={`MSE ${fmt(p?.mse_plain_cipher, 0)}`} />
              <Metric label="Ed25519 sign / verify" value={`${fmt(ed?.sign_ms.median, 3)} / ${fmt(ed?.verify_ms.median, 3)}`} unit="ms" />
            </div>
          </Section>
          <Section title="Graphs">
            <div className="grid g2">
              {r.figure_urls.map((f: string) => (
                <Card key={f} className="tight">
                  <a href={fileUrl(f)} target="_blank" rel="noreferrer"><img src={`${fileUrl(f)}?t=${r.modified}`} alt={f.split("/").pop()} style={{ width: "100%", borderRadius: 10, display: "block" }} /></a>
                </Card>
              ))}
            </div>
          </Section>
          <Section title="Text: scheme comparison">
            <Card className="flush"><DataTable rows={r.text_compare} columns={["scheme", "avalanche_bit_pct", "avalanche_char_pct", "key_sens_bit_pct", "ciphertext_entropy_4k", "chi_square_4k", "encrypt_us", "decrypt_us", "overhead_bytes"].map((k) => ({ key: k, num: k !== "scheme" }))} /></Card>
          </Section>
          <Section title="Image: scheme comparison">
            <Card className="flush"><DataTable rows={r.image_compare} columns={["scheme", "npcr", "uaci", "entropy", "corr_h", "corr_v", "corr_d", "mse", "psnr", "encrypt_ms", "decrypt_ms"].map((k) => ({ key: k, num: k !== "scheme" }))} /></Card>
          </Section>
          <Section title="Signatures">
            <Card className="flush"><DataTable rows={r.signatures.map((s: any) => ({ algorithm: s.algorithm, sign_ms: s.sign_ms.median, verify_ms: s.verify_ms.median, keygen_ms: s.keygen_ms.median, signature_bytes: s.signature_bytes, public_key_bytes: s.public_key_bytes }))} /></Card>
          </Section>
        </>
      )}
    </>
  );
}
