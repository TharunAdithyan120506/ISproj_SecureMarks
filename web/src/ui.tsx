/* Small shared components. Status is never colour-only: every pill has an icon and a word. */
import { useEffect, useMemo, useState, type ReactNode } from "react";
import * as Tabs from "@radix-ui/react-tabs";
import { AlertTriangle, Check, CircleSlash, Copy, Download, Info, Loader2, X } from "lucide-react";

export function cx(...c: (string | false | null | undefined)[]) {
  return c.filter(Boolean).join(" ");
}

/* --- page header with the cipher strip ----------------------------------------------------- */

export function PageHead({ eyebrow, title, sub, strip }: { eyebrow: string; title: string; sub?: ReactNode; strip?: string }) {
  return (
    <header className="page-head">
      <div className="eyebrow">{eyebrow}</div>
      <h1 className="page-title">{title}</h1>
      {sub && <p className="page-sub">{sub}</p>}
      {strip && <CipherStrip text={strip} />}
    </header>
  );
}

/** The signature element: plaintext characters resolve, once, into their AES ciphertext bytes. */
export function CipherStrip({ text }: { text: string }) {
  const cells = useMemo(() => {
    const chars = Array.from(text).slice(0, 40);
    let h = 2166136261;
    return chars.map((ch, i) => {
      h = Math.imul(h ^ (ch.charCodeAt(0) + i * 131), 16777619) >>> 0;
      return { ch, hex: (h & 0xff).toString(16).padStart(2, "0") };
    });
  }, [text]);
  const [n, setN] = useState(0);
  useEffect(() => {
    const reduce = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
    if (reduce) {
      setN(cells.length);
      return;
    }
    setN(0);
    let i = 0;
    const id = window.setInterval(() => {
      i += 1;
      setN(i);
      if (i >= cells.length) window.clearInterval(id);
    }, 28);
    return () => window.clearInterval(id);
  }, [cells]);
  return (
    <div className="strip" aria-hidden="true">
      {cells.map((c, i) => (
        <span key={i} className={cx("strip-cell", i < n && "ct")}>{i < n ? c.hex : c.ch === " " ? "·" : c.ch}</span>
      ))}
    </div>
  );
}

/* --- status ------------------------------------------------------------------------------------ */

type Tone = "pass" | "fail" | "warn" | "info" | "neutral";

export function Pill({ tone, children }: { tone: Tone; children: ReactNode }) {
  const Icon = { pass: Check, fail: X, warn: AlertTriangle, info: Info, neutral: CircleSlash }[tone];
  return (
    <span className={cx("pill", tone)}>
      <Icon size={13} strokeWidth={2.6} aria-hidden="true" />
      {children}
    </span>
  );
}

export function OkPill({ ok, yes, no }: { ok: boolean | null | undefined; yes: string; no: string }) {
  if (ok === null || ok === undefined) return <Pill tone="neutral">skipped</Pill>;
  return <Pill tone={ok ? "pass" : "fail"}>{ok ? yes : no}</Pill>;
}

export function Notice({ tone = "info", children }: { tone?: "info" | "warn" | "fail" | "pass"; children: ReactNode }) {
  const Icon = { info: Info, warn: AlertTriangle, fail: X, pass: Check }[tone];
  return (
    <div className={cx("notice", tone !== "info" && tone)} role={tone === "fail" ? "alert" : undefined}>
      <Icon size={16} aria-hidden="true" />
      <div>{children}</div>
    </div>
  );
}

export function Spinner({ label = "Working" }: { label?: string }) {
  return (
    <span className="row muted small" role="status">
      <Loader2 size={15} className="spin" aria-hidden="true" /> {label}…
    </span>
  );
}

export function Empty({ icon, title, children }: { icon: ReactNode; title: string; children?: ReactNode }) {
  return (
    <div className="empty">
      {icon}
      <b>{title}</b>
      {children}
    </div>
  );
}

/* --- surfaces ------------------------------------------------------------------------------------ */

export function Card({ title, sub, actions, children, className, tone }: {
  title?: ReactNode; sub?: ReactNode; actions?: ReactNode; children?: ReactNode; className?: string; tone?: "ok" | "bad";
}) {
  return (
    <section className={cx("card", tone, className)}>
      {(title || actions) && (
        <div className="card-head">
          <div>
            {title && <h3 className="card-title">{title}</h3>}
            {sub && <div className="card-sub">{sub}</div>}
          </div>
          {actions && <div className="row">{actions}</div>}
        </div>
      )}
      {children}
    </section>
  );
}

export function Section({ title, sub, children, actions }: { title: string; sub?: ReactNode; children: ReactNode; actions?: ReactNode }) {
  return (
    <section className="section">
      <div className="row" style={{ alignItems: "flex-end" }}>
        <div style={{ flex: 1, minWidth: 240 }}>
          <h2 className="section-title">{title}</h2>
          {sub && <p className="section-sub">{sub}</p>}
        </div>
        {actions && <div className="row" style={{ marginBottom: 14 }}>{actions}</div>}
      </div>
      {children}
    </section>
  );
}

export function Metric({ label, value, unit, foot, ideal, pct, tone }: {
  label: ReactNode; value: ReactNode; unit?: string; foot?: ReactNode; ideal?: number; pct?: number; tone?: "pass" | "fail";
}) {
  return (
    <div className="metric">
      <div className="metric-label">{label}</div>
      <div className="metric-value" style={tone ? { color: `var(--${tone})` } : undefined}>
        {value}
        {unit && <span className="unit">{unit}</span>}
      </div>
      {pct !== undefined && (
        <div className="meter" aria-hidden="true">
          <span style={{ width: `${Math.max(0, Math.min(100, pct))}%` }} />
          {ideal !== undefined && <i style={{ left: `${ideal}%` }} />}
        </div>
      )}
      {foot && <div className="metric-foot">{foot}</div>}
    </div>
  );
}

/* --- tabs and segmented controls ---------------------------------------------------------------------- */

export function TabView({ tabs, defaultValue }: { tabs: { value: string; label: string; content: ReactNode }[]; defaultValue?: string }) {
  return (
    <Tabs.Root defaultValue={defaultValue || tabs[0].value}>
      <Tabs.List className="seg tabs-list" aria-label="Sections">
        {tabs.map((t) => (
          <Tabs.Trigger key={t.value} value={t.value}>{t.label}</Tabs.Trigger>
        ))}
      </Tabs.List>
      {tabs.map((t) => (
        <Tabs.Content key={t.value} value={t.value} className="fade-in">{t.content}</Tabs.Content>
      ))}
    </Tabs.Root>
  );
}

export function Segmented<T extends string>({ value, options, onChange, label }: {
  value: T; options: { value: T; label: string }[]; onChange: (v: T) => void; label: string;
}) {
  return (
    <div className="seg" role="group" aria-label={label}>
      {options.map((o) => (
        <button key={o.value} type="button" aria-pressed={o.value === value} onClick={() => onChange(o.value)}>{o.label}</button>
      ))}
    </div>
  );
}

/* --- bytes ------------------------------------------------------------------------------------------- */

export function CopyButton({ text, label = "Copy" }: { text: string; label?: string }) {
  const [done, setDone] = useState(false);
  return (
    <button type="button" className="btn plain sm" onClick={() => {
      navigator.clipboard?.writeText(text);
      setDone(true);
      setTimeout(() => setDone(false), 1200);
    }}>
      {done ? <Check size={14} aria-hidden="true" /> : <Copy size={14} aria-hidden="true" />} {done ? "Copied" : label}
    </button>
  );
}

export function Hex({ label, hex, note, short }: { label: string; hex: string; note?: string; short?: boolean }) {
  return (
    <div>
      <div className="hexlabel">
        <span><b>{label}</b> · {hex.length / 2} B{note ? ` · ${note}` : ""}</span>
        <CopyButton text={hex} />
      </div>
      <div className={cx("hex", short && "short")}>{hex || "(empty)"}</div>
    </div>
  );
}

export function DownloadButton({ onClick, children }: { onClick: () => void; children: ReactNode }) {
  return (
    <button type="button" className="btn sm" onClick={onClick}>
      <Download size={14} aria-hidden="true" /> {children}
    </button>
  );
}

/** JSON viewer with light syntax colouring. */
export function JsonView({ data }: { data: unknown }) {
  const html = useMemo(() => {
    const s = JSON.stringify(data, null, 2) ?? "";
    const esc = s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
    return esc.replace(/("(?:\\.|[^"\\])*")(\s*:)?|\b(-?\d+(?:\.\d+)?(?:e[+-]?\d+)?|true|false|null)\b/g,
      (m, str, colon, num) => str ? (colon ? `<span class="k">${str}</span>${colon}` : `<span class="s">${str}</span>`)
        : num ? `<span class="n">${m}</span>` : m);
  }, [data]);
  return <pre className="json" dangerouslySetInnerHTML={{ __html: html }} />;
}

/* --- numbers --------------------------------------------------------------------------------------------- */

export function fmt(v: number | string | null | undefined, digits = 3): string {
  if (v === null || v === undefined || v === "") return "–";
  if (v === "inf") return "∞";
  const n = Number(v);
  if (!Number.isFinite(n)) return String(v);
  if (n !== 0 && Math.abs(n) < 0.001) return n.toExponential(2);
  return n.toLocaleString(undefined, { maximumFractionDigits: digits });
}

export function bytes(n: number): string {
  if (n >= 1048576) return `${fmt(n / 1048576, 2)} MB`;
  if (n >= 1024) return `${fmt(n / 1024, 1)} KB`;
  return `${n} B`;
}

export function DataTable({ rows, columns, max = 520, rowClass }: {
  rows: Record<string, any>[]; columns?: { key: string; label?: string; num?: boolean; code?: boolean; render?: (r: any) => ReactNode }[];
  max?: number; rowClass?: (r: any) => string | undefined;
}) {
  const cols = columns || Object.keys(rows[0] || {}).map((k) => ({ key: k }));
  if (!rows.length) return <div className="muted small" style={{ padding: 14 }}>No rows.</div>;
  return (
    <div className="table-wrap" style={{ maxHeight: max }}>
      <table className="t">
        <thead><tr>{cols.map((c: any) => <th key={c.key} className={c.num ? "num" : undefined}>{c.label ?? c.key}</th>)}</tr></thead>
        <tbody>
          {rows.map((r, i) => (
            <tr key={i} className={rowClass?.(r)}>
              {cols.map((c: any) => (
                <td key={c.key} className={cx(c.num && "num", c.code && "code")}>
                  {c.render ? c.render(r) : typeof r[c.key] === "object" && r[c.key] !== null ? JSON.stringify(r[c.key]) : String(r[c.key] ?? "")}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
