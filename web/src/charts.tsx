/* Chart wrappers on Recharts. Colours are read from the CSS tokens at runtime, so every
   chart follows light/dark appearance and the same scheme always has the same hue. */
import { useEffect, useRef, useState, type ReactNode } from "react";
import {
  Bar, BarChart, CartesianGrid, Cell, Legend, Line, LineChart, ReferenceLine, ResponsiveContainer,
  Scatter, ScatterChart, Tooltip, XAxis, YAxis, ZAxis,
} from "recharts";

const TOKENS = ["c1", "c2", "c3", "c4", "c5", "c6", "grid", "label", "label-2", "pass", "fail", "accent", "ch-r", "ch-g", "ch-b", "card"] as const;
type Colors = Record<(typeof TOKENS)[number], string>;

function read(): Colors {
  const s = getComputedStyle(document.documentElement);
  return Object.fromEntries(TOKENS.map((t) => [t, s.getPropertyValue(`--${t}`).trim() || "#888"])) as Colors;
}

export function useColors(): Colors {
  const [c, setC] = useState<Colors>(read);
  useEffect(() => {
    const mq = window.matchMedia("(prefers-color-scheme: dark)");
    const on = () => setC(read());
    mq.addEventListener("change", on);
    return () => mq.removeEventListener("change", on);
  }, []);
  return c;
}

export const SCHEME_KEY: Record<string, keyof Colors> = {
  "AES-256-GCM-SIV": "c1", "AES-256-GCM": "c2", "AES-256-CTR": "c3", "AES-256-CBC": "c4", "AES-256-ECB": "c5", "Logistic-map": "c6",
  "Ed25519": "c1", "ECDSA-P256": "c3", "RSA-PSS-2048": "c2", "RSA-PSS-3072": "c5",
  "MD5": "c5", "SHA-1": "c2", "SHA-256": "c1", "SHA-512": "c6", "SHA3-256": "c3", "BLAKE2b": "c4", "djb2": "label-2",
};
export const short = (s: string) => s.replace("AES-256-", "");

export type Series = { key: string; name: string; color?: string };

const axisProps = (c: Colors) => ({ stroke: c.grid, tick: { fill: c["label-2"], fontSize: 11 }, tickLine: false });

function Tip({ active, payload, label, unit, labelFmt }: any) {
  if (!active || !payload?.length) return null;
  return (
    <div className="tt">
      <div style={{ fontWeight: 600, marginBottom: 4 }}>{labelFmt ? labelFmt(label) : label}</div>
      {payload.map((p: any) => (
        <div key={p.dataKey + p.name} className="row" style={{ gap: 6 }}>
          <i style={{ width: 8, height: 8, borderRadius: 2, background: p.color || p.fill, display: "inline-block" }} />
          <span className="muted">{p.name}</span>
          <b style={{ marginLeft: "auto", fontVariantNumeric: "tabular-nums" }}>
            {typeof p.value === "number" ? p.value.toLocaleString(undefined, { maximumFractionDigits: 4 }) : p.value}{unit || ""}
          </b>
        </div>
      ))}
    </div>
  );
}

export function LineBox({ data, x, series, logY, logX, yLabel, xLabel, height = 300, unit, xFmt, refY }: {
  data: any[]; x: string; series: Series[]; logY?: boolean; logX?: boolean; yLabel?: string; xLabel?: string;
  height?: number; unit?: string; xFmt?: (v: any) => string; refY?: { y: number; label: string }[];
}) {
  const c = useColors();
  const pal = [c.c1, c.c2, c.c3, c.c4, c.c5, c.c6];
  return (
    <div style={{ width: "100%", height }}>
      <ResponsiveContainer>
        <LineChart data={data} margin={{ top: 8, right: 16, bottom: xLabel ? 18 : 4, left: 4 }}>
          <CartesianGrid stroke={c.grid} vertical={false} />
          <XAxis dataKey={x} {...axisProps(c)} scale={logX ? "log" : "auto"} type={logX ? "number" : "category"}
            domain={logX ? ["dataMin", "dataMax"] : undefined} tickFormatter={xFmt} allowDuplicatedCategory={false}
            label={xLabel ? { value: xLabel, position: "insideBottom", offset: -10, fill: c["label-2"], fontSize: 11 } : undefined} />
          <YAxis {...axisProps(c)} scale={logY ? "log" : "auto"} domain={logY ? ["auto", "auto"] : [0, "auto"]} allowDataOverflow={false}
            width={58} tickFormatter={(v) => (Math.abs(v) < 0.01 && v !== 0 ? v.toExponential(0) : v.toLocaleString(undefined, { maximumFractionDigits: 3 }))}
            label={yLabel ? { value: yLabel, angle: -90, position: "insideLeft", fill: c["label-2"], fontSize: 11, dy: 40 } : undefined} />
          <Tooltip content={<Tip unit={unit} labelFmt={xFmt} />} />
          <Legend wrapperStyle={{ fontSize: 12, color: c["label-2"] }} iconType="circle" iconSize={8} />
          {refY?.map((r) => (
            <ReferenceLine key={r.label} y={r.y} stroke={c.pass} strokeDasharray="5 4"
              label={{ value: r.label, position: "insideTopRight", fill: c.pass, fontSize: 11 }} />
          ))}
          {series.map((s, i) => (
            <Line key={s.key} type="monotone" dataKey={s.key} name={s.name} stroke={s.color || pal[i % pal.length]} strokeWidth={2}
              dot={{ r: 3, strokeWidth: 0, fill: s.color || pal[i % pal.length] }} activeDot={{ r: 5 }} connectNulls isAnimationActive={false} />
          ))}
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}

export function BarBox({ data, x, series, logY, yLabel, height = 300, unit, refY, colorBy, domain, layout }: {
  data: any[]; x: string; series: Series[]; logY?: boolean; yLabel?: string; height?: number; unit?: string;
  refY?: { y: number; label: string }[]; colorBy?: (row: any) => string; domain?: [number | string, number | string];
  layout?: "horizontal" | "vertical";
}) {
  const c = useColors();
  const pal = [c.c1, c.c2, c.c3, c.c4, c.c5, c.c6];
  const vertical = layout === "vertical";
  return (
    <div style={{ width: "100%", height }}>
      <ResponsiveContainer>
        <BarChart data={data} layout={layout} margin={{ top: 14, right: 16, bottom: 4, left: vertical ? 30 : 4 }}>
          <CartesianGrid stroke={c.grid} vertical={vertical} horizontal={!vertical} />
          {vertical ? (
            <>
              <XAxis type="number" {...axisProps(c)} scale={logY ? "log" : "auto"} domain={logY ? ["auto", "auto"] : domain || [0, "auto"]} />
              <YAxis type="category" dataKey={x} {...axisProps(c)} width={110} />
            </>
          ) : (
            <>
              <XAxis dataKey={x} {...axisProps(c)} interval={0} />
              <YAxis {...axisProps(c)} scale={logY ? "log" : "auto"} domain={logY ? ["auto", "auto"] : domain || [0, "auto"]} width={58}
                label={yLabel ? { value: yLabel, angle: -90, position: "insideLeft", fill: c["label-2"], fontSize: 11, dy: 40 } : undefined} />
            </>
          )}
          <Tooltip content={<Tip unit={unit} />} cursor={{ fill: c.grid }} />
          {series.length > 1 && <Legend wrapperStyle={{ fontSize: 12 }} iconType="circle" iconSize={8} />}
          {refY?.map((r) => (
            <ReferenceLine key={r.label} y={vertical ? undefined : r.y} x={vertical ? r.y : undefined} stroke={c.pass} strokeDasharray="5 4"
              label={{ value: r.label, position: vertical ? "top" : "insideTopRight", fill: c.pass, fontSize: 11 }} />
          ))}
          {series.map((s, i) => (
            <Bar key={s.key} dataKey={s.key} name={s.name} fill={s.color || pal[i % pal.length]} radius={vertical ? [0, 5, 5, 0] : [5, 5, 0, 0]}
              maxBarSize={46} isAnimationActive={false}>
              {colorBy && data.map((row, j) => <Cell key={j} fill={colorBy(row)} />)}
            </Bar>
          ))}
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

export function ScatterBox({ points, color, height = 220, title }: { points: number[][]; color: string; height?: number; title?: ReactNode }) {
  const c = useColors();
  const data = points.map(([x, y]) => ({ x, y }));
  return (
    <div>
      {title && <div className="small" style={{ fontWeight: 600, marginBottom: 2 }}>{title}</div>}
      <div style={{ width: "100%", height }}>
        <ResponsiveContainer>
          <ScatterChart margin={{ top: 6, right: 8, bottom: 0, left: -18 }}>
            <CartesianGrid stroke={c.grid} />
            <XAxis type="number" dataKey="x" domain={[0, 255]} ticks={[0, 128, 255]} {...axisProps(c)} />
            <YAxis type="number" dataKey="y" domain={[0, 255]} ticks={[0, 128, 255]} {...axisProps(c)} />
            <ZAxis range={[6, 6]} />
            <Scatter data={data} fill={color} fillOpacity={0.55} isAnimationActive={false} />
          </ScatterChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}

/** 256-bin histograms for R, G, B drawn on a canvas (768 bars is too many SVG nodes). */
export function Histogram({ hist, height = 150, title }: { hist: Record<"R" | "G" | "B", number[]>; height?: number; title?: ReactNode }) {
  const ref = useRef<HTMLCanvasElement>(null);
  const c = useColors();
  useEffect(() => {
    const cv = ref.current;
    if (!cv) return;
    const dpr = window.devicePixelRatio || 1;
    const w = cv.clientWidth;
    cv.width = w * dpr;
    cv.height = height * dpr;
    const ctx = cv.getContext("2d")!;
    ctx.scale(dpr, dpr);
    ctx.clearRect(0, 0, w, height);
    const max = Math.max(...hist.R, ...hist.G, ...hist.B, 1);
    const cols = { R: c["ch-r"], G: c["ch-g"], B: c["ch-b"] };
    ctx.globalCompositeOperation = "source-over";
    (["R", "G", "B"] as const).forEach((ch) => {
      ctx.fillStyle = cols[ch];
      ctx.globalAlpha = 0.5;
      hist[ch].forEach((v, i) => {
        const h = (v / max) * (height - 4);
        ctx.fillRect((i / 256) * w, height - h, Math.max(1, w / 256), h);
      });
    });
    ctx.globalAlpha = 1;
  }, [hist, height, c]);
  return (
    <div>
      {title && <div className="small" style={{ fontWeight: 600, marginBottom: 4 }}>{title}</div>}
      <canvas ref={ref} style={{ width: "100%", height, display: "block", borderRadius: 8, background: "var(--code-bg)" }}
        role="img" aria-label="RGB pixel value histogram, 0 to 255" />
      <div className="row small muted" style={{ justifyContent: "space-between" }}><span>0</span><span>pixel value</span><span>255</span></div>
    </div>
  );
}

/** Diffusion map: rows = input bit flipped, columns = output byte, cell = share of its bits that flipped. */
export function Heatmap({ matrix, height = 220 }: { matrix: number[][]; height?: number }) {
  const ref = useRef<HTMLCanvasElement>(null);
  const c = useColors();
  useEffect(() => {
    const cv = ref.current;
    if (!cv || !matrix.length) return;
    const rows = matrix.length;
    const cols = matrix[0].length;
    cv.width = cols;
    cv.height = rows;
    const ctx = cv.getContext("2d")!;
    const img = ctx.createImageData(cols, rows);
    const hex = c.accent.replace("#", "");
    const ar = parseInt(hex.slice(0, 2), 16), ag = parseInt(hex.slice(2, 4), 16), ab = parseInt(hex.slice(4, 6), 16);
    for (let y = 0; y < rows; y++) {
      for (let x = 0; x < cols; x++) {
        const v = Math.min(1, matrix[y][x] / 0.5); // 0.5 = ideal, full colour
        const i = (y * cols + x) * 4;
        img.data[i] = ar; img.data[i + 1] = ag; img.data[i + 2] = ab; img.data[i + 3] = Math.round(25 + v * 230);
      }
    }
    ctx.putImageData(img, 0, 0);
  }, [matrix, c]);
  return (
    <div>
      <canvas ref={ref} style={{ width: "100%", height, imageRendering: "pixelated", borderRadius: 8, background: "var(--code-bg)", display: "block" }}
        role="img" aria-label="Diffusion map: input bits against output bytes" />
      <div className="row small muted" style={{ justifyContent: "space-between" }}>
        <span>output byte 0 →</span><span>pale = no change · solid = 50 % of bits flip (ideal)</span>
      </div>
    </div>
  );
}

export function Legendish({ items }: { items: { label: string; color: string }[] }) {
  return <div className="legend">{items.map((i) => <span key={i.label}><i style={{ background: i.color }} />{i.label}</span>)}</div>;
}
