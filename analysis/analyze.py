"""Traffic analyser (ISL module 7): PyShark over a saved capture.

    python -m analysis.analyze captures\\exp3_replay.pcapng --audit data\\securemarks.db

1. Read every packet on the server ports (PyShark; pure-Python reader if tshark is missing).
2. Rebuild HTTP/1.1 messages from raw TCP payloads, pair n-th request with n-th response.
3. One row per request: times, latency, device, method, path, status, error code,
   X-Request-ID, X-Timestamp, body bytes, bytes on the wire, body entropy.
4. Flags: `replay` = request ID already seen within 30 s; `flood` = a source above
   5 requests/s in any 1-second window.
5. Cross-check every flag against audit_log by request ID.
Outputs in analysis/out/<capture>/: messages.csv, flows.csv, flags.csv, summary.json
and four graphs.
"""
from __future__ import annotations

import argparse
import json
import sqlite3
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import pandas as pd  # noqa: E402
import yaml  # noqa: E402
from rich.console import Console  # noqa: E402
from rich.table import Table  # noqa: E402

from analysis import plots  # noqa: E402
from analysis.httpparse import build_messages, pair_messages  # noqa: E402
from analysis.packets import HTTP_PORTS, TLS_PORTS, read_capture  # noqa: E402
from middleware.crypto.hashing import entropy  # noqa: E402

console = Console(highlight=False, width=None if sys.stdout.isatty() else 140)
REPLAY_WINDOW_S = 30
FLOOD_PER_SEC = 5


def device_map() -> dict[str, str]:
    data = yaml.safe_load((ROOT / "config" / "devices.yaml").read_text(encoding="utf-8"))
    return {r["ip"]: r["label"] for r in data["roles"].values()}


def body_kind(path: str, content_type: str) -> str:
    if path.startswith("/plain/"):
        return "plain"
    if "octet-stream" in content_type:
        return "protected"
    return "control"  # login, session handshake, key lookups, error bodies


def build_rows(pairs, ip_to_device: dict[str, str]) -> pd.DataFrame:
    rows = []
    for req, resp in pairs:
        device = ip_to_device.get(req.src)
        if device is None:  # loopback IPs collapsed or unknown host: fall back to the header
            device = req.headers.get("x-device", "unknown")
        error_code = ""
        if resp is not None and resp.status != 200:
            try:
                error_code = json.loads(resp.body).get("error", "")
            except ValueError:
                error_code = f"http_{resp.status}"
        path = (req.path or "").split("?")[0]
        rows.append({
            "req_ts": req.start_ts,
            "resp_ts": resp.end_ts if resp else None,
            "latency_ms": round((resp.end_ts - req.start_ts) * 1000, 3) if resp else None,
            "src_ip": req.src,
            "device": device,
            "method": req.method,
            "path": path,
            "status": resp.status if resp else None,
            "error_code": error_code,
            "request_id": req.headers.get("x-request-id", ""),
            "x_timestamp": req.headers.get("x-timestamp", ""),
            "policy": req.headers.get("x-policy", ""),
            "req_body_bytes": len(req.body),
            "resp_body_bytes": len(resp.body) if resp else 0,
            "wire_bytes": req.wire_bytes + (resp.wire_bytes if resp else 0),
            "req_entropy": round(entropy(req.body), 4),
            "resp_entropy": round(entropy(resp.body), 4) if resp else 0.0,
            "req_kind": body_kind(path, req.headers.get("content-type", "")) if req.body else "",
            "resp_kind": body_kind(path, resp.headers.get("content-type", "")) if resp and resp.body else "",
            "small_sample": len(req.body) < 256,
            "stream": req.stream,
            "frames": len(req.frames) + (len(resp.frames) if resp else 0),
            "truncated": req.truncated or (resp.truncated if resp else True),
        })
    df = pd.DataFrame(rows)
    if df.empty:
        df = pd.DataFrame(columns=list(rows[0]) if rows else [
            "req_ts", "resp_ts", "latency_ms", "src_ip", "device", "method", "path", "status", "error_code",
            "request_id", "x_timestamp", "policy", "req_body_bytes", "resp_body_bytes", "wire_bytes",
            "req_entropy", "resp_entropy", "req_kind", "resp_kind", "small_sample", "stream", "frames", "truncated"])
    return df


def add_flags(df: pd.DataFrame, window_s: float = REPLAY_WINDOW_S, flood_rate: int = FLOOD_PER_SEC) -> pd.DataFrame:
    df = df.sort_values("req_ts").reset_index(drop=True)
    flags = [""] * len(df)
    seen: dict[str, float] = {}
    for i, r in df.iterrows():
        rid = r.request_id
        if rid and rid in seen:
            # PRD rule: a request ID seen again within 30 s is a replay. A duplicate
            # outside the window is still a replay attempt (the server answers
            # stale_request), so it gets its own label rather than none.
            flags[i] = "replay" if r.req_ts - seen[rid] <= window_s else "replay_late"
        if rid and rid not in seen:
            seen[rid] = r.req_ts
    by_source = defaultdict(list)
    for i, r in df.iterrows():
        by_source[r.device if r.device != "unknown" else r.src_ip].append(i)
    for idxs in by_source.values():
        times = df.loc[idxs, "req_ts"].tolist()
        lo = 0
        for hi in range(len(idxs)):
            while times[hi] - times[lo] >= 1.0:
                lo += 1
            if hi - lo + 1 > flood_rate:
                for k in range(lo, hi + 1):
                    if not flags[idxs[k]]:
                        flags[idxs[k]] = "flood"
    df["flag"] = flags
    return df


def cross_check(df: pd.DataFrame, audit_db: Path | None) -> pd.DataFrame:
    flagged = df[df.flag != ""].copy()
    cols = ["audit_id", "audit_action", "audit_outcome", "audit_code", "audit_match"]
    if flagged.empty:
        return flagged.assign(**{c: [] for c in cols})
    audit: dict[str, list[dict]] = defaultdict(list)
    if audit_db and Path(audit_db).exists():
        con = sqlite3.connect(f"file:{Path(audit_db).as_posix()}?mode=ro", uri=True)
        con.row_factory = sqlite3.Row
        ids = list(set(flagged.request_id))
        for chunk in range(0, len(ids), 500):
            part = ids[chunk:chunk + 500]
            q = f"SELECT id, ts, request_id, action, outcome, code FROM audit_log WHERE request_id IN ({','.join('?' * len(part))})"
            for row in con.execute(q, part):
                audit[row["request_id"]].append(dict(row))
        con.close()
    out = {c: [] for c in cols}
    for _, r in flagged.iterrows():
        cands = [a for a in audit.get(r.request_id, []) if abs(a["ts"] - r.req_ts) <= 5]
        best = min(cands, key=lambda a: abs(a["ts"] - r.req_ts)) if cands else None
        out["audit_id"].append(best["id"] if best else None)
        out["audit_action"].append(best["action"] if best else "")
        out["audit_outcome"].append(best["outcome"] if best else "")
        out["audit_code"].append(best["code"] if best else "")
        out["audit_match"].append(bool(best))
    for c in cols:
        flagged[c] = out[c]
    return flagged


def flows_frame(data, df: pd.DataFrame, ip_to_device: dict[str, str]) -> pd.DataFrame:
    reqs_per_stream = df.groupby("stream").size().to_dict() if not df.empty else {}
    header_device = df.groupby("stream").device.first().to_dict() if not df.empty else {}
    rows = []
    for f in sorted(data.flows.values(), key=lambda f: f.first_ts):
        tls = f.sport in TLS_PORTS
        rows.append({
            "stream": f.stream, "client": f.client, "client_port": f.cport, "server": f.server,
            "server_port": f.sport, "device": ip_to_device.get(f.client) or header_device.get(f.stream, "unknown"),
            "packets": f.packets, "bytes": f.bytes, "payload_bytes": f.payload_bytes,
            "start_ts": f.first_ts, "duration_s": round(f.last_ts - f.first_ts, 4),
            "retransmissions": f.retrans, "http_requests": reqs_per_stream.get(f.stream, 0), "tls": tls,
            "tls_payload_entropy": round(entropy(bytes(f.tls_payload)), 4) if tls else None,
        })
    return pd.DataFrame(rows)


def summarise(name: str, data, df: pd.DataFrame, flows: pd.DataFrame, flags: pd.DataFrame, elapsed: float) -> dict:
    def ent(kind: str, big: bool) -> float | None:
        vals = []
        for side in ("req", "resp"):
            sel = df[(df[f"{side}_kind"] == kind)]
            sel = sel[(sel[f"{side}_body_bytes"] >= 1024) if big else (sel[f"{side}_body_bytes"] < 256)]
            vals += sel[f"{side}_entropy"].tolist()
        return round(sum(vals) / len(vals), 3) if vals else None

    return {
        "capture": name, "engine": data.engine, "packets": data.packets, "tcp_streams": len(data.flows),
        "http_requests": int(len(df)), "analysis_s": round(elapsed, 2),
        "devices": df.device.value_counts().to_dict() if not df.empty else {},
        "status_counts": {str(k): int(v) for k, v in df.status.value_counts().to_dict().items()} if not df.empty else {},
        "entropy_mean": {"plain_ge_1KB": ent("plain", True), "protected_ge_1KB": ent("protected", True),
                         "plain_lt_256B": ent("plain", False), "protected_lt_256B": ent("protected", False)},
        "flags": flags.flag.value_counts().to_dict() if not flags.empty else {},
        "flags_matched_in_audit": int(flags.audit_match.sum()) if not flags.empty else 0,
        "flags_without_audit": int((~flags.audit_match.astype(bool)).sum()) if not flags.empty else 0,
        "tls_streams": int(flows.tls.sum()) if not flows.empty else 0,
        "retransmissions": int(flows.retransmissions.sum()) if not flows.empty else 0,
    }


def analyze(pcap: Path, audit_db: Path | None = None, engine: str = "auto", out_dir: Path | None = None,
            quiet: bool = False) -> dict:
    t0 = time.time()
    name = pcap.stem
    out = out_dir or ROOT / "analysis" / "out" / name
    out.mkdir(parents=True, exist_ok=True)
    ip_to_device = device_map()
    data = read_capture(pcap, engine=engine)
    messages = build_messages(data.segments, HTTP_PORTS)
    df = build_rows(pair_messages(messages), ip_to_device)
    if not df.empty:
        df = add_flags(df)
    else:
        df["flag"] = []
    flags = cross_check(df, audit_db)
    flows = flows_frame(data, df, ip_to_device)

    df.to_csv(out / "messages.csv", index=False)
    flows.to_csv(out / "flows.csv", index=False)
    flags.to_csv(out / "flags.csv", index=False)
    graphs = [
        plots.entropy_plain_vs_protected(df, out / "entropy_plain_vs_protected.png"),
        plots.overhead_bytes(df, out / "overhead_bytes.png"),
        plots.latency_by_device(df, out / "latency_by_device.png"),
        plots.rate_timeline(df, out / "rate_timeline.png"),
    ]
    summary = summarise(name, data, df, flows, flags, time.time() - t0)
    summary["outputs"] = [str(p.relative_to(ROOT)) for p in [out / "messages.csv", out / "flows.csv", out / "flags.csv", *graphs]]
    (out / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    if not quiet:
        print_summary(summary, df, flags)
    return summary


def print_summary(summary: dict, df: pd.DataFrame, flags: pd.DataFrame) -> None:
    console.rule(f"[bold cyan]Traffic analysis · {summary['capture']}")
    console.print(f"engine [bold]{summary['engine']}[/] · {summary['packets']} packets · {summary['tcp_streams']} TCP streams · "
                  f"{summary['http_requests']} HTTP requests · {summary['analysis_s']} s")
    if summary["devices"]:
        console.print("devices: " + ", ".join(f"{k} ({v})" for k, v in summary["devices"].items()))
    e = summary["entropy_mean"]
    console.print(f"entropy (bits/byte)  plain ≥1KB: {e['plain_ge_1KB']}   protected ≥1KB: {e['protected_ge_1KB']}   "
                  f"[dim]plain <256B: {e['plain_lt_256B']}   protected <256B: {e['protected_lt_256B']}[/]")
    if not df.empty:
        t = Table(title="per endpoint")
        for col in ("path", "n", "statuses", "p50 ms", "body B", "wire B"):
            t.add_column(col)
        for path, g in df.groupby("path"):
            sc = Counter(int(s) for s in g.status.dropna())
            t.add_row(path, str(len(g)), " ".join(f"{k}x{v}" for k, v in sorted(sc.items())),
                      f"{g.latency_ms.median():.1f}", f"{(g.req_body_bytes + g.resp_body_bytes).mean():.0f}",
                      f"{g.wire_bytes.mean():.0f}")
        console.print(t)
    if not flags.empty:
        t = Table(title=f"flags ({summary['flags_matched_in_audit']} matched in audit_log, "
                        f"{summary['flags_without_audit']} without)")
        for col in ("time", "device", "flag", "request_id", "status", "audit action", "outcome", "code"):
            t.add_column(col)
        shown = pd.concat([flags[flags.flag.isin(["replay", "replay_late"])], flags[flags.flag == "flood"].head(8)])
        for _, r in shown.iterrows():
            t.add_row(time.strftime("%H:%M:%S", time.localtime(r.req_ts)), r.device, r.flag, r.request_id[:13] + "…",
                      str(int(r.status)) if pd.notna(r.status) else "-", r.audit_action, r.audit_outcome, r.audit_code)
        console.print(t)
        if len(flags[flags.flag == "flood"]) > 8:
            console.print(f"[dim]… {len(flags[flags.flag == 'flood']) - 8} more flood rows in flags.csv[/]")
    console.print("outputs: " + ", ".join(summary["outputs"]))


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pcap", type=Path)
    ap.add_argument("--audit", type=Path, default=ROOT / "data" / "securemarks.db", help="SecureMarks DB with audit_log")
    ap.add_argument("--engine", choices=["auto", "pyshark", "python"], default="auto")
    ap.add_argument("--out", type=Path)
    ap.add_argument("--json", action="store_true", help="print the summary as JSON only")
    a = ap.parse_args()
    summary = analyze(a.pcap, a.audit, a.engine, a.out, quiet=a.json)
    if a.json:
        print(json.dumps(summary))


if __name__ == "__main__":
    main()
