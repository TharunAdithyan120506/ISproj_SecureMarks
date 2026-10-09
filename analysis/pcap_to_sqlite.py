"""PCAP -> SQLite (ISL module 4).

    python -m analysis.pcap_to_sqlite captures\\exp3_replay.pcapng

Loads every packet and every HTTP message of a capture into
data\\capture_<name>.db (tables `packets` and `http_messages`), attaches the
SecureMarks database and joins each replay / flood flag to its audit_log row:

    ATTACH 'data/securemarks.db' AS app;
    SELECT m.ts, m.device, m.request_id, m.status, a.action, a.outcome, a.code
    FROM http_messages m LEFT JOIN app.audit_log a ON a.request_id = m.request_id
    WHERE m.flag IN ('replay', 'flood') ORDER BY m.ts;

A replayed request ID has two audit rows (the original and the replay); the
refined join below picks the row closest in time to each captured message.
"""
from __future__ import annotations

import argparse
import json
import sqlite3
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import pandas as pd  # noqa: E402
from rich.console import Console  # noqa: E402
from rich.table import Table  # noqa: E402

from analysis.analyze import add_flags, build_rows, device_map  # noqa: E402
from analysis.httpparse import build_messages, pair_messages  # noqa: E402
from analysis.packets import HTTP_PORTS, read_capture  # noqa: E402

console = Console(highlight=False, width=None if sys.stdout.isatty() else 140)

PRD_JOIN = """
SELECT m.ts, m.device, m.request_id, m.status, a.action, a.outcome, a.code
FROM http_messages m
LEFT JOIN app.audit_log a ON a.request_id = m.request_id
WHERE m.flag IN ('replay', 'flood')
ORDER BY m.ts
"""

NEAREST_JOIN = """
WITH flagged AS (
    SELECT * FROM http_messages WHERE flag IN ('replay', 'replay_late', 'flood')
),
candidates AS (
    SELECT f.id AS mid, a.id AS aid, ABS(a.ts - f.ts) AS dt,
           ROW_NUMBER() OVER (PARTITION BY f.id ORDER BY ABS(a.ts - f.ts)) AS rn
    FROM flagged f
    JOIN app.audit_log a ON a.request_id = f.request_id AND ABS(a.ts - f.ts) <= 5
)
SELECT f.ts, f.device, f.src_ip, f.path, f.flag, f.request_id, f.status, f.error_code,
       a.id AS audit_id, a.action, a.outcome, a.code, a.src_ip AS audit_src_ip, ROUND(c.dt, 3) AS dt_s
FROM flagged f
LEFT JOIN candidates c ON c.mid = f.id AND c.rn = 1
LEFT JOIN app.audit_log a ON a.id = c.aid
ORDER BY f.ts
"""


def convert(pcap: Path, app_db: Path, out_db: Path | None = None, engine: str = "auto") -> tuple[Path, pd.DataFrame, pd.DataFrame]:
    data = read_capture(pcap, engine=engine)
    pairs = pair_messages(build_messages(data.segments, HTTP_PORTS))
    df = build_rows(pairs, device_map())
    if not df.empty:
        df = add_flags(df)
    else:
        df["flag"] = []

    out_db = out_db or ROOT / "data" / f"capture_{pcap.stem}.db"
    out_db.parent.mkdir(parents=True, exist_ok=True)
    if out_db.exists():
        out_db.unlink()
    con = sqlite3.connect(out_db)
    con.execute("""CREATE TABLE packets(frame INTEGER PRIMARY KEY, ts REAL, src TEXT, dst TEXT, sport INTEGER,
                   dport INTEGER, stream INTEGER, length INTEGER, payload_len INTEGER, retrans INTEGER)""")
    retrans = data.retrans_frames | {s.frame for s in data.segments if s.retrans}
    con.executemany("INSERT OR IGNORE INTO packets VALUES (?,?,?,?,?,?,?,?,?,?)",
                    [(*row, int(row[0] in retrans)) for row in data.rows])
    con.execute("""CREATE TABLE http_messages(id INTEGER PRIMARY KEY, ts REAL, resp_ts REAL, latency_ms REAL,
                   src_ip TEXT, device TEXT, method TEXT, path TEXT, status INTEGER, error_code TEXT,
                   request_id TEXT, x_timestamp TEXT, policy TEXT, req_body_bytes INTEGER, resp_body_bytes INTEGER,
                   wire_bytes INTEGER, req_entropy REAL, resp_entropy REAL, stream INTEGER, flag TEXT)""")
    con.executemany(
        "INSERT INTO http_messages(ts, resp_ts, latency_ms, src_ip, device, method, path, status, error_code, request_id,"
        " x_timestamp, policy, req_body_bytes, resp_body_bytes, wire_bytes, req_entropy, resp_entropy, stream, flag)"
        " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        [(r.req_ts, r.resp_ts, r.latency_ms, r.src_ip, r.device, r.method, r.path,
          None if pd.isna(r.status) else int(r.status), r.error_code, r.request_id, r.x_timestamp, r.policy,
          r.req_body_bytes, r.resp_body_bytes, r.wire_bytes, r.req_entropy, r.resp_entropy, r.stream, r.flag)
         for r in df.itertuples()])
    con.execute("CREATE INDEX ix_msg_rid ON http_messages(request_id)")
    con.commit()

    con.execute("ATTACH ? AS app", (str(app_db),))
    joined = pd.read_sql_query(NEAREST_JOIN, con)
    prd = pd.read_sql_query(PRD_JOIN, con)
    con.close()
    return out_db, joined, prd


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pcap", type=Path)
    ap.add_argument("--app-db", type=Path, default=ROOT / "data" / "securemarks.db")
    ap.add_argument("--out", type=Path)
    ap.add_argument("--engine", choices=["auto", "pyshark", "python"], default="auto")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()

    out_db, joined, prd = convert(a.pcap, a.app_db, a.out, a.engine)
    csv_dir = ROOT / "analysis" / "out" / a.pcap.stem
    csv_dir.mkdir(parents=True, exist_ok=True)
    joined.to_csv(csv_dir / "audit_join.csv", index=False)
    if a.json:
        print(json.dumps({"db": str(out_db), "rows": len(joined),
                          "matched": int(joined.audit_id.notna().sum()) if not joined.empty else 0,
                          "csv": str(csv_dir / "audit_join.csv")}))
        return

    with sqlite3.connect(out_db) as con:
        n_pk, n_msg = con.execute("SELECT (SELECT COUNT(*) FROM packets), (SELECT COUNT(*) FROM http_messages)").fetchone()
    console.rule(f"[bold cyan]PCAP → SQLite · {a.pcap.name}")
    console.print(f"wrote {out_db}: {n_pk} packets, {n_msg} http_messages")
    console.print(f"[dim]PRD join returned {len(prd)} rows (a replayed ID matches both its original and its replay audit row)[/]")
    t = Table(title="flags joined to audit_log (nearest audit row by time, same request ID)")
    for col in ("time", "device", "src", "path", "flag", "request_id", "status", "audit #", "action", "outcome", "code"):
        t.add_column(col)
    shown = pd.concat([joined[joined.flag.isin(["replay", "replay_late"])], joined[joined.flag == "flood"].head(10)]) if not joined.empty else joined
    for r in shown.itertuples():
        t.add_row(time.strftime("%H:%M:%S", time.localtime(r.ts)), r.device, r.src_ip, r.path, r.flag,
                  (r.request_id or "")[:13] + "…", str(r.status), "-" if pd.isna(r.audit_id) else str(int(r.audit_id)),
                  r.action or "-", r.outcome or "-", r.code or "-")
    console.print(t)
    if not joined.empty:
        console.print(f"{int(joined.audit_id.notna().sum())}/{len(joined)} flagged messages matched an audit row; "
                      f"full table → {csv_dir / 'audit_join.csv'}")
    else:
        console.print("no replay or flood flags in this capture")


if __name__ == "__main__":
    main()
