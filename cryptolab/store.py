"""Persistence for lab runs: every measurement is kept in data/cryptolab.db so
timings (signature generation / verification included) are stored, not just
shown, and the history can be charted or exported."""
from __future__ import annotations

import csv
import io
import json
import sqlite3
import time
from pathlib import Path

from middleware.settings import load_settings

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    kind TEXT NOT NULL,          -- text, image, hash, signature, kex
    scheme TEXT NOT NULL,        -- algorithm or scheme name
    params TEXT NOT NULL,        -- JSON
    metrics TEXT NOT NULL        -- JSON
);
CREATE INDEX IF NOT EXISTS runs_kind ON runs(kind, ts);
"""


def db_path() -> Path:
    return load_settings().db_path.parent / "cryptolab.db"


def _connect(path: Path | None = None) -> sqlite3.Connection:
    path = path or db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(path, timeout=10)
    con.executescript(SCHEMA)
    return con


def save(kind: str, scheme: str, params: dict, metrics: dict, *, path: Path | None = None) -> int:
    with _connect(path) as con:
        cur = con.execute("INSERT INTO runs (ts, kind, scheme, params, metrics) VALUES (?, ?, ?, ?, ?)",
                          (time.time(), kind, scheme, json.dumps(params, default=str), json.dumps(metrics, default=str)))
        return int(cur.lastrowid)


def history(kind: str | None = None, limit: int = 100, *, path: Path | None = None) -> list[dict]:
    with _connect(path) as con:
        q = "SELECT id, ts, kind, scheme, params, metrics FROM runs"
        args: list = []
        if kind:
            q += " WHERE kind = ?"
            args.append(kind)
        rows = con.execute(q + " ORDER BY id DESC LIMIT ?", (*args, limit)).fetchall()
    return [{"id": r[0], "ts": r[1], "kind": r[2], "scheme": r[3], "params": json.loads(r[4]),
             "metrics": json.loads(r[5])} for r in rows]


def export_csv(kind: str | None = None, *, path: Path | None = None) -> str:
    rows = history(kind, 10_000, path=path)
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["id", "time", "kind", "scheme", "params", "metrics"])
    for r in rows:
        w.writerow([r["id"], time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r["ts"])), r["kind"], r["scheme"],
                    json.dumps(r["params"]), json.dumps(r["metrics"])])
    return buf.getvalue()
