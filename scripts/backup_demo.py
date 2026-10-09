"""Copy the rehearsal's evidence into demo_backup\\<timestamp>\\ (PRD section 14).

    python scripts\\backup_demo.py

Captures, analyser outputs, benchmark outputs, the audit database (a
consistent SQLite backup, safe while the server runs) and capture databases.
Add your inspector screenshots to the same folder by hand.
"""
from __future__ import annotations

import shutil
import sqlite3
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    dest = ROOT / "demo_backup" / time.strftime("%Y%m%d-%H%M%S")
    dest.mkdir(parents=True)
    copied = 0
    for src, sub in ((ROOT / "captures", "captures"), (ROOT / "analysis" / "out", "analysis_out"),
                     (ROOT / "bench" / "out", "bench_out")):
        if src.exists():
            shutil.copytree(src, dest / sub, ignore=shutil.ignore_patterns(".*", "attacker_loot.json"))
            copied += sum(1 for p in (dest / sub).rglob("*") if p.is_file())
    data = ROOT / "data"
    (dest / "data").mkdir()
    for db in data.glob("*.db"):
        with sqlite3.connect(db) as src, sqlite3.connect(dest / "data" / db.name) as out:
            src.backup(out)
        copied += 1
    (dest / "screenshots").mkdir()
    print(f"backed up {copied} files → {dest}")


if __name__ == "__main__":
    sys.exit(main())
