"""The five capture experiments of PRD section 9, scripted end to end.

    python -m analysis.experiments exp1          # or exp2, exp2_tls, exp3, exp4, exp5, all
    python -m analysis.experiments exp3 --no-analyse

Each run: start the capture -> drive the traffic through the SDK and the attack
scripts (real devices, real loopback IPs) -> stop -> `analysis.analyze` and,
for the replay and flood experiments, `analysis.pcap_to_sqlite`, each in its own
process.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from analysis import capture  # noqa: E402
from attacks.common import accounts, attacker, device_client, teacher_key  # noqa: E402
from middleware.crypto.canonical import build_record  # noqa: E402
from middleware.settings import load_settings  # noqa: E402
from sdk.client import SecureClient  # noqa: E402

ROLL, FRIEND = "240911608", "240911612"
PACE_S = 0.35  # human-ish pacing, so scripted steps stay under the 5 req/s flood flag


def pause() -> None:
    time.sleep(PACE_S)


def class_sheet(n_bytes: int) -> list[dict]:
    """A synthetic class marks sheet of roughly n_bytes of JSON (for the payload sweep)."""
    rows, size, i = [], 2, 0
    while size < n_bytes:
        mid, end = (i * 7) % 51, (i * 13) % 101
        row = {"roll_no": str(240911000 + i), "midsem": mid, "endsem": end, "total": mid + end}
        size += len(json.dumps(row)) + 1
        rows.append(row)
        i += 1
    return rows


def exp1(log) -> None:
    t = device_client("teacher", "t104")
    record = build_record("IT301", ROLL, 27, 45, "t104")
    log(f"plain publish: {t.plain_publish(record).summary()}")
    pause()
    log(f"protected publish: {t.publish_marks(teacher_key(), 'IT301', ROLL, 27, 45).summary()}")
    pause()
    s = device_client("student", "s608")
    log(f"plain view: {s.plain_view(ROLL).summary()}")
    pause()
    log(f"protected view: {s.view_marks().summary()}")
    pause()
    for kb in (1, 4, 10, 100):
        sheet = class_sheet(kb * 1024)
        plain = t.plain_echo(sheet)
        pause()
        log(f"payload sweep {kb:>3} KB: plain {plain.summary()} · protected {t.demo_echo(sheet).summary()}")
        pause()


def exp2(log, tls: bool = False) -> None:
    s = load_settings()
    base = s.tls_url if tls else s.server_url
    t = SecureClient.for_role("teacher", base_url=base)
    if t.health() is None:
        raise RuntimeError(f"no server at {base}" + (" - start the TLS server: python scripts\\run_demo.py --tls" if tls else ""))
    log(f"login over {'HTTPS' if tls else 'HTTP'}: {t.login('t104', accounts()['t104']['password']).summary()}")
    log(f"publish: {t.publish_marks(teacher_key(), 'IT301', ROLL, 27, 45).summary()}")
    st = SecureClient.for_role("student", base_url=base)
    st.login("s608", accounts()["s608"]["password"])
    log(f"student view: {st.view_marks().summary()}")


def exp3(log, delay: float = 35) -> None:
    from attacks import replay
    t = SecureClient.for_role("teacher")
    t.login("t104", accounts()["t104"]["password"])
    pub = t.publish_marks(teacher_key(), "IT301", ROLL, 27, 45)
    log(f"teacher publish: {pub.summary()} (request {pub.request_id[:8]}…)")
    r1 = replay.run("last")
    log(f"attacker replay at once: {r1.actual} (expected {r1.expected})")
    r2 = replay.run("last", delay=delay, on_wait=lambda left: None)
    log(f"attacker replay after {delay:.0f} s: {r2.actual} (expected {r2.expected})")


def exp4(log) -> None:
    from attacks import flood
    r = flood.run(seconds=10, rate=50, probe=True, baseline_s=3)
    for note in r.notes:
        log(note)


def exp5(log) -> None:
    from attacks import idor
    t = device_client("teacher", "t104")
    pub = t.publish_marks(teacher_key(), "IT301", ROLL, 27, 45)
    log(f"teacher-laptop 127.0.0.2 publish: {pub.summary()}")
    pause()
    s = device_client("student", "s608")
    log(f"student-laptop 127.0.0.3 own marks: {s.view_marks().summary()}")
    pause()
    log(f"student-laptop 127.0.0.3 friend's roll: {s.view_marks(FRIEND).summary()}")
    pause()
    c = device_client("ctrl", "ctrl")
    if pub.ok:
        log(f"ctrl-pc 127.0.0.4 verify record {pub.payload['record_id']}: {c.verify_record(pub.payload['record_id']).summary()}")
    log(f"ctrl-pc 127.0.0.4 audit list: {c.audit_list(limit=10).summary()}")
    a = device_client("admin", "admin")
    log(f"admin-pc 127.0.0.5 keys list: {a.keys_list().summary()}")
    log(f"attacker 127.0.0.66 IDOR: {idor.run().actual}")


EXPERIMENTS = {
    "exp1": ("exp1_plain_vs_protected", "Plain vs protected", exp1, False),
    "exp2": ("exp2_http", "HTTP: password, JWT and headers visible", lambda log: exp2(log, False), False),
    "exp2_tls": ("exp2_tls", "TLS (P1): only sizes and timing visible", lambda log: exp2(log, True), False),
    "exp3": ("exp3_replay", "Replay at once and after 35 s", exp3, True),
    "exp4": ("exp4_flood", "Result-day flood with a latency probe", exp4, True),
    "exp5": ("exp5_devices", "Five devices, one of each role", exp5, False),
}


def _py(*args: str) -> subprocess.CompletedProcess:
    env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUTF8="1")
    return subprocess.run([sys.executable, "-m", *args], cwd=ROOT, capture_output=True, text=True,
                          encoding="utf-8", errors="replace", env=env)


def analyse(pcap: str, join: bool) -> dict:
    db = str(load_settings().db_path)
    out = _py("analysis.analyze", pcap, "--audit", db, "--json")
    summary = json.loads(out.stdout.strip().splitlines()[-1]) if out.returncode == 0 and out.stdout.strip() else {
        "error": out.stderr[-800:]}
    if join:
        j = _py("analysis.pcap_to_sqlite", pcap, "--app-db", db, "--json")
        summary["sql_join"] = json.loads(j.stdout.strip().splitlines()[-1]) if j.returncode == 0 and j.stdout.strip() else {
            "error": j.stderr[-800:]}
    return summary


def run(key: str, do_capture: bool = True, do_analyse: bool = True, mode: str = "auto", log=print) -> dict:
    name, title, fn, join = EXPERIMENTS[key]
    log(f"── {name}: {title}")
    started = None
    if do_capture:
        started = capture.start(name, mode=mode)
        log(f"capture started ({started['mode']}) → {started['path']}")
    try:
        fn(log)
    finally:
        if started:
            time.sleep(1.0)
            r = capture.stop()
            log(f"capture stopped: {r['packets']} packets, {r['bytes']:,} bytes")
    result = {"experiment": name, "title": title}
    if started and do_analyse:
        log("analysing (separate process)…")
        result["analysis"] = analyse(started["path"], join)
        a = result["analysis"]
        if "error" in a:
            log(f"analysis failed: {a['error']}")
        else:
            log(f"{a['http_requests']} HTTP requests, devices {a['devices']}, statuses {a['status_counts']}, "
                f"entropy {a['entropy_mean']}, flags {a['flags']} ({a['flags_matched_in_audit']} matched in audit)")
            if "sql_join" in a and "rows" in a["sql_join"]:
                log(f"PCAP → SQLite join: {a['sql_join']['matched']}/{a['sql_join']['rows']} flagged messages matched "
                    f"→ {a['sql_join']['csv']}")
    return result


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("experiment", choices=list(EXPERIMENTS) + ["all"])
    ap.add_argument("--no-capture", action="store_true", help="only generate the traffic")
    ap.add_argument("--no-analyse", action="store_true")
    ap.add_argument("--mode", choices=["auto", "dumpcap", "tap"], default="auto")
    a = ap.parse_args()
    keys = ["exp1", "exp2", "exp3", "exp4", "exp5"] if a.experiment == "all" else [a.experiment]
    for k in keys:
        try:
            run(k, not a.no_capture, not a.no_analyse, a.mode, log=lambda m: print(m, flush=True))
        except RuntimeError as exc:
            print(f"error: {exc}", file=sys.stderr, flush=True)
            if a.experiment != "all":
                sys.exit(1)


if __name__ == "__main__":
    main()
