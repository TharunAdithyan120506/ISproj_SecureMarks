"""Availability: result-day flood with a stolen s612 token while s608 keeps
loading marks.

    python -m attacks.flood --seconds 10 --rate 50 --probe

The flood is fully valid traffic (real session, fresh request IDs), so only the
per-user token bucket stops it. The probe measures s608's latency at 1 request
per second: a short baseline, during the flood, then after. Expected: mostly
429 rate_limited for the flood, 200s with near-baseline latency for s608.
"""
from __future__ import annotations

import argparse
import csv
import statistics
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor

from middleware.settings import ROOT

from .common import AttackResult, attacker, device_client, report, with_evidence

NAME, GOAL, EXPECTED = "flood", "Availability", "429 rate_limited"
PROBE_CSV = ROOT / "analysis" / "out" / "flood_probe.csv"


def _pct(values: list[float], q: float) -> float | None:
    if not values:
        return None
    values = sorted(values)
    return values[min(len(values) - 1, int(round(q * (len(values) - 1))))]


def run(seconds: float = 10, rate: float = 50, probe: bool = True, baseline_s: float = 3,
        on_progress=None) -> AttackResult:
    flood_client = attacker(stolen_login="s612")
    flood_client.open_session("confidential")
    probe_rows: list[dict] = []
    stop = threading.Event()
    phase = {"name": "baseline"}

    def probe_loop():
        s608 = device_client("student", "s608")
        s608.open_session("confidential")
        while not stop.is_set():
            t0 = time.time()
            r = s608.view_marks()
            probe_rows.append({"ts": t0, "phase": phase["name"], "status": r.status, "code": r.code,
                               "latency_ms": round(r.elapsed_ms, 2), "request_id": r.request_id})
            stop.wait(max(0.0, 1.0 - (time.time() - t0)))

    prober = threading.Thread(target=probe_loop, daemon=True) if probe else None
    if prober:
        prober.start()
        time.sleep(baseline_s)

    phase["name"] = "flood"
    results = []
    lock = threading.Lock()

    def fire():
        r = flood_client.call("/api/marks/view", {"roll_no": "240911612"})
        with lock:
            results.append(r)

    total = int(seconds * rate)
    start = time.time()
    with ThreadPoolExecutor(max_workers=16) as pool:
        for i in range(total):
            time.sleep(max(0.0, start + i / rate - time.time()))
            pool.submit(fire)
            if on_progress and i % int(rate) == 0:
                on_progress(i / total)
    flood_time = time.time() - start

    if prober:
        phase["name"] = "after"
        time.sleep(2)
        stop.set()
        prober.join(timeout=5)

    codes = Counter(r.code for r in results)
    limited = [r for r in results if r.status == 429]
    sample = limited[0] if limited else results[-1]
    res = AttackResult(NAME, GOAL, EXPECTED, sample.status, sample.code, sample.request_id, sample.trace_id,
                       sample.detail or "")
    res.notes.append(f"flood: {len(results)} valid encrypted requests in {flood_time:.1f} s from 127.0.0.66 "
                     f"with s612's stolen token → " + ", ".join(f"{k} x{v}" for k, v in codes.most_common()))
    res.extra.update(flood_codes=dict(codes), flood_requests=len(results),
                     flood_request_ids=[r.request_id for r in results])

    if probe_rows:
        PROBE_CSV.parent.mkdir(parents=True, exist_ok=True)
        with open(PROBE_CSV, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=list(probe_rows[0]))
            w.writeheader()
            w.writerows(probe_rows)
        by_phase = {p: [r["latency_ms"] for r in probe_rows if r["phase"] == p and r["status"] == 200]
                    for p in ("baseline", "flood", "after")}
        ok = sum(1 for r in probe_rows if r["status"] == 200)
        res.notes.append(f"s608 probe: {ok}/{len(probe_rows)} requests got 200")
        for p, vals in by_phase.items():
            if vals:
                res.notes.append(f"  {p:<8} p50 {statistics.median(vals):6.1f} ms   p95 {_pct(vals, .95):6.1f} ms   (n={len(vals)})")
        res.extra.update(probe=probe_rows, probe_csv=str(PROBE_CSV),
                         probe_p50={p: statistics.median(v) for p, v in by_phase.items() if v})
    return with_evidence(res)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--seconds", type=float, default=10)
    ap.add_argument("--rate", type=float, default=50)
    ap.add_argument("--probe", action="store_true", help="run s608 at 1 request/s and log latency")
    a = ap.parse_args()
    report(run(a.seconds, a.rate, a.probe))


if __name__ == "__main__":
    main()
