"""Authentication + availability: 20 wrong passwords for t104 in 5 seconds.

    python -m attacks.bad_login [--tries 20 --seconds 5]

Expected: 401 auth_failed at first, then 429 rate_limited (the login bucket is
keyed on the source IP because there is no token yet).
"""
from __future__ import annotations

import argparse
import time
from collections import Counter

from .common import AttackResult, attacker, report, with_evidence

NAME, GOAL, EXPECTED = "bad_login", "Authentication, availability", "429 rate_limited"


def run(tries: int = 20, seconds: float = 5.0, username: str = "t104") -> AttackResult:
    c = attacker()
    results = []
    start = time.time()
    for i in range(tries):
        target = start + i * seconds / tries
        time.sleep(max(0.0, target - time.time()))
        results.append(c.login(username, f"guess-{i:02d}"))
    codes = Counter(r.code for r in results)
    last = results[-1]
    first_429 = next((i for i, r in enumerate(results) if r.status == 429), None)
    res = AttackResult(NAME, GOAL, EXPECTED, last.status, last.code, last.request_id, last.trace_id, last.detail or "")
    res.notes.append(f"{tries} attempts in {time.time() - start:.1f} s: " + ", ".join(f"{k} x{v}" for k, v in codes.items()))
    if first_429 is not None:
        res.notes.append(f"first 429 at attempt {first_429 + 1}; Argon2id makes each guess cost ~50 ms server-side too")
    res.extra["sequence"] = [r.status for r in results]
    res.extra["request_ids"] = [r.request_id for r in results]
    return with_evidence(res)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--tries", type=int, default=20)
    ap.add_argument("--seconds", type=float, default=5.0)
    a = ap.parse_args()
    report(run(a.tries, a.seconds))


if __name__ == "__main__":
    main()
