"""Efficiency analysis: every algorithm across payload sizes, plus the
middleware's per-check costs and end-to-end latency.

    python -m bench.bench --quick      # P0, about a minute
    python -m bench.bench --full       # adds 50 MB, RSA-3072, ECDSA P-256, 200 round trips

time.perf_counter(), warm-up runs, medians. Outputs bench/out/results.csv,
results.json and sym_throughput.png, sig_compare.png, kex_compare.png,
e2e_latency.png, checks_cost.png.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import platform
import statistics
import sys
import tempfile
import time
import warnings
from pathlib import Path

# Finite-field DH is deprecated in `cryptography`; it is benchmarked here only as the
# classic baseline the synopsis compares X25519 against.
warnings.filterwarnings("ignore", message="Diffie-Hellman over finite fields")

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import dh, ec, padding, rsa  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: E402
from cryptography.hazmat.primitives.kdf.hkdf import HKDF  # noqa: E402
from rich.console import Console  # noqa: E402
from rich.table import Table  # noqa: E402

from analysis import plots  # noqa: E402

OUT = ROOT / "bench" / "out"
console = Console(highlight=False, width=None if sys.stdout.isatty() else 140)
KB, MB = 1024, 1024 * 1024

# RFC 3526 group 14 (2048-bit MODP), so DH needs no slow parameter generation.
RFC3526_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)

rows: list[dict] = []


def record(group: str, name: str, metric: str, value: float, unit: str, size: int | None = None, runs: int = 0,
           note: str = "") -> None:
    rows.append({"group": group, "name": name, "metric": metric, "value": round(value, 6), "unit": unit,
                 "size_bytes": size or "", "runs": runs, "note": note})


from cryptolab.perf import median_ms, runs_for  # noqa: E402  (shared with the crypto labs)


# --- groups ------------------------------------------------------------------------------------

def bench_symmetric(sizes: list[int]) -> None:
    for key_len, name in ((16, "AES-128-GCM"), (32, "AES-256-GCM")):
        aes = AESGCM(os.urandom(key_len))
        for size in sizes:
            data, nonce, n = os.urandom(size), os.urandom(12), runs_for(size)
            ct = aes.encrypt(nonce, data, b"aad")
            enc = median_ms(lambda: aes.encrypt(nonce, data, b"aad"), n)
            dec = median_ms(lambda: aes.decrypt(nonce, ct, b"aad"), n)
            for op, ms in (("encrypt", enc), ("decrypt", dec)):
                record("symmetric", name, f"{op}_ms", ms, "ms", size, n)
                record("symmetric", name, f"{op}_MBps", size / MB / (ms / 1000), "MB/s", size, n)
    for size in sizes:
        data, n = os.urandom(size), runs_for(size)
        ms = median_ms(lambda: hashlib.sha256(data).digest(), n)
        record("hash", "SHA-256", "hash_ms", ms, "ms", size, n)
        record("hash", "SHA-256", "hash_MBps", size / MB / (ms / 1000), "MB/s", size, n)


def bench_signatures(full: bool, sign_runs: int = 200, keygen_runs: int = 20) -> None:
    digest = hashlib.sha256(b"canonical marks record").digest()
    pss = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)
    algs = {
        "Ed25519": (Ed25519PrivateKey.generate, lambda k: k.sign(digest), lambda k, s: k.public_key().verify(s, digest),
                    lambda k: k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)),
        "RSA-PSS-2048": (lambda: rsa.generate_private_key(65537, 2048), lambda k: k.sign(digest, pss, hashes.SHA256()),
                         lambda k, s: k.public_key().verify(s, digest, pss, hashes.SHA256()),
                         lambda k: k.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)),
    }
    if full:
        algs["RSA-PSS-3072"] = (lambda: rsa.generate_private_key(65537, 3072), algs["RSA-PSS-2048"][1],
                                algs["RSA-PSS-2048"][2], algs["RSA-PSS-2048"][3])
        algs["ECDSA-P256"] = (lambda: ec.generate_private_key(ec.SECP256R1()),
                              lambda k: k.sign(digest, ec.ECDSA(hashes.SHA256())),
                              lambda k, s: k.public_key().verify(s, digest, ec.ECDSA(hashes.SHA256())),
                              lambda k: k.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint))
    for name, (gen, sign, verify, pub) in algs.items():
        kg = median_ms(gen, keygen_runs if "3072" not in name else max(5, keygen_runs // 4), warmup=1)
        key = gen()
        sig = sign(key)
        record("signature", name, "keygen_ms", kg, "ms", runs=keygen_runs)
        record("signature", name, "sign_ms", median_ms(lambda: sign(key), sign_runs), "ms", runs=sign_runs)
        record("signature", name, "verify_ms", median_ms(lambda: verify(key, sig), sign_runs), "ms", runs=sign_runs)
        record("signature", name, "public_key_bytes", len(pub(key)), "B")
        record("signature", name, "signature_bytes", len(sig), "B")


def bench_kex(runs: int = 200) -> None:
    salt = os.urandom(16)

    def hkdf(secret: bytes) -> bytes:
        return HKDF(hashes.SHA256(), 32, salt, b"securemarks/v1/session").derive(secret)

    def x25519():
        a, b = X25519PrivateKey.generate(), X25519PrivateKey.generate()
        assert hkdf(a.exchange(b.public_key())) == hkdf(b.exchange(a.public_key()))

    def p256():
        a, b = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
        hkdf(a.exchange(ec.ECDH(), b.public_key()))
        hkdf(b.exchange(ec.ECDH(), a.public_key()))

    server_rsa = rsa.generate_private_key(65537, 2048)
    oaep = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)

    def rsa_oaep():
        secret = os.urandom(32)
        wrapped = server_rsa.public_key().encrypt(secret, oaep)
        hkdf(server_rsa.decrypt(wrapped, oaep))

    params = dh.DHParameterNumbers(RFC3526_P, 2).parameters()

    def dh2048():
        a, b = params.generate_private_key(), params.generate_private_key()
        hkdf(a.exchange(b.public_key()))
        hkdf(b.exchange(a.public_key()))

    wire = {"X25519": 32 + 32, "ECDH-P256": 65 + 65, "RSA-OAEP-2048": 256, "DH-2048 (RFC 3526)": 256 + 256}
    for name, fn in (("X25519", x25519), ("ECDH-P256", p256), ("RSA-OAEP-2048", rsa_oaep), ("DH-2048 (RFC 3526)", dh2048)):
        n = runs if "DH" not in name else max(20, runs // 4)
        record("key_exchange", name, "handshake_ms", median_ms(fn, n), "ms", runs=n,
               note="both sides incl. ephemeral keygen + HKDF" if name != "RSA-OAEP-2048" else "wrap + unwrap + HKDF, static server key")
        record("key_exchange", name, "public_bytes_on_wire", wire[name], "B")


def bench_passwords(runs: int = 20) -> None:
    from argon2 import PasswordHasher
    ph = PasswordHasher()
    h = ph.hash("teach@104")
    record("passwords", "Argon2id", "hash_ms", median_ms(lambda: ph.hash("teach@104"), runs, 1), "ms", runs=runs,
           note=f"t={ph.time_cost} m={ph.memory_cost} KiB p={ph.parallelism}")
    record("passwords", "Argon2id", "verify_ms", median_ms(lambda: ph.verify(h, "teach@104"), runs, 1), "ms", runs=runs)


def bench_checks(runs: int = 2000) -> None:
    """The middleware's own per-request costs (efficiency metrics of the goal matrix)."""
    import secrets
    import uuid

    from middleware.audit import AuditLogWriter
    from middleware.auth import tokens
    from middleware.auth.rbac import Principal, require_course, require_own_roll
    from middleware.db.session import Database
    from middleware.guards.ratelimit import RateLimiter
    from middleware.guards.replay import ReplayStore

    store = ReplayStore()
    for _ in range(10_000):
        store.add(str(uuid.uuid4()), 60)
    probe = str(uuid.uuid4())
    record("checks", "replay seen-set lookup", "us", median_ms(lambda: store.seen(probe), runs) * 1000, "µs",
           runs=runs, note="10,000 IDs in the set")
    limiter = RateLimiter()
    record("checks", "token bucket take", "us", median_ms(lambda: limiter.take("user:x", 1e9, 1e9), runs) * 1000, "µs", runs=runs)
    p = Principal("s608", "student", "240911608", ())
    t = Principal("t104", "teacher", None, ("IT301",))
    record("checks", "RBAC role + ownership", "us",
           median_ms(lambda: (require_own_roll(p, "240911608"), require_course(t, "IT301")), runs) * 1000, "µs", runs=runs)
    secret = secrets.token_hex(32)
    tok = tokens.issue(secret, username="s608", role="student", roll_no="240911608", courses=[], ttl_s=900)
    record("checks", "JWT HS256 verify", "us", median_ms(lambda: tokens.verify(secret, tok), runs) * 1000, "µs", runs=runs)
    with tempfile.TemporaryDirectory() as tmp:
        db = Database(Path(tmp) / "bench.db")
        db.create_all()
        audit = AuditLogWriter(db)
        ms = median_ms(lambda: audit.record(request_id=str(uuid.uuid4()), action="bench", outcome="allowed", code="ok",
                                            actor="bench", detail="audit write cost"), 200, 5)
        record("checks", "audit write (hash-chained, WAL)", "us", ms * 1000, "µs", runs=200)
        db.dispose()


def bench_e2e(n: int) -> dict | None:
    from attacks.common import device_client, teacher_key
    from middleware.crypto.canonical import build_record

    t = device_client("teacher", "t104")
    if t.health() is None:
        console.print("[yellow]server not reachable: skipping end-to-end round trips[/]")
        return None
    s = device_client("student", "s608")
    key = teacher_key()
    results = {k: [] for k in ("protected publish", "protected view", "plain publish", "plain view")}
    wire = {}

    def timed(label, fn):
        for _ in range(40):
            r = fn()
            if r.status == 429:
                time.sleep(0.5)
                continue
            if r.ok:
                results[label].append(r.elapsed_ms)
                wire.setdefault(label, []).append(r.extra.get("request_bytes", 0) + r.extra.get("response_bytes", 0))
            return

    for i in range(n):
        timed("protected publish", lambda: t.publish_marks(key, "IT301", "240911608", 27, 45))
        timed("protected view", lambda: s.view_marks())
        record_ = build_record("IT301", "240911608", 27, 45, "t104")
        timed("plain publish", lambda: t.plain_publish(record_))
        timed("plain view", lambda: s.plain_view("240911608"))
        if i % 10 == 0:
            console.print(f"  round trips {i}/{n}", end="\r")
    out = {}
    for label, vals in results.items():
        if not vals:
            continue
        vals = sorted(vals)
        p50, p95 = statistics.median(vals), vals[min(len(vals) - 1, int(round(0.95 * (len(vals) - 1))))]
        out[label] = (p50, p95)
        record("end_to_end", label, "p50_ms", p50, "ms", runs=len(vals))
        record("end_to_end", label, "p95_ms", p95, "ms", runs=len(vals))
        if wire.get(label) and any(wire[label]):
            record("end_to_end", label, "body_bytes", statistics.median(wire[label]), "B", runs=len(vals),
                   note="request + response body (SDK view)")
    exp1 = ROOT / "analysis" / "out" / "exp1_plain_vs_protected" / "messages.csv"
    if exp1.exists():
        import pandas as pd
        df = pd.read_csv(exp1)
        for path, g in df.groupby("path"):
            record("wire", path, "bytes_on_wire_per_call", g.wire_bytes.mean(), "B", runs=len(g),
                   note="from the exp1 capture (frames incl. IP/TCP/HTTP headers)")
    return out


# --- graphs -------------------------------------------------------------------------------------

def _get(group, name, metric, size=None):
    for r in rows:
        if r["group"] == group and r["name"] == name and r["metric"] == metric and (size is None or r["size_bytes"] == size):
            return r["value"]
    return float("nan")


def _label(size: int) -> str:
    return f"{size // MB} MB" if size >= MB else f"{size // KB} KB"


def draw(sizes: list[int], e2e: dict | None, full: bool) -> list[Path]:
    out = []
    labels = [_label(s) for s in sizes]
    out.append(plots.bench_lines(labels, {
        "AES-128-GCM encrypt": [_get("symmetric", "AES-128-GCM", "encrypt_MBps", s) for s in sizes],
        "AES-256-GCM encrypt": [_get("symmetric", "AES-256-GCM", "encrypt_MBps", s) for s in sizes],
        "SHA-256": [_get("hash", "SHA-256", "hash_MBps", s) for s in sizes],
    }, OUT / "sym_throughput.png", "Throughput by payload size", "MB/s (median)",
        note=f"CPU: {platform.processor() or platform.machine()} · AES-GCM via OpenSSL (cryptography)"))

    sig_algs = ["Ed25519", "RSA-PSS-2048"] + (["RSA-PSS-3072", "ECDSA-P256"] if full else [])
    sizes_note = " · ".join(f"{a}: pub {int(_get('signature', a, 'public_key_bytes'))} B, sig {int(_get('signature', a, 'signature_bytes'))} B"
                            for a in sig_algs)
    out.append(plots.bench_bars(["keygen", "sign", "verify"], {
        a: [_get("signature", a, m) for m in ("keygen_ms", "sign_ms", "verify_ms")] for a in sig_algs
    }, OUT / "sig_compare.png", "Signatures: Ed25519 vs RSA-PSS (median ms, log scale)", "ms", log=True, note=sizes_note))

    kex = ["X25519", "ECDH-P256", "RSA-OAEP-2048", "DH-2048 (RFC 3526)"]
    out.append(plots.bench_bars(kex, {"handshake": [_get("key_exchange", k, "handshake_ms") for k in kex]},
                                OUT / "kex_compare.png", "Session key agreement (median ms per handshake)", "ms",
                                note="X25519/ECDH/DH: both ephemeral keypairs + exchange + HKDF; RSA-OAEP: wrap + unwrap + HKDF"))

    checks = [r for r in rows if r["group"] == "checks"]
    out.append(plots.bench_bars([r["name"].replace(" (hash-chained, WAL)", "") for r in checks],
                                {"cost": [r["value"] for r in checks]}, OUT / "checks_cost.png",
                                "Middleware check cost per request (median µs)", "µs", log=True, fmt="{:.1f}"))
    if e2e:
        labels = list(e2e)
        out.append(plots.bench_bars(labels, {"p50": [e2e[k][0] for k in labels], "p95": [e2e[k][1] for k in labels]},
                                    OUT / "e2e_latency.png", "End-to-end latency through the SDK (ms)", "ms",
                                    note="Protected = X25519 session, AES-GCM both ways, Ed25519 sign/verify, all ten checks; "
                                         "plain = /plain/* JSON"))
    return out


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--quick", action="store_true", help="P0 sizes, ~1 minute (default)")
    mode.add_argument("--full", action="store_true", help="adds 50 MB, RSA-3072, ECDSA P-256, 200 round trips")
    ap.add_argument("--no-e2e", action="store_true", help="skip the round trips through the running server")
    a = ap.parse_args()

    t0 = time.time()
    sizes = [KB, 10 * KB, 100 * KB, MB, 10 * MB] + ([50 * MB] if a.full else [])
    cpu = platform.processor() or platform.machine()
    console.rule(f"[bold cyan]SecureMarks benchmark ({'full' if a.full else 'quick'})")
    console.print(f"CPU {cpu} · Python {platform.python_version()} · {platform.platform()}")
    steps = [("symmetric + hash", lambda: bench_symmetric(sizes)), ("signatures", lambda: bench_signatures(a.full)),
             ("key exchange", bench_kex), ("passwords", bench_passwords), ("middleware checks", bench_checks)]
    for label, fn in steps:
        s = time.time()
        fn()
        console.print(f"[green]✓[/] {label} ({time.time() - s:.1f} s)")
    e2e = None
    if not a.no_e2e:
        s = time.time()
        e2e = bench_e2e(200 if a.full else 50)
        console.print(f"[green]✓[/] end to end ({time.time() - s:.1f} s)" if e2e else "[yellow]• end to end skipped[/]")

    OUT.mkdir(parents=True, exist_ok=True)
    with open(OUT / "results.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    graphs = draw(sizes, e2e, a.full)
    (OUT / "results.json").write_text(json.dumps({"cpu": cpu, "python": platform.python_version(),
                                                  "mode": "full" if a.full else "quick", "seconds": round(time.time() - t0, 1),
                                                  "rows": rows, "graphs": [str(g.relative_to(ROOT)) for g in graphs]},
                                                 indent=1), encoding="utf-8")

    t = Table(title="headline numbers")
    for col in ("group", "name", "metric", "value"):
        t.add_column(col)
    for r in rows:
        if r["group"] in ("signature", "key_exchange", "passwords", "checks", "end_to_end") or (
                r["metric"].endswith("MBps") and r["size_bytes"] == MB):
            size = f" @ {_label(r['size_bytes'])}" if r["size_bytes"] else ""
            t.add_row(r["group"], r["name"], r["metric"] + size, f"{r['value']:.4g} {r['unit']}")
    console.print(t)
    console.print(f"done in {time.time() - t0:.1f} s → {OUT / 'results.csv'} and {len(graphs)} graphs")


if __name__ == "__main__":
    main()
