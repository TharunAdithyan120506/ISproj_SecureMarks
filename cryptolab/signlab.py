"""Digital signatures: generation and verification time, sizes, tamper check.

The message is hashed with SHA-256 first and the digest is signed, exactly as
the marks records are (sign-the-hash; Lab 6 additional exercise: integrity
from SHA, authenticity and non-repudiation from the signature).
"""
from __future__ import annotations

import hashlib
import statistics
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .perf import median_ms, timings_ms

_PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)


def _rsa(bits):
    return {
        "keygen": lambda: rsa.generate_private_key(65537, bits),
        "sign": lambda k, d: k.sign(d, _PSS, hashes.SHA256()),
        "verify": lambda k, s, d: k.public_key().verify(s, d, _PSS, hashes.SHA256()),
        "public": lambda k: k.public_key().public_bytes(serialization.Encoding.DER,
                                                        serialization.PublicFormat.SubjectPublicKeyInfo),
        "security_bits": 112 if bits == 2048 else 128, "family": "RSA (integer factorisation)",
    }


ALGORITHMS: dict[str, dict] = {
    "Ed25519": {
        "keygen": Ed25519PrivateKey.generate,
        "sign": lambda k, d: k.sign(d),
        "verify": lambda k, s, d: k.public_key().verify(s, d),
        "public": lambda k: k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw),
        "security_bits": 128, "family": "EdDSA on Curve25519 (used by SecureMarks)",
    },
    "ECDSA-P256": {
        "keygen": lambda: ec.generate_private_key(ec.SECP256R1()),
        "sign": lambda k, d: k.sign(d, ec.ECDSA(hashes.SHA256())),
        "verify": lambda k, s, d: k.public_key().verify(s, d, ec.ECDSA(hashes.SHA256())),
        "public": lambda k: k.public_key().public_bytes(serialization.Encoding.X962,
                                                        serialization.PublicFormat.UncompressedPoint),
        "security_bits": 128, "family": "ECDSA on NIST P-256 (secp256r1)",
    },
    "RSA-PSS-2048": _rsa(2048),
    "RSA-PSS-3072": _rsa(3072),
}
NAMES = list(ALGORITHMS)


def sign_once(alg: str, message: str, *, tampered: str | None = None, key=None) -> dict:
    """Generate a key, sign SHA-256(message), verify (and verify a tampered copy). All timed."""
    a = ALGORITHMS[alg]
    t0 = time.perf_counter()
    key = key or a["keygen"]()
    keygen_ms = (time.perf_counter() - t0) * 1000
    digest = hashlib.sha256(message.encode()).digest()
    t0 = time.perf_counter()
    sig = a["sign"](key, digest)
    sign_ms = (time.perf_counter() - t0) * 1000
    t0 = time.perf_counter()
    try:
        a["verify"](key, sig, digest)
        valid = True
    except InvalidSignature:
        valid = False
    verify_ms = (time.perf_counter() - t0) * 1000
    out = {
        "algorithm": alg, "family": a["family"], "security_bits": a["security_bits"],
        "message": message, "sha256": digest.hex(), "signature_hex": sig.hex(), "signature_bytes": len(sig),
        "public_key_hex": a["public"](key).hex(), "public_key_bytes": len(a["public"](key)),
        "keygen_ms": round(keygen_ms, 4), "sign_ms": round(sign_ms, 4), "verify_ms": round(verify_ms, 4),
        "valid": valid,
    }
    if tampered is not None:
        d2 = hashlib.sha256(tampered.encode()).digest()
        try:
            a["verify"](key, sig, d2)
            out["tampered_valid"] = True
        except InvalidSignature:
            out["tampered_valid"] = False
        out["tampered_message"] = tampered
    return out


def benchmark(alg: str, runs: int = 100, keygen_runs: int | None = None) -> dict:
    """Distribution of keygen / sign / verify times over many runs."""
    a = ALGORITHMS[alg]
    keygen_runs = keygen_runs or (5 if "3072" in alg else 10 if "RSA" in alg else 50)
    digest = hashlib.sha256(b"IT301|240911608|27|45").digest()
    keygen = timings_ms(a["keygen"], keygen_runs, warmup=1)
    key = a["keygen"]()
    sig = a["sign"](key, digest)
    sign = timings_ms(lambda: a["sign"](key, digest), runs)
    verify = timings_ms(lambda: a["verify"](key, sig, digest), runs)

    def summ(xs):
        return {"median": round(statistics.median(xs), 5), "mean": round(statistics.fmean(xs), 5),
                "p95": round(sorted(xs)[int(len(xs) * 0.95) - 1 if len(xs) > 1 else 0], 5),
                "min": round(min(xs), 5), "max": round(max(xs), 5)}

    return {"algorithm": alg, "family": a["family"], "security_bits": a["security_bits"], "runs": runs,
            "keygen_ms": summ(keygen), "sign_ms": summ(sign), "verify_ms": summ(verify),
            "sign_samples": [round(x, 5) for x in sign], "verify_samples": [round(x, 5) for x in verify],
            "public_key_bytes": len(a["public"](key)), "signature_bytes": len(sig),
            "signs_per_second": round(1000 / statistics.median(sign)),
            "verifies_per_second": round(1000 / statistics.median(verify))}


def compare(runs: int = 100) -> list[dict]:
    rows = []
    for alg in NAMES:
        b = benchmark(alg, runs)
        rows.append({k: v for k, v in b.items() if not k.endswith("_samples")})
    return rows


__all__ = ["ALGORITHMS", "NAMES", "sign_once", "benchmark", "compare", "median_ms"]
