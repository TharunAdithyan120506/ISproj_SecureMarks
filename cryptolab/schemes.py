"""Encryption schemes compared in the labs, behind one interface.

    env = encrypt("AES-256-GCM-SIV", key, data)          # fresh random nonce
    env = encrypt("AES-256-GCM-SIV", key, data, nonce=n)  # fixed nonce (metrics only)
    data == decrypt(env, key)

| scheme            | kind                         | nonce | tag  | padding |
|-------------------|------------------------------|-------|------|---------|
| AES-256-GCM-SIV   | AEAD, nonce-misuse resistant | 12 B  | 16 B | no      |
| AES-256-GCM       | AEAD (CTR + GHASH)           | 12 B  | 16 B | no      |
| AES-256-CTR       | stream mode                  | 16 B  | -    | no      |
| AES-256-CBC       | block chaining               | 16 B  | -    | PKCS7   |
| AES-256-ECB       | codebook (insecure)          | -     | -    | PKCS7   |
| Logistic-map      | chaotic permutation-diffusion| 16 B  | -    | no      |

Every AES call goes through the `cryptography` library. GCM-SIV (RFC 8452) is
the primary lab scheme: its synthetic IV is computed from the whole plaintext,
so changing one bit or one pixel re-randomises the entire ciphertext, which is
what NPCR, UACI and the plaintext avalanche test measure. GCM and CTR are
stream modes: the same change flips exactly one ciphertext bit.

The logistic-map cipher is hand-written and exists ONLY as the classic
academic comparison row. It is not authenticated, has no security proof and
must never protect real data.
"""
from __future__ import annotations

import hashlib
import os
import time
from dataclasses import dataclass, field

import numpy as np
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, AESGCMSIV
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

KEY_LEN = 32
TAG_LEN = 16
PRIMARY = "AES-256-GCM-SIV"

SCHEMES: dict[str, dict] = {
    "AES-256-GCM-SIV": {"nonce": 12, "tag": True, "pad": False, "kind": "AEAD, nonce-misuse resistant (RFC 8452)"},
    "AES-256-GCM": {"nonce": 12, "tag": True, "pad": False, "kind": "AEAD, counter mode + GHASH"},
    "AES-256-CTR": {"nonce": 16, "tag": False, "pad": False, "kind": "stream mode, no integrity"},
    "AES-256-CBC": {"nonce": 16, "tag": False, "pad": True, "kind": "block chaining, no integrity"},
    "AES-256-ECB": {"nonce": 0, "tag": False, "pad": True, "kind": "codebook, leaks patterns"},
    "Logistic-map": {"nonce": 16, "tag": False, "pad": False, "kind": "chaotic permutation-diffusion (educational)"},
}
NAMES = list(SCHEMES)

__all__ = ["Envelope", "encrypt", "decrypt", "new_key", "new_nonce", "fingerprint", "SCHEMES", "NAMES", "PRIMARY",
           "InvalidTag"]


@dataclass
class Envelope:
    """Everything a receiver needs except the key. `body` is the ciphertext without the tag."""
    scheme: str
    nonce: bytes
    body: bytes
    tag: bytes = b""
    aad: bytes = b""
    plaintext_len: int = 0
    key_fingerprint: str = ""
    enc_ms: float = 0.0
    extra: dict = field(default_factory=dict)

    @property
    def wire(self) -> bytes:
        """The bytes an observer sees: ciphertext body followed by the tag."""
        return self.body + self.tag

    def to_json(self, *, preview: int | None = None) -> dict:
        body = self.body if preview is None else self.body[:preview]
        return {
            "scheme": self.scheme,
            "kind": SCHEMES[self.scheme]["kind"],
            "key_fingerprint": self.key_fingerprint,
            "nonce_hex": self.nonce.hex(),
            "aad": self.aad.decode("utf-8", errors="replace"),
            "plaintext_bytes": self.plaintext_len,
            "ciphertext_bytes": len(self.body),
            "tag_hex": self.tag.hex(),
            "overhead_bytes": len(self.body) + len(self.tag) + len(self.nonce) - self.plaintext_len,
            "ciphertext_hex": body.hex(),
            "ciphertext_b64": _b64(body),
            "truncated": preview is not None and len(self.body) > preview,
            "encrypt_ms": round(self.enc_ms, 4),
        }


def new_key() -> bytes:
    return os.urandom(KEY_LEN)


def new_nonce(scheme: str) -> bytes:
    return os.urandom(SCHEMES[scheme]["nonce"])


def fingerprint(key: bytes) -> str:
    """First 8 bytes of SHA-256(key): identifies a key without revealing it."""
    return hashlib.sha256(key).hexdigest()[:16]


def encrypt(scheme: str, key: bytes, data: bytes, *, nonce: bytes | None = None, aad: bytes = b"") -> Envelope:
    spec = _spec(scheme, key)
    nonce = new_nonce(scheme) if nonce is None else nonce
    if len(nonce) != spec["nonce"]:
        raise ValueError(f"{scheme} needs a {spec['nonce']}-byte nonce")
    t0 = time.perf_counter()
    tag = b""
    if scheme in ("AES-256-GCM-SIV", "AES-256-GCM"):
        aead = AESGCMSIV(key) if scheme == "AES-256-GCM-SIV" else AESGCM(key)
        out = aead.encrypt(nonce, data, aad or None)
        body, tag = out[:-TAG_LEN], out[-TAG_LEN:]
    elif scheme == "Logistic-map":
        body = _logistic_encrypt(key, nonce, data)
    else:
        body = _block_encrypt(scheme, key, nonce, data)
    ms = (time.perf_counter() - t0) * 1000
    return Envelope(scheme, nonce, body, tag, aad, len(data), fingerprint(key), ms)


def decrypt(env: Envelope, key: bytes) -> bytes:
    """Raises InvalidTag for an AEAD whose ciphertext, nonce, AAD or key is wrong."""
    _spec(env.scheme, key)
    if env.scheme in ("AES-256-GCM-SIV", "AES-256-GCM"):
        aead = AESGCMSIV(key) if env.scheme == "AES-256-GCM-SIV" else AESGCM(key)
        return aead.decrypt(env.nonce, env.body + env.tag, env.aad or None)
    if env.scheme == "Logistic-map":
        return _logistic_decrypt(key, env.nonce, env.body)
    return _block_decrypt(env.scheme, key, env.nonce, env.body)


def decrypt_raw(env: Envelope, key: bytes) -> bytes:
    """CBC / ECB / CTR / logistic decryption that skips the padding check, so a wrong
    key yields visible noise instead of an exception (key-sensitivity images)."""
    _spec(env.scheme, key)
    if env.scheme in ("AES-256-CBC", "AES-256-ECB"):
        dec = Cipher(algorithms.AES(key), _mode(env.scheme, env.nonce)).decryptor()
        return dec.update(env.body) + dec.finalize()
    return decrypt(env, key)


def _spec(scheme: str, key: bytes) -> dict:
    if scheme not in SCHEMES:
        raise ValueError(f"unknown scheme {scheme!r}; choose from {', '.join(NAMES)}")
    if len(key) != KEY_LEN:
        raise ValueError("all lab schemes use a 32-byte (256-bit) key")
    return SCHEMES[scheme]


def _b64(data: bytes) -> str:
    import base64
    return base64.b64encode(data).decode("ascii")


# --- classic AES modes ---------------------------------------------------------------------

def _mode(scheme: str, nonce: bytes):
    return {"AES-256-CTR": lambda: modes.CTR(nonce), "AES-256-CBC": lambda: modes.CBC(nonce),
            "AES-256-ECB": lambda: modes.ECB()}[scheme]()


def _block_encrypt(scheme: str, key: bytes, nonce: bytes, data: bytes) -> bytes:
    if SCHEMES[scheme]["pad"]:
        p = padding.PKCS7(128).padder()
        data = p.update(data) + p.finalize()
    enc = Cipher(algorithms.AES(key), _mode(scheme, nonce)).encryptor()
    return enc.update(data) + enc.finalize()


def _block_decrypt(scheme: str, key: bytes, nonce: bytes, body: bytes) -> bytes:
    dec = Cipher(algorithms.AES(key), _mode(scheme, nonce)).decryptor()
    data = dec.update(body) + dec.finalize()
    if SCHEMES[scheme]["pad"]:
        u = padding.PKCS7(128).unpadder()
        data = u.update(data) + u.finalize()
    return data


# --- logistic-map chaotic cipher (educational comparison only) --------------------------------
#
# x_{n+1} = r * x_n * (1 - x_n), r close to 4, is chaotic: two seeds that differ in
# the 15th decimal place diverge after a few dozen steps. The cipher keys the map
# with HKDF(key, nonce) and runs the classic two stages:
#   1. permutation (confusion of positions): byte order = argsort of a chaotic sequence
#   2. diffusion, forward then backward, through a keyed S-box:
#        c[i] = S[(p[i] + c[i-1]) mod 256] XOR k[i]
#      Two passes make every output byte depend on every input byte, which is what
#      gives high NPCR / UACI.

_LANES = 64
_BURN_IN = 500


def _logistic_params(key: bytes, nonce: bytes) -> tuple[np.ndarray, float, int, int]:
    material = HKDF(hashes.SHA256(), 8 * _LANES + 8, salt=nonce, info=b"cryptolab/logistic").derive(key)
    seeds = np.frombuffer(material[: 8 * _LANES], dtype="<u8").astype(np.float64) / 2.0 ** 64
    seeds = 0.05 + 0.9 * seeds  # keep away from the fixed points 0 and 1
    r = 3.99 + 0.0099 * (int.from_bytes(material[-8:-2], "little") / 2.0 ** 48)
    return seeds, r, material[-2], material[-1]


def _chaos(seeds: np.ndarray, r: float, n: int) -> np.ndarray:
    """n chaotic values in (0, 1), generated in _LANES parallel lanes for speed."""
    x = seeds.copy()
    for _ in range(_BURN_IN):
        x = r * x * (1.0 - x)
    rows = -(-n // _LANES)
    out = np.empty((rows, _LANES))
    for i in range(rows):
        x = r * x * (1.0 - x)
        out[i] = x
    return out.reshape(-1)[:n]


def _logistic_material(key: bytes, nonce: bytes, n: int):
    seeds, r, iv1, iv2 = _logistic_params(key, nonce)
    seq = _chaos(seeds, r, 3 * n + 256)
    perm = np.argsort(seq[:n], kind="stable")
    k1 = (np.floor(seq[n:2 * n] * 1e14) % 256).astype(np.uint8)
    k2 = (np.floor(seq[2 * n:3 * n] * 1e14) % 256).astype(np.uint8)
    sbox = np.argsort(seq[3 * n:], kind="stable").astype(np.uint8)
    return perm, k1.tolist(), k2.tolist(), sbox, iv1, iv2


def _logistic_encrypt(key: bytes, nonce: bytes, data: bytes) -> bytes:
    n = len(data)
    if n == 0:
        return b""
    perm, k1, k2, sbox, iv1, iv2 = _logistic_material(key, nonce, n)
    p = np.frombuffer(data, dtype=np.uint8)[perm].tolist()
    s = sbox.tolist()
    c = [0] * n
    prev = iv1
    for i in range(n):                      # forward diffusion
        prev = s[(p[i] + prev) & 255] ^ k1[i]
        c[i] = prev
    prev = iv2
    for i in range(n - 1, -1, -1):          # backward diffusion
        prev = s[(c[i] + prev) & 255] ^ k2[i]
        c[i] = prev
    return bytes(c)


def _logistic_decrypt(key: bytes, nonce: bytes, body: bytes) -> bytes:
    n = len(body)
    if n == 0:
        return b""
    perm, k1, k2, sbox, iv1, iv2 = _logistic_material(key, nonce, n)
    inv = [0] * 256
    for i, v in enumerate(sbox.tolist()):
        inv[v] = i
    d = list(body)
    c = [0] * n
    for i in range(n):                      # undo backward pass
        nxt = d[i + 1] if i + 1 < n else iv2
        c[i] = (inv[d[i] ^ k2[i]] - nxt) & 255
    p = [0] * n
    prev = iv1
    for i in range(n):                      # undo forward pass
        p[i] = (inv[c[i] ^ k1[i]] - prev) & 255
        prev = c[i]
    out = np.empty(n, dtype=np.uint8)
    out[perm] = np.array(p, dtype=np.uint8)
    return out.tobytes()
