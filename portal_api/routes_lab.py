"""Crypto analysis labs: text, image, hashing, signatures, key agreement.

Everything runs in this process with cryptolab (no sign-in needed), and every
measurement is stored in data/cryptolab.db.
"""
from __future__ import annotations

import json
import os
import time

from fastapi import APIRouter, File, Form, HTTPException, UploadFile
from fastapi.responses import Response
from pydantic import BaseModel, Field

from cryptolab import hashlab, image, perf, samples, schemes, signlab, store, text
from cryptolab.serialize import channels, data_url, public
from middleware.crypto import kex

router = APIRouter(prefix="/api/lab")
MAX_TEXT = 64 * 1024


def _key(hex_key: str | None) -> bytes | None:
    if not hex_key:
        return None
    try:
        key = bytes.fromhex(hex_key.strip())
    except ValueError as exc:
        raise HTTPException(400, "key must be hex") from exc
    if len(key) != schemes.KEY_LEN:
        raise HTTPException(400, f"key must be {schemes.KEY_LEN} bytes ({schemes.KEY_LEN * 2} hex characters)")
    return key


def _scheme(name: str) -> str:
    if name not in schemes.SCHEMES:
        raise HTTPException(400, f"unknown scheme {name}")
    return name


@router.get("/schemes")
def list_schemes():
    return [{"name": n, **{k: v for k, v in s.items()}} for n, s in schemes.SCHEMES.items()]


# --- text --------------------------------------------------------------------------------------------

class TextBody(BaseModel):
    plaintext: str = Field(default=text.DEFAULT_TEXT, max_length=MAX_TEXT)
    scheme: str = schemes.PRIMARY
    key_hex: str | None = None
    aad: str = ""
    tamper: bool = False


@router.post("/text/encrypt")
def text_encrypt(b: TextBody):
    r = text.encrypt_text(_scheme(b.scheme), b.plaintext, key=_key(b.key_hex), aad=b.aad, tamper=b.tamper)
    store.save("text", b.scheme, {"bytes": r["plaintext_bytes"], "tamper": b.tamper},
               {"encrypt_ms": r["encrypt_ms"], "decrypt_ms": r["decrypt_ms"], "entropy": r["ciphertext_entropy"]})
    return r


class SecurityBody(BaseModel):
    plaintext: str = Field(default=text.DEFAULT_TEXT, min_length=1, max_length=4096)
    scheme: str = schemes.PRIMARY
    trials: int = Field(default=64, ge=8, le=256)


@router.post("/text/security")
def text_security(b: SecurityBody):
    name, pt = _scheme(b.scheme), b.plaintext.encode()
    av = text.avalanche(name, pt, trials=b.trials)
    ks = text.key_sensitivity(name, pt, trials=b.trials)
    st = text.stats(name, (pt * (4096 // len(pt) + 1))[:4096])
    out = {"scheme": name, "plaintext_bytes": len(pt), "avalanche": av, "key_sensitivity": ks, "stats": st,
           "diffusion": text.diffusion_map(name, samples=3), "ecb": text.ecb_repeats(name)}
    store.save("text_security", name, {"bytes": len(pt), "trials": b.trials},
               {"avalanche_bit_pct": av["bit_pct"], "avalanche_char_pct": av["char_pct"], "key_sens_bit_pct": ks["bit_pct"]})
    return out


@router.post("/text/compare")
def text_compare(b: SecurityBody):
    return text.compare_schemes(b.plaintext.encode(), trials=min(b.trials, 48))


class PerfBody(BaseModel):
    schemes: list[str] = Field(default_factory=lambda: list(schemes.NAMES))
    max_size: int = Field(default=perf.MB, ge=16, le=10 * perf.MB)


@router.post("/text/perf")
def text_perf(b: PerfBody):
    sizes = [s for s in perf.TEXT_SIZES_FULL if s <= b.max_size]
    rows = perf.sweep_schemes([_scheme(n) for n in b.schemes], sizes)
    store.save("text_perf", ",".join(b.schemes), {"max_size": b.max_size}, {"rows": len(rows)})
    return rows


# --- image -------------------------------------------------------------------------------------------

@router.get("/image/samples")
def image_samples():
    return [{"name": k, "label": v, "thumb": data_url(samples.get(k, 96))} for k, v in samples.SAMPLES.items()]


async def _load_image(sample: str | None, upload: UploadFile | None, side: int):
    side = max(32, min(side, 512))
    if upload is not None and upload.filename:
        raw = await upload.read()
        if len(raw) > 15 * 1024 * 1024:
            raise HTTPException(413, "image larger than 15 MB")
        try:
            return image.load(raw, side), upload.filename
        except Exception as exc:  # noqa: BLE001 - any decode error is a bad upload
            raise HTTPException(400, f"could not read {upload.filename} as an image") from exc
    name = sample or "photo"
    if name not in samples.SAMPLES:
        raise HTTPException(400, f"unknown sample {name}")
    return samples.get(name, side), name


@router.post("/image/analyze")
async def image_analyze(scheme: str = Form(schemes.PRIMARY), sample: str | None = Form(None), side: int = Form(256),
                        file: UploadFile | None = File(None)):
    from starlette.concurrency import run_in_threadpool
    img, source = await _load_image(sample, file, side)
    r = await run_in_threadpool(image.analyze, img, _scheme(scheme))
    a = r["_arrays"]
    grid_y, grid_x = img.shape[0] // 2 - 4, img.shape[1] // 2 - 4
    out = public(r)
    out.update(source=source, images={
        "plain": data_url(a["plain"]), "cipher": data_url(a["cipher"]), "decrypted": data_url(a["decrypted"]),
        "cipher_changed": data_url(a["cipher_changed"]), "wrong_key": data_url(a["wrong_key"]),
        "plain_channels": channels(a["plain"]), "cipher_channels": channels(a["cipher"]),
        "diff": data_url((a["cipher"] != a["cipher_changed"]).any(axis=2).astype("uint8")[..., None].repeat(3, 2) * 255),
    }, grid={"y": grid_y, "x": grid_x, "plain": image.pixel_grid(a["plain"], grid_y, grid_x),
             "cipher": image.pixel_grid(a["cipher"], grid_y, grid_x),
             "decrypted": image.pixel_grid(a["decrypted"], grid_y, grid_x)})
    store.save("image", scheme, {"source": source, "width": r["width"], "height": r["height"]},
               {"npcr": r["npcr"], "uaci": r["uaci"], "entropy": r["entropy_cipher"]["all"],
                "corr_h": r["corr_cipher"]["horizontal"]["mean"], "psnr": r["psnr_plain_cipher"],
                "mse": r["mse_plain_cipher"], **r["timing"]})
    return out


@router.post("/image/compare")
async def image_compare(sample: str | None = Form(None), side: int = Form(192), file: UploadFile | None = File(None)):
    from starlette.concurrency import run_in_threadpool
    img, source = await _load_image(sample, file, min(side, 256))
    rows = await run_in_threadpool(image.compare, img)
    for r in rows:
        r["image"] = data_url(r.pop("_cipher"))
    return {"source": source, "plain": data_url(img), "rows": rows}


@router.post("/image/perf")
async def image_perf(sample: str | None = Form(None), file: UploadFile | None = File(None)):
    from starlette.concurrency import run_in_threadpool
    img, _ = await _load_image(sample, file, 512)
    return await run_in_threadpool(image.sweep_sizes, img, schemes.NAMES)


@router.post("/image/envelope")
async def image_envelope(scheme: str = Form(schemes.PRIMARY), sample: str | None = Form(None), side: int = Form(256),
                         file: UploadFile | None = File(None)):
    """The full encrypted image as a JSON envelope (download)."""
    img, source = await _load_image(sample, file, side)
    key = schemes.new_key()
    _cipher, env = image.encrypt_image(_scheme(scheme), key, img)
    doc = {"source": source, "shape": list(img.shape), "dtype": "uint8 RGB", **env.to_json()}
    return Response(json.dumps(doc, indent=1), media_type="application/json",
                    headers={"Content-Disposition": f'attachment; filename="encrypted_image_{scheme}.json"'})


# --- hashing -----------------------------------------------------------------------------------------

class HashBody(BaseModel):
    message: str = Field(default="IT301 · 240911608 · midsem 27 · endsem 45", max_length=MAX_TEXT)
    other: str | None = Field(default=None, max_length=MAX_TEXT)
    algorithm: str = "SHA-256"


@router.post("/hash/digest")
def hash_digest(b: HashBody):
    data = b.message.encode()
    rows = hashlab.digest_all(data)
    av = [hashlab.avalanche(n, data, 48) for n in hashlab.NAMES]
    for r in rows:
        store.save("hash", r["algorithm"], {"bytes": len(data)}, {"time_us": r["time_us"]})
    out = {"bytes": len(data), "digests": rows, "avalanche": av}
    if b.other is not None:
        if b.algorithm not in hashlab.ALGORITHMS:
            raise HTTPException(400, "unknown algorithm")
        out["compare"] = hashlab.compare_two(b.algorithm, data, b.other.encode())
    return out


class ResistBody(BaseModel):
    algorithm: str = "SHA-256"
    max_preimage_bits: int = Field(default=16, ge=8, le=20)
    max_collision_bits: int = Field(default=28, ge=8, le=36)
    trials: int = Field(default=5, ge=1, le=20)


@router.post("/hash/resistance")
def hash_resistance(b: ResistBody):
    if b.algorithm not in hashlab.CRYPTO:
        raise HTTPException(400, "choose a cryptographic hash")
    pre = tuple(range(8, b.max_preimage_bits + 1, 2))
    col = tuple(range(8, b.max_collision_bits + 1, 4))
    t0 = time.perf_counter()
    r = hashlab.resistance(b.algorithm, preimage_bits=pre, collision_bits=col, trials=b.trials)
    r["seconds"] = round(time.perf_counter() - t0, 2)
    store.save("hash_resistance", b.algorithm, b.model_dump(), {"hashes_per_second": r["hashes_per_second"]})
    return r


@router.get("/hash/extras")
def hash_extras():
    return {"lab5": hashlab.lab5_dataset(100), "djb2": hashlab.djb2_collision(),
            "extrapolation": {n: hashlab.extrapolate(n) for n in hashlab.CRYPTO},
            "status": {n: a["status"] for n, a in hashlab.ALGORITHMS.items()}}


@router.post("/hash/perf")
def hash_perf():
    return hashlab.sweep()


# --- signatures --------------------------------------------------------------------------------------

class SignBody(BaseModel):
    algorithm: str = "Ed25519"
    message: str = Field(default="IT301 · 240911608 · midsem 27 · endsem 45 · total 72", max_length=MAX_TEXT)
    tampered: str | None = Field(default=None, max_length=MAX_TEXT)
    runs: int = Field(default=200, ge=10, le=2000)


def _sig_alg(name: str) -> str:
    if name not in signlab.ALGORITHMS:
        raise HTTPException(400, "unknown algorithm")
    return name


@router.post("/sign/once")
def sign_once(b: SignBody):
    r = signlab.sign_once(_sig_alg(b.algorithm), b.message, tampered=b.tampered)
    store.save("signature", b.algorithm, {"source": "sign once", "bytes": len(b.message.encode())},
               {"keygen_ms": r["keygen_ms"], "sign_ms": r["sign_ms"], "verify_ms": r["verify_ms"],
                "signature_bytes": r["signature_bytes"], "valid": r["valid"]})
    return r


@router.post("/sign/benchmark")
def sign_benchmark(b: SignBody):
    r = signlab.benchmark(_sig_alg(b.algorithm), b.runs)
    store.save("signature", b.algorithm, {"source": "benchmark", "runs": b.runs},
               {"sign_ms": r["sign_ms"]["median"], "verify_ms": r["verify_ms"]["median"],
                "keygen_ms": r["keygen_ms"]["median"], "signature_bytes": r["signature_bytes"]})
    return r


@router.post("/sign/compare")
def sign_compare():
    return signlab.compare(100)


# --- key agreement -----------------------------------------------------------------------------------

@router.post("/kex")
def kex_demo():
    a_priv, a_pub = kex.x25519_keypair()
    b_priv, b_pub = kex.x25519_keypair()
    e_priv, e_pub = kex.x25519_keypair()
    t0 = time.perf_counter()
    s_alice = kex.x25519_shared(a_priv, b_pub)
    ms = (time.perf_counter() - t0) * 1000
    s_bob = kex.x25519_shared(b_priv, a_pub)
    e1, e2 = kex.x25519_shared(e_priv, a_pub), kex.x25519_shared(e_priv, b_pub)
    salt = os.urandom(16)
    return {"alice_pub": a_pub.hex(), "bob_pub": b_pub.hex(), "eve_pub": e_pub.hex(),
            "alice_secret": s_alice.hex(), "bob_secret": s_bob.hex(), "eve_with_alice": e1.hex(),
            "eve_with_bob": e2.hex(), "match": s_alice == s_bob, "eve_fails": s_alice not in (e1, e2),
            "salt": salt.hex(), "session_key": kex.hkdf_derive(s_alice, salt, 32).hex(), "shared_ms": round(ms, 4)}


# --- history -----------------------------------------------------------------------------------------

@router.get("/history")
def history(kind: str | None = None, limit: int = 100):
    return store.history(kind, min(limit, 1000))


@router.get("/history.csv")
def history_csv(kind: str | None = None):
    return Response(store.export_csv(kind), media_type="text/csv",
                    headers={"Content-Disposition": f'attachment; filename="cryptolab_{kind or "all"}.csv"'})
