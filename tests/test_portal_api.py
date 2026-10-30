"""The portal API behind the React app: lab routes, per-tab sessions, role gating, file safety."""
from __future__ import annotations

import io

import pytest
from fastapi.testclient import TestClient
from PIL import Image

from portal_api.main import app

H = {"X-Portal-Session": "pytest-tab-1"}


@pytest.fixture(scope="module")
def c(tmp_path_factory):
    from cryptolab import store
    mp = pytest.MonkeyPatch()
    lab_db = tmp_path_factory.mktemp("lab") / "cryptolab.db"
    mp.setattr(store, "db_path", lambda: lab_db)  # never write the demo's data/cryptolab.db
    with TestClient(app) as client:
        yield client
    mp.undo()


def test_session_header_required(c):
    assert c.get("/api/me").status_code == 400
    assert c.get("/api/me", headers=H).json() == {"user": None}


def test_role_pages_need_sign_in(c):
    r = c.post("/api/publish", headers=H, data={"course": "IT301", "roll_no": "240911608", "midsem": "1", "endsem": "1"})
    assert r.status_code == 401
    assert c.post("/api/marks", headers=H, json={}).status_code == 401


def test_text_lab_round_trip_and_json_envelope(c):
    r = c.post("/api/lab/text/encrypt", json={"plaintext": "marks 45", "scheme": "AES-256-GCM-SIV", "aad": "x"}).json()
    env = r["envelope"]
    assert r["decrypt_ok"] and r["decrypted"] == "marks 45"
    assert len(env["ciphertext_hex"]) == 16 and len(env["tag_hex"]) == 32 and env["scheme"] == "AES-256-GCM-SIV"
    assert c.post("/api/lab/text/encrypt", json={"scheme": "nope"}).status_code == 400
    assert c.post("/api/lab/text/encrypt", json={"key_hex": "abcd"}).status_code == 400


def test_text_security_metrics(c):
    r = c.post("/api/lab/text/security", json={"scheme": "AES-256-GCM-SIV", "trials": 16}).json()
    assert 44 < r["avalanche"]["bit_pct"] < 56 and r["avalanche"]["char_pct"] > 97
    assert len(r["diffusion"]["matrix"]) == 128


def test_image_lab_sample_and_upload(c):
    r = c.post("/api/lab/image/analyze", data={"sample": "photo", "side": "96"}).json()
    assert r["npcr"] > 99 and r["lossless"] and r["images"]["cipher"].startswith("data:image/png;base64,")
    assert len(r["grid"]["plain"]) == 8 and len(r["grid"]["plain"][0][0]) == 3
    buf = io.BytesIO()
    Image.new("RGB", (40, 30), (200, 10, 10)).save(buf, format="PNG")
    up = c.post("/api/lab/image/analyze", data={"scheme": "AES-256-CTR"}, files={"file": ("x.png", buf.getvalue(), "image/png")})
    assert up.status_code == 200 and up.json()["width"] == 40
    bad = c.post("/api/lab/image/analyze", files={"file": ("x.png", b"not an image", "image/png")})
    assert bad.status_code == 400


def test_hash_and_signature_routes(c):
    d = c.post("/api/lab/hash/digest", json={"message": "abc", "other": "abd", "algorithm": "SHA-256"}).json()
    assert any(x["hex"].startswith("ba7816bf") for x in d["digests"]) and d["compare"]["total_bits"] == 256
    r = c.post("/api/lab/hash/resistance", json={"max_preimage_bits": 10, "max_collision_bits": 16, "trials": 2}).json()
    assert r["preimage"]["rows"][0]["bits"] == 8
    s = c.post("/api/lab/sign/once", json={"algorithm": "Ed25519", "tampered": "x"}).json()
    assert s["valid"] and s["tampered_valid"] is False
    hist = c.get("/api/lab/history?kind=signature").json()
    assert hist and hist[0]["kind"] == "signature"


def test_file_route_is_confined(c):
    assert c.get("/api/ops/file/lab/../../.env").status_code == 404
    assert c.get("/api/ops/file/nowhere/x.png").status_code == 404


def test_spa_fallback(c):
    r = c.get("/lab/image")
    assert r.status_code == 200 and "html" in r.headers["content-type"]
    assert c.get("/api/does-not-exist").status_code == 404
