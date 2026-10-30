"""The analysis library: every metric against its known value, every scheme round trip."""
from __future__ import annotations

import math

import numpy as np
import pytest

from cryptolab import hashlab, image, metrics as m, samples, schemes as sc, signlab, store, text

RNG = np.random.default_rng(0)


@pytest.mark.parametrize("name", sc.NAMES)
@pytest.mark.parametrize("data", [b"", b"x", b"SecureMarks " * 21, bytes(range(256)) * 9])
def test_round_trip(name, data):
    key = sc.new_key()
    assert sc.decrypt(sc.encrypt(name, key, data), key) == data


def test_aead_detects_tampering():
    key = sc.new_key()
    for name in ("AES-256-GCM-SIV", "AES-256-GCM"):
        env = sc.encrypt(name, key, b"marks")
        env.body = bytes([env.body[0] ^ 1]) + env.body[1:]
        with pytest.raises(sc.InvalidTag):
            sc.decrypt(env, key)


def test_metric_reference_values():
    rand = RNG.integers(0, 256, 1 << 16, dtype=np.uint8).tobytes()
    assert m.entropy(bytes(range(256)) * 4) == pytest.approx(8.0)
    assert m.entropy(b"aaaa") == 0.0
    assert 7.99 < m.entropy(rand) <= 8.0
    assert m.bit_diff_pct(b"\x00", b"\xff") == 100 and m.byte_diff_pct(b"ab", b"ab") == 0
    assert m.chi_square(rand) < 2 * m.CHI2_CRITICAL_255
    assert m.npcr_critical(256 * 256) == pytest.approx(99.5693, abs=1e-3)       # Wu et al. 2011
    lo, hi = m.uaci_interval(256 * 256)
    assert (lo, hi) == (pytest.approx(33.2824, abs=1e-3), pytest.approx(33.6447, abs=1e-3))


def test_image_metrics_on_known_inputs():
    a = RNG.integers(0, 256, (128, 128, 3), dtype=np.uint8)
    b = RNG.integers(0, 256, (128, 128, 3), dtype=np.uint8)
    assert m.npcr(a, a) == 0 and m.uaci(a, a) == 0
    assert m.npcr(a, b) == pytest.approx(m.NPCR_IDEAL, abs=0.2)
    assert m.uaci(a, b) == pytest.approx(m.UACI_IDEAL, abs=0.4)
    assert math.isinf(m.psnr(a, a)) and m.mse(a, a) == 0
    smooth = samples.gradient(128)
    assert m.adjacent_corr(smooth[..., 0], "horizontal") > 0.99
    assert abs(m.adjacent_corr(a[..., 0], "horizontal")) < 0.03


def test_gcm_siv_has_full_avalanche_gcm_does_not():
    pt = text.DEFAULT_TEXT.encode()
    siv = text.avalanche("AES-256-GCM-SIV", pt, trials=24)
    gcm = text.avalanche("AES-256-GCM", pt, trials=24)
    ctr = text.avalanche("AES-256-CTR", pt, trials=24)
    assert 45 < siv["bit_pct"] < 55 and siv["char_pct"] > 98
    assert gcm["bit_pct"] < 10 and ctr["bit_pct"] < 1
    for name in sc.NAMES:  # confusion: every scheme is key-sensitive
        assert 45 < text.key_sensitivity(name, pt, trials=16)["bit_pct"] < 55


def test_ecb_leaks_repeated_blocks():
    assert text.ecb_repeats("AES-256-ECB")["leaks_pattern"]
    assert not text.ecb_repeats("AES-256-CBC")["leaks_pattern"]
    assert not text.ecb_repeats("AES-256-GCM-SIV")["leaks_pattern"]


def test_encrypt_text_shows_everything_and_detects_tamper():
    r = text.encrypt_text("AES-256-GCM-SIV", "hello", aad="marks")
    assert r["decrypt_ok"] and r["decrypted"] == "hello"
    assert len(r["envelope"]["ciphertext_hex"]) == 10 and len(r["envelope"]["tag_hex"]) == 32
    bad = text.encrypt_text("AES-256-GCM-SIV", "hello", tamper=True)
    assert not bad["decrypt_ok"] and "InvalidTag" in bad["error"]
    ctr = text.encrypt_text("AES-256-CTR", "hello", tamper=True)
    assert ctr["decrypt_ok"] and "no integrity" in ctr["error"]


def test_image_analysis_primary_scheme_passes():
    r = image.analyze(samples.photo(128), "AES-256-GCM-SIV")
    assert r["lossless"] and r["npcr"] > 99.4 and 33.0 < r["uaci"] < 34.0
    assert r["entropy_cipher"]["all"] > 7.99 and r["entropy_plain"]["all"] < 7.8
    assert r["corr_plain"]["horizontal"]["mean"] > 0.85
    assert abs(r["corr_cipher"]["horizontal"]["mean"]) < 0.02
    assert r["psnr_plain_cipher"] < 10 and r["psnr_plain_decrypted"] == "inf"
    assert "InvalidTag" in r["key_sensitivity"]["result"]


def test_stream_mode_fails_npcr_and_logistic_passes():
    img = samples.photo(96)
    assert image.analyze(img, "AES-256-CTR", full=False)["npcr"] < 1
    lg = image.analyze(img, "Logistic-map", full=False)
    assert lg["npcr"] > 99 and lg["lossless"]


def test_hash_digests_and_avalanche():
    rows = {r["algorithm"]: r for r in hashlab.digest_all(b"abc")}
    assert rows["SHA-256"]["hex"] == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    assert rows["MD5"]["hex"] == "900150983cd24fb0d6963f7d28e17f72"
    assert rows["djb2"]["hex"] == hashlab.djb2(b"abc").hex() and len(rows["djb2"]["hex"]) == 8
    assert 40 < hashlab.avalanche("SHA-256", b"IT301 240911608", 32)["bit_pct"] < 60


def test_resistance_experiments_follow_theory():
    r = hashlab.resistance("SHA-256", preimage_bits=(8, 10), collision_bits=(12, 16), trials=6)
    for row in r["preimage"]["rows"] + r["collision"]["rows"]:
        assert abs(row["log2_mean"] - row["log2_theory"]) < 2.5
    assert r["extrapolation"][2]["log2_tries"] == 128


def test_djb2_collides_quickly():
    c = hashlab.djb2_collision(cap=400_000)
    assert c["found"] and c["a"] != c["b"] and hashlab.djb2(c["a"].encode()) == hashlab.djb2(c["b"].encode())


def test_signatures_time_and_tamper():
    r = signlab.sign_once("Ed25519", "IT301 45", tampered="IT301 95")
    assert r["valid"] and r["tampered_valid"] is False and r["signature_bytes"] == 64
    assert r["sign_ms"] > 0 and r["verify_ms"] > 0
    b = signlab.benchmark("ECDSA-P256", runs=10)
    assert b["sign_ms"]["median"] > 0 and len(b["sign_samples"]) == 10


def test_store_round_trip(tmp_path):
    db = tmp_path / "lab.db"
    rid = store.save("signature", "Ed25519", {"runs": 1}, {"sign_ms": 0.02}, path=db)
    rows = store.history("signature", path=db)
    assert rows[0]["id"] == rid and rows[0]["metrics"]["sign_ms"] == 0.02
    assert "Ed25519" in store.export_csv(path=db)
