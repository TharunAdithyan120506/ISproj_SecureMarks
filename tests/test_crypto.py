"""Block 1: the crypto core."""
from __future__ import annotations

import pytest

from middleware.crypto import aead, kex, sign
from middleware.crypto.canonical import RecordError, build_record, canonical_record
from middleware.crypto.hashing import bit_difference, entropy, sha256
from middleware.crypto.encoding import short


@pytest.mark.parametrize("key_len", [16, 32])
def test_aesgcm_round_trip(key_len):
    key = aead.new_key(key_len)
    nonce, ct = aead.encrypt(key, b"marks: 27/45", b"aad")
    assert len(nonce) == 12 and len(ct) == len(b"marks: 27/45") + 16
    assert aead.decrypt(key, nonce, ct, b"aad") == b"marks: 27/45"


def test_aesgcm_flipped_byte_fails():
    key = aead.new_key()
    nonce, ct = aead.encrypt(key, b"secret marks", b"aad")
    flipped = bytes([ct[0] ^ 0x01]) + ct[1:]
    with pytest.raises(aead.InvalidTag):
        aead.decrypt(key, nonce, flipped, b"aad")


def test_aesgcm_wrong_key_or_aad_fails():
    key = aead.new_key()
    nonce, ct = aead.encrypt(key, b"secret marks", b"marks|IT301|240911608")
    with pytest.raises(aead.InvalidTag):
        aead.decrypt(aead.new_key(), nonce, ct, b"marks|IT301|240911608")
    with pytest.raises(aead.InvalidTag):
        aead.decrypt(key, nonce, ct, b"marks|IT301|240911612")


def test_nonces_are_fresh():
    key = aead.new_key()
    assert len({aead.encrypt(key, b"x")[0] for _ in range(200)}) == 200


def test_ed25519_sign_verify_and_edit_fails():
    priv, pub = sign.ed25519_keypair()
    digest = sha256(b"record")
    sig = sign.ed25519_sign(priv, digest)
    assert len(sig) == 64 and len(pub) == 32
    sign.ed25519_verify(pub, sig, digest)
    with pytest.raises(sign.InvalidSignature):
        sign.ed25519_verify(pub, sig, sha256(b"record (edited)"))
    _, other_pub = sign.ed25519_keypair()
    with pytest.raises(sign.InvalidSignature):
        sign.ed25519_verify(other_pub, sig, digest)


def test_rsa_pss_sign_verify():
    priv = kex.rsa_keypair()
    digest = sha256(b"record")
    alg, sig = sign.sign(priv, digest)
    assert alg == sign.RSA_PSS and len(sig) == 256
    sign.verify(alg, sign.public_bytes(priv), sig, digest)
    with pytest.raises(sign.InvalidSignature):
        sign.verify(alg, sign.public_bytes(priv), sig, sha256(b"other"))


def test_x25519_both_sides_derive_equal_keys():
    a_priv, a_pub = kex.x25519_keypair()
    b_priv, b_pub = kex.x25519_keypair()
    salt = kex.session_salt("00112233445566778899aabbccddeeff")
    ka = kex.hkdf_derive(kex.x25519_shared(a_priv, b_pub), salt, 32)
    kb = kex.hkdf_derive(kex.x25519_shared(b_priv, a_pub), salt, 32)
    assert ka == kb and len(ka) == 32
    # Eve, with her own keypair and both public keys, gets something else
    e_priv, _ = kex.x25519_keypair()
    assert kex.hkdf_derive(kex.x25519_shared(e_priv, a_pub), salt, 32) != ka


def test_rsa_oaep_wrap_unwrap():
    priv = kex.rsa_keypair()
    secret = kex.rsa_session_secret()
    assert kex.rsa_unwrap(priv, kex.rsa_wrap(kex.rsa_public_der(priv), secret)) == secret


def test_canonical_record_is_stable_and_validated():
    r = build_record("IT301", "240911608", 27, 45, "t104", "2026-10-09T10:00:00Z")
    assert canonical_record(r) == canonical_record(dict(reversed(list(r.items()))))
    assert canonical_record(r).startswith(b'{"course":"IT301","endsem":45')
    with pytest.raises(RecordError):
        canonical_record({**r, "total": 99})
    with pytest.raises(RecordError):
        canonical_record({**r, "extra": 1})


def test_password_key_file_round_trip():
    priv, pub = sign.ed25519_keypair()
    pem = sign.save_private_pem(priv, "pw")
    assert b"ENCRYPTED" in pem
    assert sign.public_bytes(sign.load_private_pem(pem, "pw")) == pub
    with pytest.raises(ValueError):
        sign.load_private_pem(pem, "wrong")


def test_helpers():
    assert short(bytes(range(32))) == "00010203…1c1d1e1f"
    assert bit_difference(sha256(b"hello"), sha256(b"hellp")) > 80
    assert entropy(b"aaaa") == 0 and entropy(bytes(range(256))) == 8.0
