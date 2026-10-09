"""Block 5: the end-to-end marks flow and the security goals behind it."""
from __future__ import annotations

import time

import jwt

from middleware import records
from middleware.crypto import aead, sign
from middleware.crypto.canonical import build_record, canonical_record
from middleware.crypto.hashing import sha256
from middleware.db.models import Mark
from sdk.client import SecureClient

ROLL_608, ROLL_612 = "240911608", "240911612"


def test_publish_then_student_sees_verified_marks(client_for, teacher_key, app):
    t = client_for("t104")
    res = t.publish_marks(teacher_key, "IT301", ROLL_608, 27, 45)
    assert res.ok, res.summary()
    assert res.payload["version"] >= 1 and len(res.payload["sha256"]) == 64
    client_steps = [s["step"] for s in res.trace]
    for step in ("build_record", "canonicalize", "sha256", "ed25519_sign", "x25519_keypair", "hkdf_derive",
                 "aesgcm_encrypt", "send"):
        assert step in client_steps
    server_steps = [s["step"] for s in app.state.sm.tracer.get(res.trace_id)]
    for step in ("rate_limit", "auth_jwt", "session_lookup", "freshness", "replay_check", "aesgcm_decrypt",
                 "rbac", "sig_verify", "encrypt_at_rest", "audit_write"):
        assert step in server_steps

    s = client_for("s608")
    view = s.view_marks()
    assert view.ok
    rec = next(r for r in view.payload["records"] if r["record"]["course"] == "IT301")
    assert rec["verified"] and rec["record"]["endsem"] == 45 and rec["signer"] == "t104"
    assert {"aesgcm_decrypt_response", "sha256_recompute", "ed25519_verify"} <= {x["step"] for x in view.trace}


def test_marks_are_ciphertext_at_rest(app):
    with app.state.sm.db.session() as s:
        row = s.query(Mark).filter_by(roll_no=ROLL_608).first()
    assert b"240911608" not in row.ciphertext and b"endsem" not in row.ciphertext


def test_student_cannot_view_friend(client_for, app):
    s = client_for("s608")
    res = s.view_marks(ROLL_612)
    assert (res.status, res.error) == (403, "forbidden")
    entry = app.state.sm.audit.list(request_id=res.request_id)[0]
    assert entry["action"] == "idor_blocked" and entry["outcome"] == "denied"


def test_teacher_cannot_publish_for_other_course(client_for, teacher_key):
    t = client_for("t104")
    res = t.publish_marks(teacher_key, "CS201", ROLL_608, 20, 40)
    assert (res.status, res.error) == (403, "forbidden")


def test_wrong_password_and_expired_token(client_for, http, settings):
    c = SecureClient("http://testserver", None, "attacker", http=http, save_last_request=False)
    assert (c.login("t104", "nope").status) == 401
    s = client_for("s608")
    s.token = jwt.encode({"sub": "s608", "role": "student", "roll_no": ROLL_608, "courses": [],
                          "exp": int(time.time()) - 60}, settings.jwt_secret, algorithm="HS256")
    res = s.view_marks()
    assert (res.status, res.error) == (401, "auth_failed")


def test_forged_signature_is_rejected(client_for):
    t = client_for("t104")  # stolen token, but not t104's private key
    attacker_key, _ = sign.ed25519_keypair()
    res = t.publish_marks(attacker_key, "IT301", ROLL_608, 30, 50)
    assert (res.status, res.error) == (400, "bad_signature")


def test_weak_session_policy_is_refused(client_for):
    s = client_for("s608")
    res = s.call("/api/marks/view", {"roll_no": ROLL_608}, policy="normal")
    assert (res.status, res.error) == (403, "policy_too_weak")


def test_db_tamper_is_caught_by_student_signature_check(client_for, app):
    st = app.state.sm
    mark = records.latest(st.db, ROLL_608, ("IT301",))[0]
    record, _canon, _v = records.open_record(st.keys, mark)
    record["endsem"], record["total"] = 95, record["midsem"] + 95
    _, dek = st.keys.dek_for(mark.dek_id)
    nonce, ct = aead.encrypt(dek, canonical_record(record), records.marks_aad(mark.course, mark.roll_no))
    with st.db.session() as s:
        row = s.get(Mark, mark.id)
        original = (row.ciphertext, row.nonce)
        row.ciphertext, row.nonce = ct, nonce

    view = client_for("s608").view_marks()
    rec = next(r for r in view.payload["records"] if r["record"]["course"] == "IT301")
    assert view.ok and rec["record"]["endsem"] == 95 and not rec["verified"]

    ctrl = client_for("ctrl").verify_record(mark.id)
    assert ctrl.ok and ctrl.payload["sha256_ok"] is False and ctrl.payload["signature_ok"] is False
    assert "midsem" not in str(ctrl.payload)  # controller never sees marks

    with st.db.session() as s:  # restore
        row = s.get(Mark, mark.id)
        row.ciphertext, row.nonce = original


def test_swapped_ciphertext_fails_decryption(client_for, app):
    st = app.state.sm
    mine = records.latest(st.db, ROLL_608, ("IT301",))[0]
    friend = records.latest(st.db, ROLL_612, ("IT301",))[0]
    with st.db.session() as s:
        row = s.get(Mark, mine.id)
        original = (row.ciphertext, row.nonce)
        row.ciphertext, row.nonce = friend.ciphertext, friend.nonce
    res = client_for("s608").view_marks()
    assert (res.status, res.error) == (500, "record_integrity_failed")
    with st.db.session() as s:
        row = s.get(Mark, mine.id)
        row.ciphertext, row.nonce = original


def test_controller_verifies_without_marks(client_for, app):
    mark = records.latest(app.state.sm.db, ROLL_608, ("IT301",))[0]
    res = client_for("ctrl").verify_record(mark.id)
    assert res.ok and res.payload["sha256_ok"] and res.payload["signature_ok"]
    assert "endsem" not in res.payload


def test_audit_list_roles(client_for):
    assert client_for("ctrl").audit_list(limit=5).payload["chain_ok"] is True
    res = client_for("t104").audit_list(limit=5)
    assert (res.status, res.error) == (403, "forbidden")


def test_rotate_keeps_old_records_readable(client_for, teacher_key):
    a = client_for("admin")
    res = a.rotate_data_key()
    assert res.ok and res.payload["new_version"] == 2
    view = client_for("s608").view_marks()
    assert view.ok and all(r["verified"] for r in view.payload["records"])
    assert client_for("t104").publish_marks(teacher_key, "IT301", ROLL_608, 28, 45).ok


def test_revoked_key_blocks_publish_but_old_records_verify(client_for, teacher_key):
    a = client_for("admin")
    assert a.revoke_signing("t104").ok
    res = client_for("t104").publish_marks(teacher_key, "IT301", ROLL_608, 29, 45)
    assert (res.status, res.error) == (403, "key_revoked")
    view = client_for("s608").view_marks()
    rec = next(r for r in view.payload["records"] if r["record"]["course"] == "IT301")
    assert rec["verified"] and rec["key_status"] == "revoked" and rec["key_revoked_at"]


def test_plain_baseline_is_readable(http):
    record = build_record("IT301", ROLL_608, 27, 45, "t104")
    assert http.post("/plain/publish", json=record).json() == {"ok": True, "stored": 1}
    assert http.get(f"/plain/marks/{ROLL_608}").json()["endsem"] == 45


def test_signature_covers_digest(teacher_key):
    record = build_record("IT301", ROLL_608, 27, 45, "t104")
    digest = sha256(canonical_record(record))
    sig = sign.ed25519_sign(teacher_key, digest)
    sign.ed25519_verify(sign.ed25519_public_bytes(teacher_key), sig, digest)
