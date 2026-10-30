"""Answer-sheet images: signed, encrypted in transit and at rest, verified by the student."""
from __future__ import annotations

import io

from PIL import Image

from middleware import records
from middleware.crypto.canonical import build_record
from middleware.crypto.hashing import sha256_hex
from middleware.db.models import Attachment, Mark

ROLL_608, ROLL_612 = "240911608", "240911612"


def sheet(color=(10, 132, 255), size=(120, 80)) -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", size, color).save(buf, format="PNG")
    return buf.getvalue()


def test_publish_with_sheet_then_student_downloads_it(client_for, teacher_key, app):
    img = sheet()
    t = client_for("t104")
    res = t.publish_marks(teacher_key, "IT301", ROLL_608, 30, 48, attachment=img, attachment_mime="image/png")
    assert res.ok, res.summary()
    assert res.payload["attachment_bytes"] == len(img)
    assert res.payload["sign_ms"] > 0 and res.payload["verify_ms"] > 0
    server_steps = [s["step"] for s in app.state.sm.tracer.get(res.trace_id)]
    assert "attachment_check" in server_steps

    s = client_for("s608")
    view = s.view_marks()
    rec = next(r for r in view.payload["records"] if r["record"]["course"] == "IT301")
    assert rec["verified"] and rec["record"]["attachment_sha256"] == sha256_hex(img)
    assert rec["attachment"]["size_bytes"] == len(img) and rec["attachment"]["width"] == 120
    assert rec["sign_ms"] > 0 and rec["verify_ms"] > 0

    got = s.fetch_attachment("IT301", record=rec["record"])
    assert got.ok and got.payload["verified"] and got.payload["mime"] == "image/png"
    assert got.payload["computed_sha256"] == sha256_hex(img)


def test_sheet_is_ciphertext_at_rest(app):
    with app.state.sm.db.session() as s:
        att = s.query(Attachment).first()
    assert att is not None and b"PNG" not in att.ciphertext[:16] and b"IHDR" not in att.ciphertext


def test_image_not_matching_signed_hash_is_refused(client_for, teacher_key):
    t = client_for("t104")
    record = build_record("IT301", ROLL_608, 30, 48, "t104", attachment_sha256=sha256_hex(sheet()))
    res = t.publish_marks(teacher_key, "IT301", ROLL_608, 30, 48, record=record,
                          attachment=sheet((255, 0, 0)), attachment_mime="image/png")
    assert (res.status, res.error) == (400, "attachment_mismatch")


def test_unsigned_attachment_is_refused(client_for, teacher_key):
    t = client_for("t104")
    record = build_record("IT301", ROLL_608, 30, 48, "t104")  # no attachment_sha256 in the signed record
    res = t.publish_marks(teacher_key, "IT301", ROLL_608, 30, 48, record=record, attachment=sheet())
    assert (res.status, res.error) == (400, "attachment_mismatch")


def test_wrong_type_is_refused(client_for, teacher_key):
    res = client_for("t104").publish_marks(teacher_key, "IT301", ROLL_608, 30, 48, attachment=b"MZ\x90\x00",
                                           attachment_mime="application/x-msdownload")
    assert (res.status, res.error) == (400, "bad_request")


def test_student_cannot_fetch_friend_sheet(client_for, app):
    res = client_for("s608").fetch_attachment("IT301", ROLL_612)
    assert (res.status, res.error) == (403, "forbidden")


def test_swapped_sheet_ciphertext_fails(client_for, teacher_key, app):
    st = app.state.sm
    assert client_for("t104").publish_marks(teacher_key, "IT301", ROLL_612, 20, 40, attachment=sheet((0, 200, 0))).ok
    mine = records.latest(st.db, ROLL_608, ("IT301",))[0]
    friend = records.latest(st.db, ROLL_612, ("IT301",))[0]
    with st.db.session() as s:
        a = s.query(Attachment).filter_by(mark_id=mine.id).one()
        b = s.query(Attachment).filter_by(mark_id=friend.id).one()
        original = (a.ciphertext, a.nonce)
        a.ciphertext, a.nonce = b.ciphertext, b.nonce
    res = client_for("s608").fetch_attachment("IT301")
    assert (res.status, res.error) == (500, "record_integrity_failed")
    with st.db.session() as s:
        a = s.query(Attachment).filter_by(mark_id=mine.id).one()
        a.ciphertext, a.nonce = original


def test_signature_times_are_stored(app):
    with app.state.sm.db.session() as s:
        row = s.query(Mark).filter(Mark.sign_ms.is_not(None)).first()
    assert row.sign_ms > 0 and row.verify_ms > 0
