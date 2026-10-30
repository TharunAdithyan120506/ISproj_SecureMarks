"""Integrity and authenticity at rest: a malicious server admin edits the database.

    python -m attacks.tamper_db              # decrypt t104's record for 240911608, endsem -> 95, re-encrypt
    python -m attacks.tamper_db --swap       # copy 240911612's ciphertext into 240911608's row
    python -m attacks.tamper_db --sheet      # replace the answer-sheet image, re-encrypted with the data key
    python -m attacks.tamper_db --audit      # edit an audit row (breaks the hash chain, P1)
    python -m attacks.tamper_db --restore    # put the original row back

The admin holds the master key, so the edit re-encrypts cleanly and the server
serves it, but the teacher's Ed25519 signature no longer matches: the student
sees "Signature invalid" and the exam controller's verify reports it. The swap
fails AES-GCM at rest (AAD binds course|roll) -> 500 record_integrity_failed.
The sheet edit decrypts fine too, but the image's SHA-256 no longer equals the
attachment_sha256 inside the signed record, so the student's device rejects it.
"""
from __future__ import annotations

import argparse
import base64
import io
import json

from middleware import records
from middleware.crypto import aead
from middleware.crypto.canonical import canonical
from middleware.db.models import Attachment, AuditLog, Mark
from middleware.db.session import Database
from middleware.keys.manager import KeyManager
from middleware.settings import load_settings

from .common import AttackResult, device_client, ensure_published, report, with_evidence

NAME, GOAL = "tamper_db", "Integrity, authenticity"


def _open():
    s = load_settings()
    db = Database(s.db_path)
    return s, db, KeyManager(db, s.master_key_path)


def _backup_path():
    return load_settings().captures_dir / "tamper_backup.json"


def _save_backup(mark: Mark) -> None:
    path = _backup_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        return  # keep the very first original
    path.write_text(json.dumps({"mark_id": mark.id, "ciphertext": base64.b64encode(mark.ciphertext).decode(),
                                "nonce": base64.b64encode(mark.nonce).decode()}), encoding="utf-8")


def _sheet_backup_path():
    return load_settings().captures_dir / "tamper_sheet_backup.json"


def restore() -> str:
    done = []
    _s, db, _k = _open()
    path = _backup_path()
    if path.exists():
        b = json.loads(path.read_text(encoding="utf-8"))
        with db.session() as s:
            row = s.get(Mark, b["mark_id"])
            if row is not None:
                row.ciphertext, row.nonce = base64.b64decode(b["ciphertext"]), base64.b64decode(b["nonce"])
        path.unlink()
        done.append(f"record {b['mark_id']} restored")
    path = _sheet_backup_path()
    if path.exists():
        b = json.loads(path.read_text(encoding="utf-8"))
        with db.session() as s:
            row = s.get(Attachment, b["attachment_id"])
            if row is not None:
                row.ciphertext, row.nonce = base64.b64decode(b["ciphertext"]), base64.b64decode(b["nonce"])
        path.unlink()
        done.append(f"answer sheet {b['attachment_id']} restored")
    db.dispose()
    return "; ".join(done) or "nothing to restore"


def _forged_sheet() -> bytes:
    from PIL import Image, ImageDraw
    img = Image.new("RGB", (320, 200), (255, 255, 255))
    ImageDraw.Draw(img).text((20, 90), "endsem 95 / 100 (forged)", fill=(200, 0, 0))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def ensure_sheet(roll_no: str = "240911608", course: str = "IT301") -> None:
    """Publish a record with an answer sheet if the target has none."""
    from PIL import Image
    from .common import teacher_key
    _s, db, _k = _open()
    mark = records.latest(db, roll_no, (course,))
    has = bool(mark) and records.attachment_for(db, mark[0].id) is not None
    db.dispose()
    if has:
        return
    buf = io.BytesIO()
    Image.new("RGB", (320, 200), (235, 240, 255)).save(buf, format="PNG")
    res = device_client("teacher", "t104").publish_marks(teacher_key(), course, roll_no, 27, 45,
                                                         attachment=buf.getvalue(), attachment_mime="image/png")
    if not res.ok:
        raise RuntimeError(f"could not publish a record with an answer sheet: {res.summary()}")


def edit_sheet(roll_no: str = "240911608", course: str = "IT301") -> str:
    _s, db, keys = _open()
    mark = _target(db, roll_no, course)
    att = records.attachment_for(db, mark.id)
    _, dek = keys.dek_for(att.dek_id)
    forged = _forged_sheet()
    nonce, ct = aead.encrypt(dek, forged, records.sheet_aad(mark.course, mark.roll_no, mark.version))
    with db.session() as s:
        row = s.get(Attachment, att.id)
        path = _sheet_backup_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            path.write_text(json.dumps({"attachment_id": row.id, "ciphertext": base64.b64encode(row.ciphertext).decode(),
                                        "nonce": base64.b64encode(row.nonce).decode()}), encoding="utf-8")
        row.ciphertext, row.nonce = ct, nonce  # the sha256 column and the signed record are left untouched
    db.dispose()
    return f"answer sheet of record {mark.id} replaced by a forged {len(forged):,} B image (re-encrypted, AAD correct)"


def _target(db, roll_no: str, course: str) -> Mark:
    rows = records.latest(db, roll_no, (course,))
    if not rows:
        raise RuntimeError(f"no {course} record for {roll_no}; publish one first")
    return rows[0]


def edit(roll_no: str = "240911608", course: str = "IT301", new_endsem: int = 95) -> str:
    _s, db, keys = _open()
    mark = _target(db, roll_no, course)
    record, _canon, _v = records.open_record(keys, mark)
    old = record["endsem"]
    record["endsem"], record["total"] = new_endsem, record["midsem"] + new_endsem
    _, dek = keys.dek_for(mark.dek_id)
    nonce, ct = aead.encrypt(dek, canonical(record), records.marks_aad(course, roll_no))
    with db.session() as s:
        row = s.get(Mark, mark.id)
        _save_backup(row)
        row.ciphertext, row.nonce = ct, nonce  # sha256 and signature columns left untouched
    db.dispose()
    return f"record {mark.id}: endsem {old} → {new_endsem} (re-encrypted with the data key, signature untouched)"


def swap(roll_no: str = "240911608", other_roll: str = "240911612", course: str = "IT301") -> str:
    _s, db, _keys = _open()
    mine, other = _target(db, roll_no, course), _target(db, other_roll, course)
    with db.session() as s:
        row = s.get(Mark, mine.id)
        _save_backup(row)
        row.ciphertext, row.nonce = other.ciphertext, other.nonce
    db.dispose()
    return f"record {mine.id} ({roll_no}) now holds the ciphertext of record {other.id} ({other_roll})"


def tamper_audit() -> str:
    _s, db, _k = _open()
    with db.session() as s:
        row = s.query(AuditLog).filter(AuditLog.outcome == "denied").order_by(AuditLog.id.desc()).first()
        if row is None:
            return "no denied audit row to hide"
        row.outcome, row.code = "allowed", "ok"
        rid = row.id
    db.dispose()
    return f"audit entry #{rid} rewritten from denied to allowed (hash chain now broken from #{rid})"


def run(mode: str = "edit") -> AttackResult:
    if mode == "restore":
        return AttackResult(NAME, GOAL, "200 restored", 200, "restored", detail=restore())
    if mode == "audit":
        detail = tamper_audit()
        ctrl = device_client("ctrl", "ctrl")
        res = ctrl.audit_list(limit=5)
        ok = res.payload.get("chain_ok") if res.ok else None
        return with_evidence(AttackResult(NAME, "Accountability", "chain_ok false", 200,
                                          f"chain_ok {str(ok).lower()}", res.request_id, res.trace_id, detail,
                                          [f"broken at entry #{res.payload.get('chain_broken_at')}" if res.ok else res.summary()],
                                          res.trace))

    if mode == "sheet":
        ensure_sheet()
        detail = edit_sheet()
        student = device_client("student", "s608")
        view = student.view_marks()
        rec = next((r for r in (view.payload or {}).get("records", []) if r["record"]["course"] == "IT301"), None)
        got = student.fetch_attachment("IT301", record=rec["record"] if rec else None)
        ok = got.ok and got.payload.get("verified")
        code = "sheet_invalid" if got.ok and not ok else got.code
        result = AttackResult(NAME, "Integrity, authenticity", "200 sheet_invalid", got.status, code, got.request_id,
                              got.trace_id, detail, [f"student device: SHA-256 of the image "
                                                     f"{'matches' if ok else 'does NOT match'} the teacher-signed hash",
                                                     "undo with: python -m attacks.tamper_db --restore"], got.trace)
        return with_evidence(result)

    ensure_published()
    detail = swap() if mode == "swap" else edit()
    student = device_client("student", "s608")
    view = student.view_marks()
    if mode == "swap":
        result = AttackResult(NAME, GOAL, "500 record_integrity_failed", view.status, view.code, view.request_id,
                              view.trace_id, detail, [view.detail or ""], view.trace)
        return with_evidence(result)

    rec = next((r for r in (view.payload or {}).get("records", []) if r["record"]["course"] == "IT301"), None)
    shown = "Signature invalid" if rec and not rec["verified"] else "Verified" if rec else view.summary()
    result = AttackResult(NAME, GOAL, "200 signature_invalid", view.status,
                          "signature_invalid" if rec and not rec["verified"] else view.code,
                          view.request_id, view.trace_id, detail, [f"student page shows: {shown}"], view.trace)
    if rec:
        result.extra["record"] = {"endsem": rec["record"]["endsem"], "total": rec["record"]["total"],
                                  "sha_ok": rec["sha_ok"], "signature_ok": rec["signature_ok"]}
        ctrl = device_client("ctrl", "ctrl").verify_record(rec["record_id"])
        if ctrl.ok:
            result.notes.append(f"exam controller verify: sha256_ok={ctrl.payload['sha256_ok']} "
                                f"signature_ok={ctrl.payload['signature_ok']} (audited, request {ctrl.request_id[:8]}…)")
            result.extra["ctrl_request_id"] = ctrl.request_id
    result.notes.append("undo with: python -m attacks.tamper_db --restore")
    return with_evidence(result)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--swap", action="store_true")
    g.add_argument("--sheet", action="store_true")
    g.add_argument("--audit", action="store_true")
    g.add_argument("--restore", action="store_true")
    a = ap.parse_args()
    report(run("swap" if a.swap else "sheet" if a.sheet else "audit" if a.audit else "restore" if a.restore else "edit"))


if __name__ == "__main__":
    main()
