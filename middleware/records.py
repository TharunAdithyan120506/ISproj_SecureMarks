"""Marks at rest: AES-256-GCM under the active data key, AAD = b"marks|{course}|{roll_no}"
so a ciphertext copied into another student's row no longer decrypts.

Publishing never overwrites: each publish inserts `version + 1`, and views
return the latest version per course. An answer-sheet image, when attached, is
encrypted the same way with AAD = b"sheet|{course}|{roll_no}|{version}", so it
cannot be moved to another student or another version either.
"""
from __future__ import annotations

import json

from sqlalchemy import func, select

from .crypto import aead
from .crypto.hashing import sha256_hex
from .db.models import Attachment, Mark
from .db.session import Database
from .errors import ApiError
from .keys.manager import KeyManager


def marks_aad(course: str, roll_no: str) -> bytes:
    return f"marks|{course}|{roll_no}".encode()


def sheet_aad(course: str, roll_no: str, version: int) -> bytes:
    return f"sheet|{course}|{roll_no}|{version}".encode()


def store(keys: KeyManager, db: Database, *, record: dict, canonical_bytes: bytes, signature: bytes,
          signer: str, sig_alg: str, key_fingerprint: str, request_id: str, sign_ms: float | None = None,
          verify_ms: float | None = None, attachment: dict | None = None) -> tuple[Mark, int, bytes]:
    """Encrypt and insert a new version (and its attachment). Returns (row, dek_version, dek) for the trace.

    `attachment` = {"data": bytes, "mime": str, "width": int, "height": int}.
    """
    dek_row, dek = keys.active_dek()
    nonce, ct = aead.encrypt(dek, canonical_bytes, marks_aad(record["course"], record["roll_no"]))
    with db.session() as s:
        current = s.scalar(select(func.max(Mark.version)).where(
            Mark.course == record["course"], Mark.roll_no == record["roll_no"])) or 0
        row = Mark(course=record["course"], roll_no=record["roll_no"], version=current + 1,
                   ciphertext=ct, nonce=nonce, dek_id=dek_row.id, sha256=sha256_hex(canonical_bytes),
                   signature=signature, signer=signer, sig_alg=sig_alg, key_fingerprint=key_fingerprint,
                   published_at=record["published_at"], request_id=request_id, sign_ms=sign_ms, verify_ms=verify_ms)
        s.add(row)
        s.flush()
        if attachment is not None:
            data = attachment["data"]
            a_nonce, a_ct = aead.encrypt(dek, data, sheet_aad(row.course, row.roll_no, row.version))
            s.add(Attachment(mark_id=row.id, mime=attachment["mime"], size_bytes=len(data),
                             width=attachment.get("width"), height=attachment.get("height"), sha256=sha256_hex(data),
                             ciphertext=a_ct, nonce=a_nonce, dek_id=dek_row.id))
    return row, dek_row.version, dek


def latest(db: Database, roll_no: str, courses: tuple[str, ...] | None = None) -> list[Mark]:
    """Latest version of each course's record for one roll number."""
    with db.session() as s:
        sub = select(Mark.course, func.max(Mark.version).label("v")).where(Mark.roll_no == roll_no)
        if courses is not None:
            sub = sub.where(Mark.course.in_(courses))
        sub = sub.group_by(Mark.course).subquery()
        q = select(Mark).join(sub, (Mark.course == sub.c.course) & (Mark.version == sub.c.v)).where(
            Mark.roll_no == roll_no).order_by(Mark.course)
        return list(s.scalars(q))


def get(db: Database, record_id: int) -> Mark | None:
    with db.session() as s:
        return s.get(Mark, record_id)


def attachment_for(db: Database, mark_id: int) -> Attachment | None:
    with db.session() as s:
        return s.scalar(select(Attachment).where(Attachment.mark_id == mark_id))


def attachment_meta(db: Database, mark_ids: list[int]) -> dict[int, dict]:
    """Size, type and hash of attachments (never the bytes), keyed by mark id."""
    if not mark_ids:
        return {}
    with db.session() as s:
        rows = s.scalars(select(Attachment).where(Attachment.mark_id.in_(mark_ids)))
        return {a.mark_id: {"mime": a.mime, "size_bytes": a.size_bytes, "width": a.width, "height": a.height,
                            "sha256": a.sha256, "ciphertext_bytes": len(a.ciphertext)} for a in rows}


def open_record(keys: KeyManager, mark: Mark) -> tuple[dict, bytes, int]:
    """Decrypt one row. Returns (record, canonical bytes, dek version)."""
    dek_row, dek = keys.dek_for(mark.dek_id)
    try:
        plain = aead.decrypt(dek, mark.nonce, mark.ciphertext, marks_aad(mark.course, mark.roll_no))
    except aead.InvalidTag as exc:
        raise ApiError("record_integrity_failed",
                       f"record {mark.id} ({mark.course}/{mark.roll_no}) failed AES-GCM check at rest "
                       "(ciphertext edited or swapped from another row)") from exc
    return json.loads(plain), plain, dek_row.version


def open_attachment(keys: KeyManager, mark: Mark, att: Attachment) -> tuple[bytes, int]:
    """Decrypt an answer sheet. Returns (image bytes, dek version)."""
    dek_row, dek = keys.dek_for(att.dek_id)
    try:
        data = aead.decrypt(dek, att.nonce, att.ciphertext, sheet_aad(mark.course, mark.roll_no, mark.version))
    except aead.InvalidTag as exc:
        raise ApiError("record_integrity_failed",
                       f"answer sheet of record {mark.id} failed AES-GCM check at rest "
                       "(ciphertext edited or swapped from another row)") from exc
    return data, dek_row.version
