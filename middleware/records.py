"""Marks at rest: AES-256-GCM under the active data key, AAD = b"marks|{course}|{roll_no}"
so a ciphertext copied into another student's row no longer decrypts.

Publishing never overwrites: each publish inserts `version + 1`, and views
return the latest version per course.
"""
from __future__ import annotations

import json

from sqlalchemy import func, select

from .crypto import aead
from .crypto.hashing import sha256_hex
from .db.models import Mark
from .db.session import Database
from .errors import ApiError
from .keys.manager import KeyManager


def marks_aad(course: str, roll_no: str) -> bytes:
    return f"marks|{course}|{roll_no}".encode()


def store(keys: KeyManager, db: Database, *, record: dict, canonical_bytes: bytes, signature: bytes,
          signer: str, sig_alg: str, key_fingerprint: str, request_id: str) -> tuple[Mark, int, bytes]:
    """Encrypt and insert a new version. Returns (row, dek_version, dek) for the trace."""
    dek_row, dek = keys.active_dek()
    nonce, ct = aead.encrypt(dek, canonical_bytes, marks_aad(record["course"], record["roll_no"]))
    with db.session() as s:
        current = s.scalar(select(func.max(Mark.version)).where(
            Mark.course == record["course"], Mark.roll_no == record["roll_no"])) or 0
        row = Mark(course=record["course"], roll_no=record["roll_no"], version=current + 1,
                   ciphertext=ct, nonce=nonce, dek_id=dek_row.id, sha256=sha256_hex(canonical_bytes),
                   signature=signature, signer=signer, sig_alg=sig_alg, key_fingerprint=key_fingerprint,
                   published_at=record["published_at"], request_id=request_id)
        s.add(row)
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
