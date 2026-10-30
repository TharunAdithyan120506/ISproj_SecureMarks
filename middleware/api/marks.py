"""Protected marks endpoints: publish (teacher), view (student / teacher),
verify (exam controller, never sees marks), attachment (the answer-sheet image)."""
from __future__ import annotations

import io
import time
from datetime import datetime

from fastapi import APIRouter, Depends

from .. import records
from ..auth.rbac import Principal, require_course, require_own_roll
from ..crypto import sign
from ..crypto.canonical import RecordError, canonical_record
from ..crypto.encoding import b64d, b64e, short
from ..crypto.hashing import sha256, sha256_hex
from ..errors import ApiError
from ..secure import SecureRequest, secure_request

router = APIRouter()

ATTACHMENT_TYPES = {"image/png", "image/jpeg", "image/webp"}
ATTACHMENT_MAX = 600 * 1024  # decoded bytes; the whole encrypted request is also under the policy cap


# --- authorisation callbacks (step 9) -------------------------------------------------

def authorize_publish(p: Principal, payload: dict) -> str:
    record = payload.get("record")
    if not isinstance(record, dict):
        raise ApiError("bad_request", "payload.record must be an object")
    if record.get("teacher") != p.username:
        raise ApiError("forbidden", f"record.teacher must be the caller ({p.username})")
    return require_course(p, str(record.get("course")))


def authorize_view(p: Principal, payload: dict) -> str:
    roll = str(payload.get("roll_no", ""))
    if p.role == "student":
        return require_own_roll(p, roll)
    return f"teacher view limited to own courses {', '.join(p.courses)}"


# --- handlers (run in the thread pool under the 10 s timeout) ----------------------------

def _publish(ctx: SecureRequest) -> dict:
    s, p, payload = ctx.state, ctx.principal, ctx.payload
    try:
        canon = canonical_record(payload["record"])
    except RecordError as exc:
        raise ApiError("bad_request", str(exc)) from exc
    record = payload["record"]
    digest = sha256(canon)
    sig_alg = payload.get("sig_alg")

    with ctx.step("sig_verify") as st:
        required = ctx.policy.signature
        if required != "none" and sig_alg != required:
            raise ApiError("bad_signature", f"policy '{ctx.policy.name}' requires a {required} signature, got {sig_alg}")
        try:
            signature = b64d(payload.get("signature_b64") or "")
        except ValueError as exc:
            raise ApiError("bad_signature", "signature_b64 is not base64") from exc
        if not signature:
            raise ApiError("bad_signature", "missing signature")
        key = s.keys.signing_key(p.username, alg=sig_alg)
        if key is None:
            raise ApiError("bad_signature", f"no registered {sig_alg} key for {p.username}")
        if key.status == "revoked":
            raise ApiError("key_revoked", f"{p.username}'s {key.alg} key {key.fingerprint} was revoked at {key.revoked_at:%Y-%m-%d %H:%M:%S} UTC")
        t0 = time.perf_counter()
        try:
            sign.verify(sig_alg, key.public_key, signature, digest)
        except sign.InvalidSignature as exc:
            raise ApiError("bad_signature", f"{sig_alg} signature does not verify against {p.username}'s key {key.fingerprint}") from exc
        verify_ms = (time.perf_counter() - t0) * 1000
        st.detail = (f"{sig_alg} ✓ over SHA-256 {short(digest)} with {p.username}'s key {key.fingerprint} "
                     f"in {verify_ms:.3f} ms")

    attachment = _check_attachment(ctx, record, payload)

    sign_ms = payload.get("sign_ms")
    sign_ms = round(float(sign_ms), 4) if isinstance(sign_ms, (int, float)) and 0 <= sign_ms < 10_000 else None
    with ctx.step("encrypt_at_rest") as st:
        row, dek_version, dek = records.store(
            s.keys, s.db, record=record, canonical_bytes=canon, signature=signature, signer=p.username,
            sig_alg=sig_alg, key_fingerprint=key.fingerprint, request_id=ctx.meta.request_id,
            sign_ms=sign_ms, verify_ms=round(verify_ms, 4), attachment=attachment)
        st.detail = (f"AES-256-GCM, DEK v{dek_version} {short(dek)}, AAD marks|{row.course}|{row.roll_no} "
                     f"→ {len(row.ciphertext)} B stored as record {row.id} version {row.version}"
                     + (f"; answer sheet {len(attachment['data']):,} B under AAD sheet|{row.course}|{row.roll_no}|"
                        f"{row.version}" if attachment else ""))

    ctx.audit_detail = (f"{row.course}/{row.roll_no} v{row.version} record {row.id} sha256 {row.sha256[:16]}…"
                        + (" + answer sheet" if attachment else ""))
    return {"record_id": row.id, "version": row.version, "sha256": row.sha256, "sign_ms": sign_ms,
            "verify_ms": round(verify_ms, 4), "attachment_bytes": len(attachment["data"]) if attachment else None}


def _check_attachment(ctx: SecureRequest, record: dict, payload: dict) -> dict | None:
    """The image must match the SHA-256 inside the signed record, so it is covered by the signature."""
    want = record.get("attachment_sha256")
    b64 = payload.get("attachment_b64")
    if want is None and not b64:
        return None
    with ctx.step("attachment_check") as st:
        if want is None:
            raise ApiError("attachment_mismatch", "attachment sent but the signed record has no attachment_sha256")
        if not b64:
            raise ApiError("attachment_mismatch", "the signed record names an attachment but none was sent")
        mime = str(payload.get("attachment_mime", ""))
        if mime not in ATTACHMENT_TYPES:
            raise ApiError("bad_request", f"attachment type must be one of {', '.join(sorted(ATTACHMENT_TYPES))}")
        try:
            data = b64d(b64)
        except ValueError as exc:
            raise ApiError("bad_request", "attachment_b64 is not base64") from exc
        if len(data) > ATTACHMENT_MAX:
            raise ApiError("too_large", f"answer sheet is {len(data):,} B; the limit is {ATTACHMENT_MAX:,} B")
        got = sha256_hex(data)
        if got != want:
            raise ApiError("attachment_mismatch", f"image SHA-256 {got[:16]}… differs from the signed {want[:16]}…")
        width, height = _image_size(data)
        st.detail = f"{mime} {len(data):,} B {width}×{height}, SHA-256 {got[:16]}… matches the signed record"
    return {"data": data, "mime": mime, "width": width, "height": height}


def _image_size(data: bytes) -> tuple[int | None, int | None]:
    try:
        from PIL import Image
        with Image.open(io.BytesIO(data)) as img:
            return img.size
    except Exception:  # noqa: BLE001 - size is informational only
        return None, None


def _view(ctx: SecureRequest) -> dict:
    s, p = ctx.state, ctx.principal
    roll = str(ctx.payload.get("roll_no", ""))
    courses = None if p.role == "student" else p.courses
    out = []
    with ctx.step("decrypt_at_rest") as st:
        versions = set()
        marks = records.latest(s.db, roll, courses)
        sheets = records.attachment_meta(s.db, [mk.id for mk in marks])
        for mark in marks:
            record, _canon, dek_version = records.open_record(s.keys, mark)
            versions.add(dek_version)
            key = s.keys.signing_key(mark.signer, fp=mark.key_fingerprint)
            out.append({
                "record_id": mark.id, "version": mark.version, "record": record,
                "signature_b64": b64e(mark.signature), "signer": mark.signer, "sig_alg": mark.sig_alg,
                "sha256": mark.sha256, "key_fingerprint": mark.key_fingerprint,
                "key_status": key.status if key else "unknown",
                "key_revoked_at": key.revoked_at.isoformat() + "Z" if key and key.revoked_at else None,
                "sign_ms": mark.sign_ms, "verify_ms": mark.verify_ms, "attachment": sheets.get(mark.id),
            })
        st.detail = (f"{len(out)} record(s) for roll {roll} decrypted with DEK "
                     f"{', '.join(f'v{v}' for v in sorted(versions)) or '-'} (AAD bound to course|roll)")
    ctx.audit_detail = f"roll {roll}: {len(out)} record(s)"
    return {"records": out}


def _verify(ctx: SecureRequest) -> dict:
    s = ctx.state
    try:
        record_id = int(ctx.payload.get("record_id"))
    except (TypeError, ValueError) as exc:
        raise ApiError("bad_request", "record_id must be an integer") from exc
    mark = records.get(s.db, record_id)
    if mark is None:
        raise ApiError("not_found", f"record {record_id} not found")

    with ctx.step("decrypt_at_rest") as st:
        _record, canon, dek_version = records.open_record(s.keys, mark)
        st.detail = f"record {mark.id} decrypted server-side with DEK v{dek_version}; marks are not returned"
    with ctx.step("sha256_recompute") as st:
        sha_ok = sha256_hex(canon) == mark.sha256
        st.ok = sha_ok
        st.detail = f"recomputed {sha256_hex(canon)[:16]}… vs stored {mark.sha256[:16]}…"
    key = s.keys.signing_key(mark.signer, fp=mark.key_fingerprint)
    with ctx.step("sig_verify") as st:
        sig_ok = False
        if key is not None:
            try:
                sign.verify(mark.sig_alg, key.public_key, mark.signature, sha256(canon))
                sig_ok = True
            except sign.InvalidSignature:
                pass
        st.ok = sig_ok
        st.detail = f"{mark.sig_alg} by {mark.signer} key {mark.key_fingerprint}: {'valid' if sig_ok else 'INVALID'}"

    before_revocation = None
    if key is not None and key.revoked_at is not None:
        published = datetime.fromisoformat(mark.published_at.replace("Z", "+00:00")).replace(tzinfo=None)
        before_revocation = published < key.revoked_at
    ctx.audit_detail = f"record {record_id}: sha256_ok={sha_ok} signature_ok={sig_ok}"
    return {
        "record_id": mark.id, "course": mark.course, "roll_no": mark.roll_no, "version": mark.version,
        "signer": mark.signer, "sig_alg": mark.sig_alg, "key_fingerprint": mark.key_fingerprint,
        "sha256_ok": sha_ok, "signature_ok": sig_ok, "key_status": key.status if key else "unknown",
        "key_revoked_at": key.revoked_at.isoformat() + "Z" if key and key.revoked_at else None,
        "signed_before_revocation": before_revocation, "published_at": mark.published_at,
    }


def authorize_attachment(p: Principal, payload: dict) -> str:
    out = authorize_view(p, payload)
    if p.role == "teacher":
        out = require_course(p, str(payload.get("course", "")))
    return out


def _attachment(ctx: SecureRequest) -> dict:
    s, p = ctx.state, ctx.principal
    roll, course = str(ctx.payload.get("roll_no", "")), str(ctx.payload.get("course", ""))
    marks = [mk for mk in records.latest(s.db, roll, None if p.role == "student" else p.courses) if mk.course == course]
    if not marks:
        raise ApiError("not_found", f"no {course} record for roll {roll}")
    mark = marks[0]
    att = records.attachment_for(s.db, mark.id)
    if att is None:
        raise ApiError("not_found", f"record {mark.id} has no answer sheet")
    with ctx.step("decrypt_attachment") as st:
        data, dek_version = records.open_attachment(s.keys, mark, att)
        st.detail = (f"{len(att.ciphertext):,} B → {len(data):,} B {att.mime} with DEK v{dek_version}, "
                     f"AAD sheet|{mark.course}|{mark.roll_no}|{mark.version}")
    ctx.audit_detail = f"answer sheet {mark.course}/{mark.roll_no} v{mark.version} ({len(data):,} B)"
    return {"record_id": mark.id, "version": mark.version, "course": mark.course, "mime": att.mime,
            "width": att.width, "height": att.height, "size_bytes": len(data), "sha256": att.sha256,
            "image_b64": b64e(data)}


# --- routes -----------------------------------------------------------------------------------

@router.post("/api/marks/publish")
async def publish(ctx: SecureRequest = Depends(secure_request(
        ("teacher",), "confidential", authorize_publish, ("sig_verify", "attachment_check", "encrypt_at_rest")))):
    return await ctx.respond(_publish)


@router.post("/api/marks/attachment")
async def attachment(ctx: SecureRequest = Depends(secure_request(
        ("student", "teacher"), "confidential", authorize_attachment, ("decrypt_attachment",)))):
    return await ctx.respond(_attachment)


@router.post("/api/marks/view")
async def view(ctx: SecureRequest = Depends(secure_request(
        ("student", "teacher"), "confidential", authorize_view, ("decrypt_at_rest",)))):
    return await ctx.respond(_view)


@router.post("/api/marks/verify")
async def verify(ctx: SecureRequest = Depends(secure_request(
        ("ctrl",), "normal", None, ("decrypt_at_rest", "sha256_recompute", "sig_verify")))):
    return await ctx.respond(_verify)
