"""Protected marks endpoints: publish (teacher), view (student / teacher),
verify (exam controller, never sees marks)."""
from __future__ import annotations

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
        try:
            sign.verify(sig_alg, key.public_key, signature, digest)
        except sign.InvalidSignature as exc:
            raise ApiError("bad_signature", f"{sig_alg} signature does not verify against {p.username}'s key {key.fingerprint}") from exc
        st.detail = f"{sig_alg} ✓ over SHA-256 {short(digest)} with {p.username}'s key {key.fingerprint}"

    with ctx.step("encrypt_at_rest") as st:
        row, dek_version, dek = records.store(
            s.keys, s.db, record=record, canonical_bytes=canon, signature=signature, signer=p.username,
            sig_alg=sig_alg, key_fingerprint=key.fingerprint, request_id=ctx.meta.request_id)
        st.detail = (f"AES-256-GCM, DEK v{dek_version} {short(dek)}, AAD marks|{row.course}|{row.roll_no} "
                     f"→ {len(row.ciphertext)} B stored as record {row.id} version {row.version}")

    ctx.audit_detail = f"{row.course}/{row.roll_no} v{row.version} record {row.id} sha256 {row.sha256[:16]}…"
    return {"record_id": row.id, "version": row.version, "sha256": row.sha256}


def _view(ctx: SecureRequest) -> dict:
    s, p = ctx.state, ctx.principal
    roll = str(ctx.payload.get("roll_no", ""))
    courses = None if p.role == "student" else p.courses
    out = []
    with ctx.step("decrypt_at_rest") as st:
        versions = set()
        for mark in records.latest(s.db, roll, courses):
            record, _canon, dek_version = records.open_record(s.keys, mark)
            versions.add(dek_version)
            key = s.keys.signing_key(mark.signer, fp=mark.key_fingerprint)
            out.append({
                "record_id": mark.id, "version": mark.version, "record": record,
                "signature_b64": b64e(mark.signature), "signer": mark.signer, "sig_alg": mark.sig_alg,
                "sha256": mark.sha256, "key_fingerprint": mark.key_fingerprint,
                "key_status": key.status if key else "unknown",
                "key_revoked_at": key.revoked_at.isoformat() + "Z" if key and key.revoked_at else None,
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


# --- routes -----------------------------------------------------------------------------------

@router.post("/api/marks/publish")
async def publish(ctx: SecureRequest = Depends(secure_request(
        ("teacher",), "confidential", authorize_publish, ("sig_verify", "encrypt_at_rest")))):
    return await ctx.respond(_publish)


@router.post("/api/marks/view")
async def view(ctx: SecureRequest = Depends(secure_request(
        ("student", "teacher"), "confidential", authorize_view, ("decrypt_at_rest",)))):
    return await ctx.respond(_view)


@router.post("/api/marks/verify")
async def verify(ctx: SecureRequest = Depends(secure_request(
        ("ctrl",), "normal", None, ("decrypt_at_rest", "sha256_recompute", "sig_verify")))):
    return await ctx.respond(_verify)
