"""Marks portal: sign in, publish (with answer sheet), my marks, verify, audit, keys."""
from __future__ import annotations

import base64
import io
import json
import time

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from fastapi.responses import Response
from pydantic import BaseModel

from middleware.crypto.canonical import ENDSEM_MAX, MIDSEM_MAX, build_record
from middleware.crypto.hashing import sha256_hex
from sdk.client import SecureClient, load_accounts

from .present import call_json, wire_json
from .sessions import ROLE_LABEL, PortalSession, get_session, login, require

router = APIRouter(prefix="/api")

SHEET_MAX_SIDE = 1600
SHEET_MAX_BYTES = 350 * 1024


# --- session ------------------------------------------------------------------------------------

class LoginBody(BaseModel):
    username: str
    password: str


@router.get("/accounts")
def accounts():
    out = []
    for name, a in load_accounts().items():
        out.append({"username": name, "password": a["password"], "role": a["role"], "label": ROLE_LABEL[a["role"]],
                    "detail": a.get("roll_no") or ", ".join(a.get("courses", []))})
    return out


@router.post("/login")
def do_login(body: LoginBody, s: PortalSession = Depends(get_session)):
    with s.lock:
        ok, msg = login(s, body.username.strip(), body.password)
    if not ok:
        raise HTTPException(401, msg)
    return s.me()


@router.post("/logout")
def do_logout(s: PortalSession = Depends(get_session)):
    with s.lock:
        s.logout()
    return {"ok": True}


@router.get("/me")
def me(s: PortalSession = Depends(get_session)):
    return {"user": s.me()}


_health_cache: dict = {"t": 0.0, "v": None}


@router.get("/health")
def health():
    if time.time() - _health_cache["t"] > 2:
        c = SecureClient(device_label="portal-health", save_last_request=False)
        try:
            _health_cache.update(t=time.time(), v=c.health())
        finally:
            c.close()
    return {"middleware": _health_cache["v"], "portal": True}


# --- teacher -------------------------------------------------------------------------------------

def _prepare_sheet(raw: bytes, filename: str) -> tuple[bytes, str, dict]:
    """Downscale large photos so the encrypted request stays under the policy cap."""
    from PIL import Image, UnidentifiedImageError
    try:
        img = Image.open(io.BytesIO(raw))
        img.load()
    except (UnidentifiedImageError, OSError) as exc:
        raise HTTPException(400, f"{filename or 'file'} is not an image") from exc
    original = {"bytes": len(raw), "width": img.width, "height": img.height, "format": img.format}
    if len(raw) <= SHEET_MAX_BYTES and img.format in ("PNG", "JPEG", "WEBP") and max(img.size) <= SHEET_MAX_SIDE:
        return raw, Image.MIME[img.format], original
    img = img.convert("RGB")
    img.thumbnail((SHEET_MAX_SIDE, SHEET_MAX_SIDE))
    for q in (88, 80, 72, 64, 55):
        buf = io.BytesIO()
        img.save(buf, format="JPEG", quality=q, optimize=True)
        if buf.tell() <= SHEET_MAX_BYTES:
            break
    return buf.getvalue(), "image/jpeg", original


@router.post("/publish")
async def publish(course: str = Form(...), roll_no: str = Form(...), midsem: int = Form(...), endsem: int = Form(...),
                  policy: str = Form("confidential"), baseline: bool = Form(False),
                  sheet: UploadFile | None = File(None), s: PortalSession = Depends(get_session)):
    c = require(s, "teacher")
    if not (0 <= midsem <= MIDSEM_MAX and 0 <= endsem <= ENDSEM_MAX):
        raise HTTPException(400, f"midsem 0-{MIDSEM_MAX}, endsem 0-{ENDSEM_MAX}")
    legacy = policy == "legacy-rsa"
    key = s.signing_key_rsa if legacy else s.signing_key
    att, mime, original = None, "image/png", None
    if sheet is not None and sheet.filename:
        att, mime, original = _prepare_sheet(await sheet.read(), sheet.filename)
    record = build_record(course, roll_no.strip(), midsem, endsem, teacher=c.username,
                          attachment_sha256=sha256_hex(att) if att else None)

    def work():
        with s.lock:
            res = c.publish_marks(key, course, roll_no.strip(), midsem, endsem, record=record,
                                  policy="legacy-rsa" if legacy else None, attachment=att, attachment_mime=mime)
            plain = c.plain_publish({k: v for k, v in record.items() if k != "attachment_sha256"}) if baseline else None
            out = call_json(res, c)
            s.last["publish"] = res
            return res, plain, out

    from starlette.concurrency import run_in_threadpool
    res, plain, out = await run_in_threadpool(work)
    out.update(record=record, sign_ms=res.extra.get("sign_ms"), signature_hex=res.extra.get("signature_hex"),
               sheet={"bytes": len(att), "mime": mime, "original": original, "sha256": sha256_hex(att)} if att else None,
               baseline={"status": plain.status, "code": plain.code, "body": record} if plain else None)
    return out


@router.get("/wire/{name}")
def download_wire(name: str, s: PortalSession = Depends(get_session)):
    """Full ciphertext envelope of the last protected call of that kind, as a JSON file."""
    res = s.last.get(name)
    if res is None:
        raise HTTPException(404, "nothing captured yet")
    data = json.dumps(wire_json(res, full=True), indent=2)
    return Response(data, media_type="application/json",
                    headers={"Content-Disposition": f'attachment; filename="securemarks_{name}_{res.request_id[:8]}.json"'})


# --- student ---------------------------------------------------------------------------------------

@router.post("/marks")
def my_marks(body: dict | None = None, s: PortalSession = Depends(get_session)):
    c = require(s, "student", "teacher")
    roll = str((body or {}).get("roll_no") or c.roll_no or "")
    with s.lock:
        res = c.view_marks(roll)
        s.last["view"] = res
        return call_json(res, c)


@router.post("/marks/plain")
def plain_marks(s: PortalSession = Depends(get_session)):
    c = require(s, "student")
    res = c.plain_view(c.roll_no)
    return {"status": res.status, "code": res.code, "payload": res.payload}


@router.post("/marks/sheet")
def sheet(body: dict, s: PortalSession = Depends(get_session)):
    c = require(s, "student", "teacher")
    with s.lock:
        view = c.view_marks(str(body.get("roll_no") or c.roll_no))
        rec = next((r for r in (view.payload or {}).get("records", []) if r["record"]["course"] == body.get("course")),
                   None)
        res = c.fetch_attachment(str(body.get("course")), str(body.get("roll_no") or c.roll_no),
                                 record=rec["record"] if rec else None)
        s.last["sheet"] = res
        out = call_json(res, c)
    if res.ok:
        p = out["payload"]
        out["image"] = f"data:{p['mime']};base64,{p.pop('image_b64')}"
    return out


# --- exam controller / admin -----------------------------------------------------------------------

@router.post("/verify")
def verify(body: dict, s: PortalSession = Depends(get_session)):
    c = require(s, "ctrl")
    with s.lock:
        return call_json(c.verify_record(int(body.get("record_id", 0))), c)


@router.post("/audit")
def audit(body: dict | None = None, s: PortalSession = Depends(get_session)):
    c = require(s, "ctrl", "admin")
    b = body or {}
    filters = {k: b[k] for k in ("action", "outcome", "actor", "device") if b.get(k)}
    with s.lock:
        return call_json(c.audit_list(limit=int(b.get("limit", 100)), **filters), c, steps=False)


@router.post("/keys")
def keys(s: PortalSession = Depends(get_session)):
    c = require(s, "admin")
    with s.lock:
        return call_json(c.keys_list(), c, steps=False)


@router.post("/keys/rotate")
def rotate(s: PortalSession = Depends(get_session)):
    c = require(s, "admin")
    with s.lock:
        return call_json(c.rotate_data_key(), c)


@router.post("/keys/revoke")
def revoke(body: dict, s: PortalSession = Depends(get_session)):
    c = require(s, "admin")
    with s.lock:
        return call_json(c.revoke_signing(str(body.get("username", "t104"))), c)


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()
