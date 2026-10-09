"""Admin key management (protected, policy `normal`). Metadata only: no key bytes
ever leave the server."""
from __future__ import annotations

from fastapi import APIRouter, Depends

from ..errors import ApiError
from ..secure import SecureRequest, secure_request

router = APIRouter()


def _list(ctx: SecureRequest) -> dict:
    with ctx.step("keys_list") as st:
        keys = ctx.state.keys.list_keys()
        st.detail = f"{len(keys['data_keys'])} data key(s), {len(keys['signing_keys'])} signing key(s)"
    return keys


def _rotate(ctx: SecureRequest) -> dict:
    with ctx.step("dek_rotate") as st:
        version = ctx.state.keys.rotate()
        st.detail = f"data key v{version} active; previous version retired (still decrypts old records)"
    ctx.audit_detail = f"data key rotated to v{version}"
    return {"new_version": version}


def _revoke(ctx: SecureRequest) -> dict:
    username = str(ctx.payload.get("username", ""))
    with ctx.step("signing_revoke") as st:
        n = ctx.state.keys.revoke_signing(username)
        if n == 0:
            raise ApiError("not_found", f"no active signing key for '{username}'")
        st.detail = f"{n} key(s) of {username} revoked; earlier records still verify"
    ctx.audit_detail = f"revoked {n} signing key(s) of {username}"
    return {"status": "revoked", "username": username, "keys_revoked": n}


@router.post("/api/admin/keys/list")
async def keys_list(ctx: SecureRequest = Depends(secure_request(("admin",), "normal", None, ("keys_list",)))):
    return await ctx.respond(_list)


@router.post("/api/admin/keys/rotate")
async def keys_rotate(ctx: SecureRequest = Depends(secure_request(("admin",), "normal", None, ("dek_rotate",)))):
    return await ctx.respond(_rotate)


@router.post("/api/admin/signing/revoke")
async def signing_revoke(ctx: SecureRequest = Depends(secure_request(("admin",), "normal", None, ("signing_revoke",)))):
    return await ctx.respond(_revoke)
