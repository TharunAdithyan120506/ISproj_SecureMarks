"""Demo-only helpers (DEMO_MODE=1): trace lookup for the inspector and a
protected echo used by the payload sweep and the round-trip test."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from ..auth import tokens
from ..errors import ApiError
from ..secure import SecureRequest, secure_request

router = APIRouter()


@router.get("/demo/trace/{request_id}")
def demo_trace(request_id: str, request: Request):
    state = request.app.state.sm
    token = tokens.bearer(request.headers.get("authorization"))
    try:
        tokens.verify(state.settings.jwt_secret, token or "")
    except tokens.TokenError as exc:
        raise ApiError("auth_failed", str(exc)) from exc
    return {"request_id": request_id, "steps": state.tracer.get(request_id)}


def _echo(ctx: SecureRequest) -> dict:
    data = ctx.payload.get("data")
    with ctx.step("echo") as st:
        st.detail = f"echoing {len(str(data))} chars"
    return {"echo": data}


@router.post("/demo/echo")
async def demo_echo(ctx: SecureRequest = Depends(secure_request(
        ("teacher", "student", "ctrl", "admin"), "normal", None, ("echo",)))):
    return await ctx.respond(_echo)
