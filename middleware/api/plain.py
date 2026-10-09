"""Unprotected baseline endpoints (DEMO_MODE only): the same marks sent as plain
JSON, so experiment 1 can show readable vs unreadable traffic side by side."""
from __future__ import annotations

from fastapi import APIRouter, Request

from ..errors import ApiError
from ..secure import RequestContext

router = APIRouter()


@router.post("/plain/publish")
async def plain_publish(request: Request):
    ctx = RequestContext(request)
    try:
        body = await request.json()
    except ValueError as exc:
        raise ApiError("bad_request", "body must be JSON") from exc
    records = body.get("records") if isinstance(body, dict) and "records" in body else [body]
    for record in records:
        if not isinstance(record, dict) or "roll_no" not in record:
            raise ApiError("bad_request", "each record needs a roll_no")
        ctx.state.plain_store[str(record["roll_no"])] = record
    ctx.state.tracer.step(ctx.meta.trace_id, "plain_store", f"{len(records)} record(s) stored in plaintext, no checks")
    return ctx.ok_json({"ok": True, "stored": len(records)}, detail=f"{len(records)} plaintext record(s)")


@router.get("/plain/marks/{roll_no}")
def plain_marks(roll_no: str, request: Request):
    ctx = RequestContext(request)
    record = ctx.state.plain_store.get(roll_no)
    if record is None:
        raise ApiError("not_found", f"no plain record for {roll_no}")
    ctx.state.tracer.step(ctx.meta.trace_id, "plain_read", "returned in plaintext, no checks")
    return ctx.ok_json(record, detail=f"plaintext view of {roll_no}")


@router.post("/plain/echo")
async def plain_echo(request: Request):
    """Payload sweep for the entropy/overhead graphs (plain side)."""
    ctx = RequestContext(request)
    body = await request.body()
    return ctx.ok_json({"echo_bytes": len(body)}, audit=False)
