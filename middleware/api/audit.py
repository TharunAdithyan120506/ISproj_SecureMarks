"""POST /api/audit/list - exam controller and admin. Returns entries plus
`chain_ok`, recomputed over the whole hash chain (P1)."""
from __future__ import annotations

from fastapi import APIRouter, Depends

from ..secure import SecureRequest, secure_request

router = APIRouter()


def _list(ctx: SecureRequest) -> dict:
    p = ctx.payload
    with ctx.step("audit_query") as st:
        entries = ctx.state.audit.list(limit=int(p.get("limit", 100)), since_id=int(p.get("since_id", 0)),
                                       action=p.get("action") or None, outcome=p.get("outcome") or None,
                                       request_id=p.get("request_id") or None)
        st.detail = f"{len(entries)} entries"
    with ctx.step("audit_chain_verify") as st:
        ok, broken_at = ctx.state.audit.verify_chain()
        st.ok = ok
        st.detail = "hash chain intact" if ok else f"hash chain broken at entry #{broken_at}"
    return {"entries": entries, "chain_ok": ok, "chain_broken_at": broken_at}


@router.post("/api/audit/list")
async def audit_list(ctx: SecureRequest = Depends(secure_request(
        ("ctrl", "admin"), "normal", None, ("audit_query", "audit_chain_verify")))):
    return await ctx.respond(_list)
