"""POST /api/auth/login - plain JSON on purpose: over HTTP the password is
visible in Wireshark, which is the finding of the HTTP vs TLS experiment."""
from __future__ import annotations

import time

from fastapi import APIRouter, Request
from pydantic import BaseModel
from sqlalchemy import select

from ..auth import tokens
from ..auth.passwords import verify_password
from ..db.models import User
from ..errors import ApiError
from ..secure import RequestContext

router = APIRouter()


class LoginIn(BaseModel):
    username: str
    password: str


@router.post("/api/auth/login")
def login(body: LoginIn, request: Request):
    ctx = RequestContext(request, plan=["argon2_verify", "jwt_issue"])
    state = ctx.state
    ctx.meta.actor = body.username  # the claimed identity, for the audit row

    with ctx.step("argon2_verify") as st:
        with state.db.session() as s:
            user = s.scalars(select(User).where(User.username == body.username)).first()
        t0 = time.perf_counter()
        ok = verify_password(user.pw_hash if user else None, body.password)
        ms = (time.perf_counter() - t0) * 1000
        if not ok:
            raise ApiError("auth_failed", f"wrong username or password (Argon2id verify {ms:.0f} ms)")
        ctx.meta.role = user.role
        st.detail = f"Argon2id ✓ for {user.username} ({ms:.0f} ms)"

    with ctx.step("jwt_issue") as st:
        token = tokens.issue(state.settings.jwt_secret, username=user.username, role=user.role,
                             roll_no=user.roll_no, courses=user.course_list, ttl_s=state.settings.jwt_ttl_s)
        st.detail = f"HS256 JWT for {user.username} ({user.role}), expires in {state.settings.jwt_ttl_s} s"

    return ctx.ok_json({
        "token": token, "role": user.role, "roll_no": user.roll_no, "courses": user.course_list,
        "expires_in": state.settings.jwt_ttl_s,
    }, detail=f"login as {user.role}")
