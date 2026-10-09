"""Session handshake and the public lookups: policies and public keys.

POST /api/session carries only public keys (X25519) or an RSA-OAEP-wrapped
secret (legacy-rsa, P1): a capture of the handshake shows two public keys and
no session key.
"""
from __future__ import annotations

from fastapi import APIRouter, Query, Request
from pydantic import BaseModel

from ..crypto import kex
from ..crypto.encoding import b64d, b64e, short
from ..crypto.sign import fingerprint
from ..errors import ApiError
from ..secure import RequestContext

router = APIRouter()


class SessionIn(BaseModel):
    policy: str
    client_pub_b64: str | None = None
    wrapped_key_b64: str | None = None


@router.post("/api/session")
def open_session(body: SessionIn, request: Request):
    ctx = RequestContext(request, plan=["auth_jwt", "policy_select", "x25519_keypair", "hkdf_derive"])
    state = ctx.state
    principal = ctx.authenticate()

    with ctx.step("policy_select") as st:
        policy = state.policies.get(body.policy)
        if policy is None:
            raise ApiError("bad_request", f"unknown policy '{body.policy}' (have {', '.join(state.policies.names())})")
        st.detail = f"{policy.name}: {policy.cipher}, {policy.key_exchange}, signature {policy.signature}, window {policy.replay_window_s} s"

    session_id = state.sessions.new_id()
    salt = kex.session_salt(session_id)
    response: dict = {"session_id": session_id, "policy": policy.name, "cipher": policy.cipher,
                      "key_exchange": policy.key_exchange, "kdf": "HKDF-SHA256", "key_len": policy.key_len}

    if policy.key_exchange == "X25519":
        with ctx.step("x25519_keypair") as st:
            try:
                client_pub = b64d(body.client_pub_b64 or "")
                if len(client_pub) != 32:
                    raise ValueError
            except ValueError as exc:
                raise ApiError("bad_request", "client_pub_b64 must be a 32-byte X25519 public key") from exc
            priv, server_pub = kex.x25519_keypair()
            shared = kex.x25519_shared(priv, client_pub)
            st.detail = f"server pub {short(server_pub)}, client pub {short(client_pub)}, shared secret {short(shared)}"
        response["server_pub_b64"] = b64e(server_pub)
    else:
        ctx.plan[ctx.plan.index("x25519_keypair")] = "rsa_oaep_unwrap"
        with ctx.step("rsa_oaep_unwrap") as st:
            try:
                wrapped = b64d(body.wrapped_key_b64 or "")
                shared = kex.rsa_unwrap(state.keys.server_rsa(), wrapped)
            except ApiError:
                raise
            except Exception as exc:
                raise ApiError("bad_request", "wrapped_key_b64 must be an RSA-OAEP-2048 wrapped secret") from exc
            st.detail = f"RSA-OAEP-2048 unwrap {len(wrapped)} B → secret {short(shared)}"

    with ctx.step("hkdf_derive") as st:
        key = kex.hkdf_derive(shared, salt, policy.key_len)
        st.detail = f"HKDF-SHA256(salt=session id, info=securemarks/v1/session) → {policy.key_len} B key {short(key)}"

    sess = state.sessions.put(session_id, principal.username, policy.name, key, policy.key_exchange)
    response["expires_in"] = sess.expires_in
    ctx.audit_detail = f"session {session_id[:8]}… {policy.name} {policy.key_exchange}"
    return ctx.ok_json(response)


@router.get("/api/policies")
def get_policies(request: Request):
    ctx = RequestContext(request)
    return ctx.ok_json(ctx.state.policies.raw, audit=False)


@router.get("/api/keys/signing/{username}")
def get_signing_key(username: str, request: Request, alg: str | None = None,
                    fp: str | None = Query(None, alias="fingerprint")):
    ctx = RequestContext(request, plan=["auth_jwt", "key_lookup"])
    ctx.authenticate()
    with ctx.step("key_lookup") as st:
        row = ctx.state.keys.signing_key(username, alg=alg, fp=fp)
        if row is None:
            raise ApiError("not_found", f"no signing key for {username}")
        st.detail = f"{row.alg} key {row.fingerprint} for {username} ({row.status})"
    return ctx.ok_json({
        "username": username, "alg": row.alg, "public_key_b64": b64e(row.public_key), "status": row.status,
        "fingerprint": row.fingerprint, "created_at": row.created_at.isoformat() + "Z",
        "revoked_at": row.revoked_at.isoformat() + "Z" if row.revoked_at else None,
    }, audit=False)


@router.get("/api/keys/server")
def get_server_key(request: Request):
    """P1: the server's RSA-OAEP-2048 public key for legacy-rsa sessions."""
    ctx = RequestContext(request)
    der = ctx.state.keys.server_rsa_public()
    return ctx.ok_json({"alg": "RSA-OAEP-2048", "public_key_b64": b64e(der), "fingerprint": fingerprint(der)}, audit=False)
