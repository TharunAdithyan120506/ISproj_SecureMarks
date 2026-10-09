"""The inspector: one table that merges the SDK's client-side steps with the
server's steps (GET /demo/trace/{id}) for a single call, in time order.

    render_trace(client_steps, request_id, client=..., trace_id=..., related=[...])
"""
from __future__ import annotations

import streamlit as st

from .common import esc, pill

SIDE_LABEL = {"teacher": "Teacher SDK", "student": "Student SDK", "ctrl": "Controller SDK", "admin": "Admin SDK"}
MAX_VALUE = 140


def _value(detail: str) -> str:
    d = detail or ""
    short = d if len(d) <= MAX_VALUE else d[: MAX_VALUE - 1] + "…"
    return f'<span title="{esc(d)}">{esc(short)}</span>'


def merged_steps(client_steps: list[dict], client=None, trace_id: str | None = None,
                 related: list[str] | None = None, server_steps: list[dict] | None = None) -> list[dict]:
    steps = [dict(s, side=s.get("side", "client")) for s in client_steps]
    if server_steps is None and client is not None:
        server_steps = []
        for tid in [*(related or []), trace_id]:
            if tid:
                server_steps += client.server_trace(tid)
    steps += [dict(s, side="server") for s in (server_steps or [])]
    return sorted(steps, key=lambda s: s.get("ts") or 0)


def render_trace(client_steps: list[dict], request_id: str | None, client=None, trace_id: str | None = None,
                 related: list[str] | None = None, server_steps: list[dict] | None = None,
                 role: str | None = None, title: str = "Inspector") -> None:
    steps = merged_steps(client_steps, client, trace_id or request_id, related, server_steps)
    n_server = sum(1 for s in steps if s["side"] == "server")
    fails = sum(1 for s in steps if s.get("ok") is False)
    st.markdown(f"#### {esc(title)}")
    st.caption(f"request ID `{request_id or '-'}` · {len(steps) - n_server} client steps · {n_server} server steps"
               + (f" · {fails} failed" if fails else "")
               + " · keys shown as first 4 … last 4 bytes")
    if not steps:
        st.info("No steps recorded.")
        return
    side_client = SIDE_LABEL.get(role or (client.role if client else ""), "Client SDK")
    t0 = steps[0].get("ts") or 0
    rows = []
    for i, s in enumerate(steps, 1):
        side = s["side"]
        chip = (f'<span class="sm-side sm-side-server">Server</span>' if side == "server"
                else f'<span class="sm-side sm-side-client">{esc(side_client)}</span>')
        ok = s.get("ok")
        ok = None if ok is None else bool(ok)
        dt = ((s.get("ts") or t0) - t0) * 1000
        rows.append(f'<tr class="{"fail" if ok is False else ""}"><td class="sm-muted">{i}</td><td>{chip}</td>'
                    f'<td class="step">{esc(s["step"])}</td><td class="val">{_value(s.get("detail"))}</td>'
                    f'<td class="sm-muted">{dt:,.1f} ms</td><td>{pill(ok)}</td></tr>')
    st.markdown('<div class="sm-group"><table class="sm-trace"><thead><tr><th>#</th><th>Side</th><th>Step</th>'
                '<th>Value</th><th>t+</th><th>Result</th></tr></thead><tbody>' + "".join(rows) + "</tbody></table></div>",
                unsafe_allow_html=True)


def result_banner(res, ok_text: str = "Success") -> None:
    """One-line outcome of a call: status pill, code, detail, latency."""
    if res.ok:
        st.markdown(f'{pill(True, f"{res.status} OK")} &nbsp; {esc(ok_text)} '
                    f'<span class="sm-muted">· {res.elapsed_ms:.1f} ms · request {esc(res.request_id[:8])}…</span>',
                    unsafe_allow_html=True)
    else:
        st.markdown(f'{pill(False, f"{res.status} {res.code}")} &nbsp; {esc(res.detail or "")} '
                    f'<span class="sm-muted">· request {esc((res.request_id or "")[:8])}…</span>',
                    unsafe_allow_html=True)
