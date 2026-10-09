"""Exam controller: verify a record's hash and signature without ever seeing the
marks, and read the hash-chained audit log (admin can read the log too)."""
from __future__ import annotations

import time

import pandas as pd
import streamlit as st

from components.common import esc, page, pill, require
from components.inspector import render_trace, result_banner

page("Verify and audit", "🔎", "Exam controller device. Verification runs server-side; the marks never reach this screen.")
c = require("ctrl", "admin")

if c.role == "ctrl":
    st.subheader("Verify a record")
    v1, v2 = st.columns([1, 2])
    record_id = v1.number_input("Record ID", min_value=1, value=int(st.session_state.get("verify_id", 1)), step=1)
    v2.caption("Record IDs appear in the teacher's publish result and in the audit log details below.")
    if v1.button("Verify", type="primary"):
        st.session_state["verify_id"] = record_id
        st.session_state["verify_last"] = c.verify_record(int(record_id))
    vres = st.session_state.get("verify_last")
    if vres is not None:
        if vres.ok:
            p = vres.payload
            st.markdown(
                f'<div class="sm-card {"sm-ok" if p["sha256_ok"] and p["signature_ok"] else "sm-bad"}">'
                f'<h4>Record {p["record_id"]} · {esc(p["course"])} · roll {esc(p["roll_no"])} · version {p["version"]}</h4>'
                f'{pill(p["sha256_ok"], "SHA-256 matches" if p["sha256_ok"] else "SHA-256 mismatch")} &nbsp; '
                f'{pill(p["signature_ok"], "signature valid" if p["signature_ok"] else "signature INVALID")} &nbsp; '
                f'<span class="sm-muted">signed by {esc(p["signer"])} ({esc(p["sig_alg"])}, key {esc(p["key_fingerprint"])}, '
                f'{esc(p["key_status"])})</span><div class="sm-muted" style="margin-top:6px">No marks were returned to '
                f'this device: the response carries only booleans and metadata.</div></div>', unsafe_allow_html=True)
        else:
            result_banner(vres)
        with st.expander("Inspector for this verify call"):
            render_trace(vres.trace, vres.request_id, client=c, trace_id=vres.trace_id,
                         related=vres.extra.get("related_traces"), role="ctrl")
    st.divider()

st.subheader("Audit log")
f1, f2, f3, f4 = st.columns([1.2, 1, 1, 1])
action = f1.selectbox("Action", ["(any)", "login", "session_open", "marks_publish", "marks_view", "idor_blocked",
                                 "marks_verify", "audit_list", "keys_list", "keys_rotate", "signing_revoke",
                                 "plain_publish", "plain_view", "demo_echo"])
outcome = f2.selectbox("Outcome", ["(any)", "allowed", "denied", "error"])
limit = f3.selectbox("Rows", [50, 100, 250, 500], index=1)
f4.write("")
if f4.button("Refresh", use_container_width=True) or "audit_last" not in st.session_state:
    filters = {}
    if action != "(any)":
        filters["action"] = action
    if outcome != "(any)":
        filters["outcome"] = outcome
    st.session_state["audit_last"] = c.audit_list(limit=int(limit), **filters)

ares = st.session_state["audit_last"]
if not ares.ok:
    result_banner(ares)
else:
    p = ares.payload
    chain = pill(p["chain_ok"], "hash chain intact" if p["chain_ok"] else f"hash chain BROKEN at entry #{p['chain_broken_at']}")
    st.markdown(f"{chain} <span class='sm-muted'>· entry_hash = SHA-256(prev_hash + canonical entry), recomputed on every "
                f"request</span>", unsafe_allow_html=True)
    df = pd.DataFrame(p["entries"])
    if df.empty:
        st.info("No entries match.")
    else:
        df["time"] = df.ts.map(lambda t: time.strftime("%H:%M:%S", time.localtime(t)))
        df["entry_hash"] = df.entry_hash.str[:12] + "…"
        df["request_id"] = df.request_id.str[:13]
        counts = df.outcome.value_counts()
        m1, m2, m3 = st.columns(3)
        m1.metric("allowed", int(counts.get("allowed", 0)))
        m2.metric("denied", int(counts.get("denied", 0)))
        m3.metric("error", int(counts.get("error", 0)))

        def tint(row):
            color = {"denied": "background-color:#fdf3f3", "error": "background-color:#fbe5e5"}.get(row.outcome, "")
            return [color] * len(row)

        cols = ["id", "time", "device", "src_ip", "actor", "role", "action", "outcome", "code", "request_id", "detail", "entry_hash"]
        st.dataframe(df[cols].style.apply(tint, axis=1), use_container_width=True, hide_index=True, height=460)
