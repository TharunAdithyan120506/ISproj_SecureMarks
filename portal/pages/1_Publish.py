"""Teacher: publish marks. The SDK builds the record, hashes and signs it,
opens an X25519 session and sends AES-GCM ciphertext; the inspector shows every
client and server step with real values."""
from __future__ import annotations

import json

import streamlit as st

from components.common import ROOT, esc, html_block, page, pill, require
from components.inspector import render_trace
from middleware.crypto.canonical import ENDSEM_MAX, MIDSEM_MAX, build_record

page("Publish marks", "📝", "Teacher device. The record is signed with your Ed25519 key, which never leaves this device.")
c = require("teacher")
key = st.session_state.get("signing_key")

with st.form("publish"):
    a, b, m1, m2 = st.columns([1, 1.3, 1, 1])
    course = a.selectbox("Course", c.courses or ["IT301"])
    roll = b.text_input("Roll no", "240911608")
    midsem = m1.number_input(f"Midsem (/{MIDSEM_MAX})", 0, MIDSEM_MAX, 27)
    endsem = m2.number_input(f"Endsem (/{ENDSEM_MAX})", 0, ENDSEM_MAX, 45)
    o1, o2 = st.columns([1, 1])
    policy = o1.selectbox("Policy", ["confidential", "legacy-rsa (P1: RSA-OAEP + RSA-PSS)"],
                          help="confidential = X25519 + AES-256-GCM + Ed25519. legacy-rsa is the comparison policy.")
    baseline = o2.toggle("Also send the same record to /plain/publish (baseline for experiment 1)", value=False)
    go = st.form_submit_button("Sign and publish", type="primary", use_container_width=True)

if go:
    legacy = policy.startswith("legacy")
    signing_key = st.session_state.get("signing_key_rsa") if legacy else key
    with st.spinner("Signing, encrypting, sending…"):
        record = build_record(course, roll.strip(), int(midsem), int(endsem), teacher=c.username)
        res = c.publish_marks(signing_key, course, roll.strip(), int(midsem), int(endsem), record=record,
                              policy="legacy-rsa" if legacy else None)
        plain = c.plain_publish(record) if baseline else None
    st.session_state["publish_last"] = {"res": res, "plain": plain, "record": record}

last = st.session_state.get("publish_last")
if last:
    res, plain = last["res"], last["plain"]
    st.divider()
    left, right = st.columns([1.1, 1])
    with left:
        st.markdown("#### Result")
        if res.ok:
            p = res.payload
            st.markdown(html_block(f"""
                <div class="sm-card sm-ok">
                  <div style="display:flex;justify-content:space-between;align-items:center;gap:10px">
                    <div style="font-size:1.25rem;font-weight:600;letter-spacing:-.01em">Published</div>{pill(True, '200 OK')}</div>
                  <div class="sm-muted" style="margin-top:4px">Record {p['record_id']} · version {p['version']} · stored as
                    AES-256-GCM ciphertext · {res.elapsed_ms:.1f} ms</div>
                  <div class="sm-mono" style="margin-top:10px;color:#3A3A3C;word-break:break-all">SHA-256 {esc(p['sha256'])}</div>
                </div>"""), unsafe_allow_html=True)
        else:
            st.markdown(html_block(f"""
                <div class="sm-card sm-bad">
                  <div style="display:flex;justify-content:space-between;align-items:center;gap:10px">
                    <div style="font-size:1.25rem;font-weight:600;letter-spacing:-.01em">Refused</div>
                    {pill(False, f'{res.status} {res.code}')}</div>
                  <div class="sm-muted" style="margin-top:4px">{esc(res.detail or '')}</div>
                </div>"""), unsafe_allow_html=True)
        if plain is not None:
            st.markdown(f'Baseline /plain/publish: {pill(plain.ok, f"{plain.status} {plain.code}")} '
                        f'<span class="sm-muted">the same marks, readable by anyone on the wire</span>',
                        unsafe_allow_html=True)
    with right:
        st.markdown("#### On the wire")
        meta_file, raw_file = ROOT / "captures" / "last_request.json", ROOT / "captures" / "last_request.bin"
        shown = False
        if meta_file.exists() and raw_file.exists():
            meta = json.loads(meta_file.read_text(encoding="utf-8"))
            if meta.get("request_id") == res.request_id:
                raw = raw_file.read_bytes()
                head, _, body = raw.partition(b"\r\n\r\n")
                lines = head.decode("latin-1").split("\r\n")
                lines = [ln if not ln.lower().startswith("authorization") else ln[:40] + "…" for ln in lines]
                st.code("\n".join(lines) + f"\n\n<{len(body)} bytes of AES-GCM ciphertext>\n" + body[:96].hex(" ", 4),
                        language="http")
                shown = True
        if not shown:
            st.caption("The raw request is saved to captures\\last_request.bin in demo mode (used by the replay attack).")
        if plain is not None:
            st.caption("…and the baseline request body, as Wireshark would show it:")
            st.code(json.dumps(last["record"], indent=None), language="json")
    render_trace(res.trace, res.request_id, client=c, trace_id=res.trace_id,
                 related=res.extra.get("related_traces"), role="teacher")
else:
    st.info("Fill in the form to publish. Then open the student window (s608) and load **My marks**.")
