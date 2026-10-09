"""Student: view own marks. The SDK decrypts the response, recomputes the
SHA-256 and verifies the teacher's Ed25519 signature end to end - so even a
record edited inside the server's database is caught here."""
from __future__ import annotations

import streamlit as st

from components.common import esc, html_block, page, pill, require
from components.inspector import render_trace, result_banner

page("My marks", "🎓", "Student device. Only your own roll number is ever returned; every record is checked against "
                       "the teacher's signature on this device.")
c = require("student")

top_l, top_r = st.columns([1, 1])
with top_l:
    if st.button("Load my marks", type="primary", use_container_width=True) or "marks_last" not in st.session_state:
        with st.spinner("Decrypting and verifying…"):
            st.session_state["marks_last"] = c.view_marks()
            st.session_state.pop("marks_plain", None)
with top_r:
    if st.button("Also fetch the plain baseline (/plain/marks)", use_container_width=True):
        st.session_state["marks_plain"] = c.plain_view(c.roll_no)

res = st.session_state["marks_last"]
st.markdown(f"Roll **{esc(c.roll_no)}**")
if not res.ok:
    result_banner(res)
else:
    records = res.payload.get("records", [])
    if not records:
        st.info("No marks published for you yet.")
    for r in records:
        rec = r["record"]
        ok = r.get("verified")
        fp = r.get("signer_fingerprint") or r.get("key_fingerprint")
        if ok:
            badge = pill(True, f"Verified · signed by {r['signer']} · {fp}")
        else:
            why = "hash mismatch" if not r.get("sha_ok") else "signature does not match"
            badge = pill(False, f"Signature invalid · {why}")
        revoked = ""
        if r.get("key_status") == "revoked":
            revoked = (f'<div class="sm-muted">⚠ {esc(r["signer"])}\'s key was revoked on {esc(r.get("key_revoked_at"))}; '
                       "this record was signed before the revocation.</div>")
        st.markdown(html_block(f"""
<div class="sm-card {'sm-ok' if ok else 'sm-bad'}">
  <div style="display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap">
    <h4>{esc(rec['course'])}</h4>{badge}
  </div>
  <div style="display:flex;gap:36px;flex-wrap:wrap;margin-top:6px">
    <div><div class="sm-muted">Midsem</div><div class="sm-big">{esc(rec['midsem'])}</div></div>
    <div><div class="sm-muted">Endsem</div><div class="sm-big">{esc(rec['endsem'])}</div></div>
    <div><div class="sm-muted">Total</div><div class="sm-big">{esc(rec['total'])}</div></div>
  </div>
  <div class="sm-muted" style="margin-top:8px">published {esc(rec['published_at'])} by {esc(rec['teacher'])} ·
    version {esc(r['version'])} · record {esc(r['record_id'])} · sha256 {esc(r['sha256'][:16])}…</div>
  {'' if ok else '<div style="margin-top:6px;color:#b42323"><b>Do not trust these numbers:</b> they were changed after the teacher signed them.</div>'}
  {revoked}
</div>"""), unsafe_allow_html=True)

plain = st.session_state.get("marks_plain")
if plain is not None:
    st.markdown(f"Baseline /plain/marks: {pill(plain.ok, f'{plain.status} {plain.code}')}", unsafe_allow_html=True)
    if plain.ok:
        st.json(plain.payload)

st.divider()
st.markdown("#### Try another roll number")
st.caption("Authorisation demo: the roll number travels encrypted, and the server compares it with the roll in your token.")
f1, f2 = st.columns([2, 1])
other = f1.text_input("Roll no", "240911612", label_visibility="collapsed")
if f2.button("View this roll", use_container_width=True):
    with st.spinner("Asking the server…"):
        st.session_state["idor_last"] = c.view_marks(other.strip())
idor = st.session_state.get("idor_last")
if idor is not None:
    result_banner(idor, "returned marks")

st.divider()
shown = idor if idor is not None and st.toggle("Inspect the last 'another roll' request", value=False) else res
render_trace(shown.trace, shown.request_id, client=c, trace_id=shown.trace_id,
             related=shown.extra.get("related_traces"), role="student")
