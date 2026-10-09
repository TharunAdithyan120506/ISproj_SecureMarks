"""Admin: key management. Metadata only - key bytes never leave the server."""
from __future__ import annotations

import pandas as pd
import streamlit as st

from components.common import page, require
from components.inspector import render_trace, result_banner

page("Keys", "🗝️", "Admin device. Data keys are stored wrapped by the master key; only teachers' public keys are on the server.")
c = require("admin")

if st.button("Refresh key list") or "keys_last" not in st.session_state:
    st.session_state["keys_last"] = c.keys_list()
kres = st.session_state["keys_last"]

if not kres.ok:
    result_banner(kres)
else:
    left, right = st.columns([1, 1.2])
    with left:
        st.markdown("#### Data keys (AES-256-GCM)")
        st.dataframe(pd.DataFrame(kres.payload["data_keys"]), use_container_width=True, hide_index=True)
    with right:
        st.markdown("#### Signing keys (public halves)")
        st.dataframe(pd.DataFrame(kres.payload["signing_keys"]), use_container_width=True, hide_index=True)

st.divider()
a, b = st.columns(2)
with a:
    st.markdown("#### Revoke a teacher's signing key")
    st.caption("Further publishes by that teacher get 403 key_revoked. Records signed earlier still verify, and the "
               "student view notes the revocation date. Undo for the next rehearsal: `python scripts\\setup_demo.py --rekey t104`.")
    who = st.selectbox("Teacher", ["t104"])
    sure = st.checkbox(f"I understand {who} will not be able to publish until re-keyed")
    if st.button(f"Revoke {who}", type="primary", disabled=not sure):
        st.session_state["admin_last"] = c.revoke_signing(who)
        st.session_state.pop("keys_last", None)
        st.rerun()
with b:
    st.markdown("#### Rotate the data key (P1)")
    st.caption("The new version encrypts new publishes; the old one becomes retired and still decrypts old records.")
    if st.button("Rotate data key"):
        st.session_state["admin_last"] = c.rotate_data_key()
        st.session_state.pop("keys_last", None)
        st.rerun()

last = st.session_state.get("admin_last")
if last is not None:
    st.divider()
    result_banner(last, str(last.payload) if last.ok else "")
    render_trace(last.trace, last.request_id, client=c, trace_id=last.trace_id,
                 related=last.extra.get("related_traces"), role="admin")
