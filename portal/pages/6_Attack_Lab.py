"""Attack lab: the security analysis catalogue and its evidence.

Per the PRD cut line, the attacks run as terminal commands (the scripts are
what matter); this page lists them with their expected outcome and shows the
audit evidence the middleware recorded for each refused request.
"""
from __future__ import annotations

import sqlite3
import time

import pandas as pd
import streamlit as st

from attacks import CATALOG
from components.common import esc, page
from middleware.settings import load_settings

page("Attack lab", "🛡️", "Security analysis against the local demo server. Run each command in a terminal (venv active); "
                          "the evidence appears below.")

st.markdown("#### Catalogue")
rows = [{"attack": title, "goal tested": goal, "expected": expected, "command": cli}
        for _key, title, goal, expected, cli in CATALOG]
st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
st.caption("Undo helpers for rehearsals: `python -m attacks.tamper_db --restore` puts the edited record back; "
           "`python scripts\\setup_demo.py --rekey t104` issues a fresh key after a revocation; "
           "`python scripts\\setup_demo.py --reset` (server stopped) gives a clean slate.")

st.divider()
st.markdown("#### Evidence: refused requests in the audit log")
c1, c2, c3 = st.columns([1, 1, 1])
limit = c1.selectbox("Rows", [25, 50, 100, 250], index=1)
device = c2.selectbox("Device", ["(any)", "attacker", "teacher-laptop", "student-laptop", "ctrl-pc", "admin-pc"])
c3.write("")
c3.button("Refresh", use_container_width=True)

db = load_settings().db_path
if not db.exists():
    st.info("No database yet: run `python scripts\\setup_demo.py --reset`.")
    st.stop()
con = sqlite3.connect(f"file:{db.as_posix()}?mode=ro", uri=True)
q = ("SELECT id, ts, request_id, device, src_ip, actor, action, outcome, code, detail FROM audit_log "
     "WHERE outcome != 'allowed'" + (" AND device = ?" if device != "(any)" else "") + " ORDER BY id DESC LIMIT ?")
params = ([device] if device != "(any)" else []) + [int(limit)]
df = pd.read_sql_query(q, con, params=params)
con.close()

if df.empty:
    st.info("No refused requests recorded yet.")
else:
    df["time"] = df.ts.map(lambda t: time.strftime("%H:%M:%S", time.localtime(t)))
    summary = df.groupby("code").size().sort_values(ascending=False)
    cols = st.columns(min(6, len(summary)))
    for col, (code, n) in zip(cols, summary.items()):
        col.metric(code, int(n))
    st.dataframe(df[["id", "time", "device", "src_ip", "actor", "action", "outcome", "code", "request_id", "detail"]],
                 use_container_width=True, hide_index=True, height=420)

    st.markdown("#### Server trace for one request")
    pick = st.selectbox("Audit entry", df.id.tolist(),
                        format_func=lambda i: f"#{i} · {df.set_index('id').loc[i, 'code']} · "
                                              f"{df.set_index('id').loc[i, 'request_id'][:13]}…")
    row = df.set_index("id").loc[pick]
    detail = row.detail or ""
    trace_id = detail.split("[trace ", 1)[1].rstrip("]") if "[trace " in detail else row.request_id
    con = sqlite3.connect(f"file:{db.as_posix()}?mode=ro", uri=True)
    steps = pd.read_sql_query("SELECT step, detail, ok FROM trace_events WHERE request_id = ? ORDER BY id", con,
                              params=[trace_id])
    con.close()
    if steps.empty:
        st.caption("No trace stored for this request (DEMO_MODE=0, or it was refused before tracing began).")
    else:
        steps["result"] = steps.ok.map({1: "PASS", 0: "FAIL"}).fillna("SKIP")
        st.markdown(f"<span class='sm-muted'>trace {esc(trace_id)}</span>", unsafe_allow_html=True)
        st.dataframe(steps[["step", "result", "detail"]], use_container_width=True, hide_index=True)
