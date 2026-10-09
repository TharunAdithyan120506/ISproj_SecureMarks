"""Traffic lab (ISL modules 7 and 4): start/stop captures, analyse saved
.pcapng files with PyShark in a separate process, load them into SQLite and
join them with the audit log. PyShark never runs inside Streamlit."""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

import pandas as pd
import streamlit as st

from components.common import ROOT, esc, page, run_module
from analysis.capture import available_modes, list_captures, status
from analysis.packets import WIRESHARK_DIR

page("Traffic lab", "📡", "Capture → PyShark analyser → PCAP → SQLite join with the audit log.")

OUT = ROOT / "analysis" / "out"

# --- capture -------------------------------------------------------------------------------------------
modes = available_modes()
st.markdown("#### Capture")
m1, m2 = st.columns([1, 1])
m1.markdown(f"**dumpcap** (Npcap loopback): {'✅ ' + esc(modes['dumpcap']) if modes['dumpcap'] else '❌ not installed'}",
            unsafe_allow_html=True)
m2.markdown("**tap** (recording relay fallback): " + ("✅ running on :8000 → server :8001" if modes["tap"]
                                                      else "not running (`python scripts\\run_demo.py --tap`)"))
current = status()
c1, c2, c3 = st.columns([2, 1, 1])
if current:
    c1.success(f"Capturing **{current['name']}** ({current['mode']}) · {current['elapsed_s']} s · {current['bytes']:,} bytes")
    if c2.button("Stop capture", type="primary", use_container_width=True):
        r = run_module("analysis.capture", "stop")
        st.session_state["cap_msg"] = (r.stdout or r.stderr).strip()
        st.rerun()
else:
    name = c1.text_input("Capture name", "exp_live", label_visibility="collapsed")
    if c2.button("Start capture", type="primary", use_container_width=True, disabled=not (modes["dumpcap"] or modes["tap"])):
        r = run_module("analysis.capture", "start", "--name", name)
        st.session_state["cap_msg"] = (r.stdout or r.stderr).strip()
        st.rerun()
if st.session_state.get("cap_msg"):
    st.code(st.session_state["cap_msg"], language=None)

with st.expander("Scripted experiments (run in a terminal, venv active)"):
    st.markdown("""
Each command starts its own capture, drives the traffic from the simulated devices, stops the capture and runs the
analyser (and, for 3 and 4, PCAP → SQLite):

| # | Command | Evidence |
|---|---|---|
| 1 | `python -m analysis.experiments exp1` | marks readable on /plain/*, ciphertext on /api/*; entropy and overhead graphs |
| 2 | `python -m analysis.experiments exp2` (and `exp2_tls`, P1) | password, JWT and headers visible over HTTP; only sizes and timing over TLS |
| 3 | `python -m analysis.experiments exp3` | same request ID twice: 409 replay_detected, then 409 stale_request; audit match in the join |
| 4 | `python -m analysis.experiments exp4` | rate spike, 429s, student latency close to baseline |
| 5 | `python -m analysis.experiments exp5` | five hosts, 403 on the friend attempt, latency per device |
""")

# --- saved captures -------------------------------------------------------------------------------------
st.divider()
st.markdown("#### Saved captures")
caps = [c for c in list_captures() if c["path"].endswith((".pcapng", ".pcap"))]
if not caps:
    st.info("No captures yet. Start one above or run an experiment.")
    st.stop()
labels = {c["name"]: c for c in caps}
sel = st.selectbox("Capture", list(labels), format_func=lambda n: f"{n} · {labels[n]['bytes']:,} B · "
                   f"{time.strftime('%H:%M:%S', time.localtime(labels[n]['modified']))}")
cap = labels[sel]
b1, b2, b3, b4 = st.columns(4)
if b1.button("Run analyser", type="primary", use_container_width=True):
    with st.spinner("python -m analysis.analyze (separate process)…"):
        r = run_module("analysis.analyze", cap["path"], "--json")
    st.session_state["ana_msg"] = r.stderr.strip()[-1500:] if r.returncode else ""
if b2.button("PCAP → SQLite", use_container_width=True):
    with st.spinner("python -m analysis.pcap_to_sqlite…"):
        r = run_module("analysis.pcap_to_sqlite", cap["path"], "--json")
    st.session_state["ana_msg"] = r.stderr.strip()[-1500:] if r.returncode else ""
if b3.button("Export XML", use_container_width=True):
    r = run_module("analysis.pcap_to_xml", cap["path"])
    st.session_state["ana_msg"] = (r.stdout or r.stderr).strip()
if b4.button("Open in Wireshark", use_container_width=True):
    if (WIRESHARK_DIR / "Wireshark.exe").exists() and hasattr(os, "startfile"):
        os.startfile(cap["path"])
    else:
        st.session_state["ana_msg"] = f"Wireshark is not installed; the file is at {cap['path']}"
if st.session_state.get("ana_msg"):
    st.code(st.session_state["ana_msg"], language=None)

out = OUT / Path(cap["path"]).stem
summary_file = out / "summary.json"
if not summary_file.exists():
    st.info("Run the analyser to see results for this capture.")
    st.stop()
s = json.loads(summary_file.read_text(encoding="utf-8"))
k1, k2, k3, k4, k5 = st.columns(5)
k1.metric("Packets", s["packets"])
k2.metric("HTTP requests", s["http_requests"])
k3.metric("Devices", len(s["devices"]))
e = s["entropy_mean"]
k4.metric("Entropy plain ≥1 KB", e["plain_ge_1KB"] if e["plain_ge_1KB"] is not None else "-")
k5.metric("Entropy protected ≥1 KB", e["protected_ge_1KB"] if e["protected_ge_1KB"] is not None else "-")
st.caption(f"engine **{s['engine']}** · devices {s['devices']} · statuses {s['status_counts']} · flags {s['flags']} "
           f"({s['flags_matched_in_audit']} matched in audit, {s['flags_without_audit']} without)")

g1, g2 = st.columns(2)
for col, name in ((g1, "entropy_plain_vs_protected.png"), (g2, "overhead_bytes.png"),
                  (g1, "latency_by_device.png"), (g2, "rate_timeline.png")):
    if (out / name).exists():
        col.image(str(out / name), use_container_width=True)

tabs = st.tabs(["messages.csv", "flows.csv", "flags.csv", "SQL join (audit_join.csv)"])
for tab, name in zip(tabs, ["messages.csv", "flows.csv", "flags.csv", "audit_join.csv"]):
    with tab:
        f = out / name
        if f.exists() and f.stat().st_size > 2:
            try:
                st.dataframe(pd.read_csv(f), use_container_width=True, hide_index=True, height=360)
            except pd.errors.EmptyDataError:
                st.caption("empty")
        else:
            st.caption("Run PCAP → SQLite to build the join." if name == "audit_join.csv" else "empty")
        if name == "audit_join.csv":
            st.code("ATTACH 'data/securemarks.db' AS app;\n"
                    "SELECT m.ts, m.device, m.request_id, m.status, a.action, a.outcome, a.code\n"
                    "FROM http_messages m\nLEFT JOIN app.audit_log a ON a.request_id = m.request_id\n"
                    "WHERE m.flag IN ('replay', 'flood')\nORDER BY m.ts;", language="sql")
