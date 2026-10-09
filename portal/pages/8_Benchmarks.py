"""Efficiency analysis: run the quick benchmark and read the goal matrix off it."""
from __future__ import annotations

import json

import pandas as pd
import streamlit as st

from components.common import ROOT, page, stream_module

page("Benchmarks", "⏱️", "Every algorithm across payload sizes, the middleware's per-check cost and end-to-end latency.")

OUT = ROOT / "bench" / "out"
c1, c2 = st.columns([1, 3])
if c1.button("Run quick benchmark (~30-60 s)", type="primary", use_container_width=True):
    box = c2.empty()
    with st.spinner("python -m bench.bench --quick"):
        code, _ = stream_module("bench.bench", "--quick", placeholder=box)
    if code != 0:
        st.error("The benchmark failed; see the output above.")

results = OUT / "results.csv"
if not results.exists():
    st.info("No results yet: run the quick benchmark.")
    st.stop()
df = pd.read_csv(results)
meta = json.loads((OUT / "results.json").read_text(encoding="utf-8")) if (OUT / "results.json").exists() else {}
st.caption(f"CPU {meta.get('cpu', '?')} · Python {meta.get('python', '?')} · {meta.get('mode', '?')} run in {meta.get('seconds', '?')} s")


def val(group, name, metric, size=None):
    sel = df[(df.group == group) & (df.name == name) & (df.metric == metric)]
    if size is not None:
        sel = sel[sel.size_bytes.astype(str) == str(size)]
    return float(sel.value.iloc[0]) if not sel.empty else None


def fmt(v, unit, digits=3):
    return "-" if v is None else f"{v:.{digits}g} {unit}"


probe = ROOT / "analysis" / "out" / "flood_probe.csv"
flood_note = "-"
if probe.exists():
    p = pd.read_csv(probe)
    ok = p[p.status == 200]
    if not ok.empty:
        base = ok[ok.phase == "baseline"].latency_ms.median()
        during = ok[ok.phase == "flood"].latency_ms.median()
        flood_note = f"s608 p50 {base:.1f} ms baseline → {during:.1f} ms during flood"

MB = 1024 * 1024
tab_matrix, tab_graphs, tab_table = st.tabs(["Goal matrix", "Graphs", "All results"])
with tab_matrix:
    st.markdown("Each security goal: its mechanism, the attack that tests it, and the measured cost.")
    matrix = pd.DataFrame([
        ["Confidentiality", "X25519 + AES-GCM in transit, AES-256-GCM at rest", "plain vs protected capture (exp1)",
         f"AES-256-GCM {fmt(val('symmetric', 'AES-256-GCM', 'encrypt_MBps', MB), 'MB/s', 4)} @ 1 MB"],
        ["Integrity", "GCM tag, SHA-256 record hash, AAD binding", "tamper_cipher → 400; tamper_db → signature invalid",
         f"SHA-256 {fmt(val('hash', 'SHA-256', 'hash_MBps', MB), 'MB/s', 4)} @ 1 MB"],
        ["Authentication", "Argon2id, 15-min JWT, Ed25519 signatures", "bad_login, forge_sig → 400, revoked_key → 403",
         f"Ed25519 sign {fmt(val('signature', 'Ed25519', 'sign_ms'), 'ms')} vs RSA-2048 "
         f"{fmt(val('signature', 'RSA-PSS-2048', 'sign_ms'), 'ms')}; Argon2id {fmt(val('passwords', 'Argon2id', 'hash_ms'), 'ms')}"],
        ["Accountability", "hash-chained audit log + trace events", "every attack has an audit row (SQL join)",
         f"audit write {fmt(val('checks', 'audit write (hash-chained, WAL)', 'us'), 'µs')}"],
        ["Availability", "token bucket, size cap, 10 s timeout, 20-slot cap", "flood → 429s while the student keeps loading",
         flood_note],
        ["Authorisation", "role + ownership checks", "idor → 403 forbidden",
         f"RBAC {fmt(val('checks', 'RBAC role + ownership', 'us'), 'µs')}"],
        ["Replay resistance", "request ID + timestamp in AAD, seen-ID set", "replay → 409 replay_detected / stale_request",
         f"seen-set lookup {fmt(val('checks', 'replay seen-set lookup', 'us'), 'µs')}"],
    ], columns=["Goal", "Mechanism", "Security test", "Efficiency (measured)"])
    st.dataframe(matrix, use_container_width=True, hide_index=True)
    k = st.columns(4)
    k[0].metric("X25519 handshake", fmt(val("key_exchange", "X25519", "handshake_ms"), "ms"))
    k[1].metric("RSA-OAEP-2048 handshake", fmt(val("key_exchange", "RSA-OAEP-2048", "handshake_ms"), "ms"))
    k[2].metric("Protected publish p50", fmt(val("end_to_end", "protected publish", "p50_ms"), "ms"))
    k[3].metric("Plain publish p50", fmt(val("end_to_end", "plain publish", "p50_ms"), "ms"))

with tab_graphs:
    g1, g2 = st.columns(2)
    for i, name in enumerate(["sym_throughput.png", "sig_compare.png", "kex_compare.png", "e2e_latency.png", "checks_cost.png"]):
        if (OUT / name).exists():
            (g1 if i % 2 == 0 else g2).image(str(OUT / name), use_container_width=True)

with tab_table:
    group = st.selectbox("Group", ["(all)"] + sorted(df.group.unique()))
    st.dataframe(df if group == "(all)" else df[df.group == group], use_container_width=True, hide_index=True, height=480)
