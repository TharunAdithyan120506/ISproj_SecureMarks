"""SecureMarks portal: sign in, pick a role page.

    streamlit run portal\\Home.py
"""
from __future__ import annotations

import streamlit as st

from components.common import ROLE_LABEL, esc, health, html_block, load_accounts, login, page, section, user

page("SecureMarks", "🔐",
     "The app only says “confidential”. The middleware picks the algorithms, manages the keys, blocks replays and "
     "floods, and logs every decision - and the packet capture proves it.",
     eyebrow="Security middleware · Student marks portal")

ROLE_PAGES = {
    "teacher": [("pages/1_Publish.py", "Publish marks", ":material/edit_note:")],
    "student": [("pages/2_My_Marks.py", "My marks", ":material/school:")],
    "ctrl": [("pages/3_Verify_Audit.py", "Verify and audit", ":material/fact_check:")],
    "admin": [("pages/4_Keys.py", "Keys", ":material/key:"), ("pages/3_Verify_Audit.py", "Audit log", ":material/fact_check:")],
}

# Minimal line glyphs in the spirit of SF Symbols (inline SVG, no icon font needed).
GLYPHS = {
    "flask": '<path d="M9 3h6M10 3v6l-5.2 8.7A2 2 0 0 0 6.5 21h11a2 2 0 0 0 1.7-3.3L14 9V3"/><path d="M7.5 15h9"/>',
    "shield": '<path d="M12 3l7 3v5.5c0 4.6-3 8-7 9.5-4-1.5-7-4.9-7-9.5V6z"/><path d="M9 12l2 2 4-4"/>',
    "wave": '<path d="M3 12h3l2.5-6 4 12 3-9 2 3H21"/>',
    "gauge": '<path d="M4 17a8 8 0 1 1 16 0"/><path d="M12 17l4.5-5.5"/>',
}
LABS = [
    ("pages/5_Crypto_Playground.py", "Crypto playground", "AES-GCM, SHA-256, Ed25519 and X25519, live.", "flask", "#5856D6"),
    ("pages/6_Attack_Lab.py", "Attack lab", "Each attack, its expected refusal and the audit evidence.", "shield", "#FF3B30"),
    ("pages/7_Traffic_Lab.py", "Traffic lab", "Capture, PyShark analysis and the PCAP → SQLite join.", "wave", "#007AFF"),
    ("pages/8_Benchmarks.py", "Benchmarks", "Cost of every algorithm and every check, measured.", "gauge", "#FF9500"),
]


def glyph(name: str, color: str) -> str:
    return (f'<div class="sm-glyph" style="background:{color}"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" '
            f'stroke="#fff" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round">{GLYPHS[name]}</svg></div>')


u = user()
if not u:
    left, right = st.columns([1, 1.15], gap="large")
    with left:
        section("Sign in", "Your role picks the simulated device: each role has its own loopback IP, so a capture "
                           "shows separate hosts.")
        with st.form("login", border=False):
            username = st.text_input("Username", placeholder="t104, s608, s612, ctrl or admin")
            password = st.text_input("Password", type="password")
            submitted = st.form_submit_button("Sign in", type="primary", use_container_width=True)
        if submitted:
            with st.spinner("Verifying with Argon2id…"):
                ok, msg = login(username.strip(), password)
            if ok:
                st.rerun()
            st.error(msg)
    with right:
        section("Demo accounts", "Demo-only passwords, also listed in README.md. One tap signs this window in as "
                                 "that device.")
        for name, a in load_accounts().items():
            extra = a.get("roll_no") or ", ".join(a.get("courses", []))
            c1, c2 = st.columns([3, 1.4], vertical_alignment="center")
            c1.markdown(html_block(f"""
                <div style="display:flex;gap:12px;align-items:center">
                  <div class="sm-avatar {esc(a['role'])}" style="width:36px;height:36px;font-size:.85rem">{esc(name[:2].upper())}</div>
                  <div><div class="sm-profile-name">{esc(name)}
                    <span class="sm-profile-meta" style="font-weight:400">· {ROLE_LABEL[a['role']]}{(' · ' + esc(extra)) if extra else ''}</span></div>
                    <div class="sm-profile-meta sm-mono">{esc(a['password'])}</div></div>
                </div>"""), unsafe_allow_html=True)
            if c2.button("Sign in", key=f"quick-{name}", use_container_width=True):
                with st.spinner("Signing in…"):
                    ok, msg = login(name, a["password"])
                if ok:
                    st.rerun()
                st.error(msg)
        st.caption("For the demo: teacher window on the left, student window on the right, server console below.")
else:
    st.markdown(html_block(f"""
        <div class="sm-card" style="display:flex;gap:16px;align-items:center">
          <div class="sm-avatar {esc(u['role'])}" style="width:52px;height:52px;font-size:1.1rem">{esc(u['username'][:2].upper())}</div>
          <div><div style="font-size:1.25rem;font-weight:600;letter-spacing:-.01em">Welcome, {esc(u['username'])}</div>
            <div class="sm-muted">{ROLE_LABEL[u['role']]} on {esc(u['device'])} · {esc(u['ip'])}
            {'' if u['bound'] else ' · loopback binding unavailable, the X-Device header identifies this device'}</div></div>
        </div>"""), unsafe_allow_html=True)
    cols = st.columns(4)
    for col, (path, label, icon) in zip(cols, ROLE_PAGES[u["role"]]):
        with col:
            st.page_link(path, label=label, icon=icon)

section("Labs", "No sign-in needed.")
cols = st.columns(4, gap="medium")
for col, (path, title, text, g, color) in zip(cols, LABS):
    with col:
        st.markdown(f'<div class="sm-tile">{glyph(g, color)}<div class="sm-tile-title">{esc(title)}</div>'
                    f'<div class="sm-tile-text">{esc(text)}</div></div>', unsafe_allow_html=True)
        st.page_link(path, label="Open", icon=":material/arrow_forward:")

section("Status")
h = health()
c1, c2, c3, c4 = st.columns(4)
c1.metric("Middleware", "Online" if h else "Offline")
c2.metric("Open sessions", h["sessions"] if h else "-")
c3.metric("Seen request IDs", h["seen_request_ids"] if h else "-")
c4.metric("Demo mode", ("On" if h["demo_mode"] else "Off") if h else "-")

section("How a protected call is checked")
with st.expander("The ten checks, in order", expanded=not u):
    st.markdown("""
| # | Check | Refused with |
|---|---|---|
| 1 | Concurrency cap (20 in flight) | `503 busy` |
| 2 | Size cap (policy maximum, 5 MB hard cap) | `413 too_large` |
| 3 | Token bucket per user (per IP before login) | `429 rate_limited` |
| 4 | JWT valid and unexpired | `401 auth_failed` |
| 5 | Session exists, same user, policy strong enough | `401 session_invalid` · `403 policy_too_weak` |
| 6 | Freshness: X-Timestamp within 30 s | `409 stale_request` |
| 7 | Request ID never seen before | `409 replay_detected` |
| 8 | AES-GCM decrypt with the session key and AAD | `400 integrity_failed` |
| 9 | Role and ownership | `403 forbidden` |
| 10 | Handler: Ed25519 signature, key not revoked, 10 s timeout | `400 bad_signature` · `403 key_revoked` · `504 timeout` |

Every outcome is written to the hash-chained audit log; in demo mode every step is also traced and printed on the
server console.
""")
