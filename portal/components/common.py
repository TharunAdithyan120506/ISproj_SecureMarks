"""Shared portal plumbing: import path, page chrome, login state and small widgets.

Each browser tab is its own Streamlit session, so a teacher window and a
student window side by side behave as two separate devices, each with its
own SecureClient bound to its own loopback IP.
"""
from __future__ import annotations

import html
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import streamlit as st  # noqa: E402

from sdk.client import SecureClient, load_accounts, load_devices, load_signing_key  # noqa: E402

ROLE_LABEL = {"teacher": "Teacher", "student": "Student", "ctrl": "Exam controller", "admin": "Admin"}

# Apple-style design language (iOS / iPadOS 27): SF type scale, system colours,
# grouped background with white inset cards, hairline separators, capsule
# controls and a translucent sidebar. Tokens mirror .streamlit/config.toml.
CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:opsz,wght@14..32,400..700&display=swap');
:root {
  --sm-font: -apple-system, BlinkMacSystemFont, "SF Pro Text", "SF Pro Display", "Inter", "Segoe UI Variable Text", "Segoe UI", system-ui, sans-serif;
  --sm-mono: "SF Mono", ui-monospace, "Cascadia Mono", Menlo, Consolas, monospace;
  --sm-bg: #F2F2F7; --sm-card: #FFFFFF; --sm-label: #1D1D1F; --sm-label2: #6E6E73; --sm-label3: #AEAEB2;
  --sm-sep: rgba(60,60,67,0.12); --sm-fill: rgba(120,120,128,0.12); --sm-fill2: rgba(120,120,128,0.18);
  --sm-blue: #007AFF; --sm-green: #34C759; --sm-green-ink: #248A3D; --sm-red: #FF3B30; --sm-red-ink: #D70015;
  --sm-orange: #FF9500; --sm-indigo: #5856D6; --sm-indigo-ink: #4B49B6;
  --sm-radius: 20px; --sm-radius-s: 14px;
  --sm-shadow: 0 1px 2px rgba(0,0,0,0.04), 0 6px 20px rgba(0,0,0,0.045);
}
html, body, .stApp, .stMarkdown, button, input, textarea, select { font-family: var(--sm-font) !important;
  -webkit-font-smoothing: antialiased; font-feature-settings: "cv11", "ss01"; }
.stApp { background: var(--sm-bg); }
[data-testid="stMainBlockContainer"], .block-container { max-width: 1180px; padding-top: 2.6rem; padding-bottom: 4rem; }
[data-testid="stDecoration"] { display: none; }
[data-testid="stHeader"], [data-testid="stAppHeader"] { background: rgba(242,242,247,0.72);
  backdrop-filter: saturate(180%) blur(20px); -webkit-backdrop-filter: saturate(180%) blur(20px); }

/* type scale: large title, title 2/3, headline, footnote */
h1 { font-size: 2.125rem !important; font-weight: 700 !important; letter-spacing: -0.022em; line-height: 1.12 !important; }
h2 { font-size: 1.375rem !important; font-weight: 700 !important; letter-spacing: -0.016em; }
h3 { font-size: 1.25rem !important; font-weight: 600 !important; letter-spacing: -0.012em; }
h4 { font-size: 1.0625rem !important; font-weight: 600 !important; letter-spacing: -0.008em; margin-top: .6rem !important; }
[data-testid="stCaptionContainer"], .stCaption { color: var(--sm-label2) !important; }
[data-testid="stHeadingIconWrapper"], [data-testid="stHeaderActionElements"] { display: none !important; }
hr { border: none !important; height: 1px !important; background: var(--sm-sep) !important; margin: 1.6rem 0 !important; }

/* page header */
.sm-eyebrow { font-size: .8125rem; font-weight: 600; color: var(--sm-blue); letter-spacing: .01em; margin-bottom: 2px; }
.sm-title { font-size: 2.125rem; font-weight: 700; letter-spacing: -0.022em; line-height: 1.12; color: var(--sm-label); margin: 0; }
.sm-subtitle { font-size: 1.0625rem; color: var(--sm-label2); line-height: 1.45; max-width: 760px; margin: 8px 0 18px 0; }

/* buttons: capsules, filled primary, tinted secondary */
[data-testid^="stBaseButton-"], button[kind] { border-radius: 999px !important; font-weight: 600 !important;
  border: none !important; box-shadow: none !important; transition: transform .08s ease, background .15s ease; }
[data-testid="stBaseButton-secondary"], [data-testid="stBaseButton-secondaryFormSubmit"], button[kind="secondary"] {
  background: var(--sm-fill) !important; color: var(--sm-blue) !important; }
[data-testid="stBaseButton-secondary"]:hover, button[kind="secondary"]:hover { background: var(--sm-fill2) !important; }
[data-testid="stBaseButton-primary"], [data-testid="stBaseButton-primaryFormSubmit"], button[kind="primary"],
button[kind="primaryFormSubmit"] { background: var(--sm-blue) !important; color: #fff !important; }
[data-testid="stBaseButton-primary"]:hover, button[kind="primary"]:hover, button[kind="primaryFormSubmit"]:hover { background: #0071EB !important; }
[data-testid^="stBaseButton-"]:active, button[kind]:active { transform: scale(0.98); }
[data-testid^="stBaseButton-"]:disabled { opacity: .4; }

/* fields */
[data-baseweb="input"], [data-baseweb="select"] > div, [data-baseweb="textarea"] { border-radius: 12px !important;
  background: var(--sm-card) !important; box-shadow: 0 0 0 1px rgba(0,0,0,0.05) inset; }
[data-testid="stForm"] { background: var(--sm-card); border: none !important; border-radius: var(--sm-radius);
  box-shadow: var(--sm-shadow); padding: 22px 24px 18px 24px; }
label, [data-testid="stWidgetLabel"] p { color: var(--sm-label2) !important; font-size: .8125rem !important; font-weight: 500 !important; }

/* segmented-control tabs */
[data-testid="stTabs"] [data-baseweb="tab-list"] { background: var(--sm-fill); border-radius: 10px; padding: 3px; gap: 2px; width: fit-content; max-width: 100%; }
[data-testid="stTabs"] [data-baseweb="tab"] { border-radius: 8px; padding: 5px 16px; height: auto; font-weight: 500; }
[data-testid="stTabs"] [aria-selected="true"] { background: var(--sm-card); box-shadow: 0 1px 3px rgba(0,0,0,0.12), 0 0 0 .5px rgba(0,0,0,.04); }
[data-testid="stTabs"] [data-baseweb="tab-highlight"], [data-testid="stTabs"] [data-baseweb="tab-border"] { display: none; }

/* surfaces */
[data-testid="stMetric"] { background: var(--sm-card); border-radius: 16px; padding: 14px 18px; box-shadow: var(--sm-shadow); }
[data-testid="stMetricLabel"] p { color: var(--sm-label2) !important; font-size: .8125rem !important; font-weight: 500 !important; }
[data-testid="stMetricValue"] { font-size: 1.75rem !important; letter-spacing: -0.02em; font-variant-numeric: tabular-nums; }
[data-testid="stExpander"] details { background: var(--sm-card); border: none !important; border-radius: var(--sm-radius-s);
  box-shadow: var(--sm-shadow); }
[data-testid="stAlert"], [data-testid="stAlertContainer"] { border-radius: var(--sm-radius-s) !important; border: none !important; }
[data-testid="stImage"] img { border-radius: 16px; box-shadow: var(--sm-shadow); }
[data-testid="stDataFrame"] { border-radius: var(--sm-radius-s); overflow: hidden; box-shadow: var(--sm-shadow); }
[data-testid="stCode"] pre, .stCode pre { border-radius: var(--sm-radius-s) !important; }
[data-testid="stPageLink-NavLink"] { background: var(--sm-fill); border-radius: 999px; padding: 6px 16px !important;
  width: fit-content; margin-top: 10px; }
[data-testid="stPageLink-NavLink"] p, [data-testid="stPageLink-NavLink"] span { color: var(--sm-blue) !important; font-weight: 600; }
[data-testid="stPageLink-NavLink"]:hover { background: var(--sm-fill2); }

/* translucent sidebar */
[data-testid="stSidebar"] { background: rgba(251,251,253,0.86) !important; backdrop-filter: saturate(180%) blur(24px);
  -webkit-backdrop-filter: saturate(180%) blur(24px); border-right: 1px solid var(--sm-sep) !important; }
[data-testid="stSidebarNavLink"] { border-radius: 10px; margin: 1px 6px; }
[data-testid="stSidebarNavLink"][aria-current="page"] { background: rgba(0,122,255,0.10) !important; }
[data-testid="stSidebarNavLink"][aria-current="page"] span { color: var(--sm-blue) !important; font-weight: 600; }
.sm-profile { display: flex; gap: 12px; align-items: center; background: var(--sm-card); border-radius: 16px; padding: 12px 14px;
  box-shadow: var(--sm-shadow); margin-bottom: 10px; }
.sm-avatar { width: 40px; height: 40px; border-radius: 50%; display: flex; align-items: center; justify-content: center;
  color: #fff; font-weight: 600; font-size: .95rem; background: linear-gradient(180deg, #8E8E93, #636366); flex: none; }
.sm-avatar.teacher { background: linear-gradient(180deg, #4DA3FF, #007AFF); }
.sm-avatar.student { background: linear-gradient(180deg, #FFB340, #FF9500); }
.sm-avatar.ctrl { background: linear-gradient(180deg, #7D7AFF, #5856D6); }
.sm-avatar.admin { background: linear-gradient(180deg, #5BD27A, #34C759); }
.sm-profile-name { font-weight: 600; font-size: .95rem; line-height: 1.2; }
.sm-profile-meta { color: var(--sm-label2); font-size: .78rem; }
.sm-status { display: flex; align-items: center; gap: 7px; color: var(--sm-label2); font-size: .78rem; margin-top: 8px; }
.sm-dot { width: 8px; height: 8px; border-radius: 50%; background: var(--sm-green); box-shadow: 0 0 0 3px rgba(52,199,89,.18); flex: none; }
.sm-dot.off { background: var(--sm-red); box-shadow: 0 0 0 3px rgba(255,59,48,.18); }

/* capsule badges */
.sm-pill { display: inline-block; padding: 2px 10px; border-radius: 999px; font-size: .75rem; font-weight: 600; white-space: nowrap; line-height: 1.5; }
.sm-pass { color: var(--sm-green-ink); background: rgba(52,199,89,0.14); }
.sm-fail { color: var(--sm-red-ink); background: rgba(255,59,48,0.12); }
.sm-skip { color: var(--sm-label2); background: var(--sm-fill); }
.sm-side { display: inline-block; padding: 2px 9px; border-radius: 999px; font-size: .72rem; font-weight: 600; white-space: nowrap; }
.sm-side-client { color: #0066CC; background: rgba(0,122,255,0.10); }
.sm-side-server { color: var(--sm-indigo-ink); background: rgba(88,86,214,0.12); }

/* cards and inset grouped lists */
.sm-card { background: var(--sm-card); border-radius: var(--sm-radius); padding: 18px 22px; margin-bottom: 12px; box-shadow: var(--sm-shadow); }
.sm-card h4 { margin: 0 0 6px 0 !important; font-size: 1.0625rem; font-weight: 600; }
.sm-ok { box-shadow: var(--sm-shadow), inset 0 0 0 1.5px rgba(52,199,89,0.28); }
.sm-bad { box-shadow: var(--sm-shadow), inset 0 0 0 1.5px rgba(255,59,48,0.35); }
.sm-muted { color: var(--sm-label2); font-size: .85rem; }
.sm-big { font-size: 2.125rem; font-weight: 600; line-height: 1.1; letter-spacing: -0.02em; font-variant-numeric: tabular-nums; }
.sm-mono { font-family: var(--sm-mono); font-size: .8rem; }
.sm-device { display: inline-block; padding: 3px 10px; border-radius: 999px; background: var(--sm-fill); font-size: .78rem; color: var(--sm-label2); }
.sm-group { background: var(--sm-card); border-radius: 16px; box-shadow: var(--sm-shadow); overflow: hidden; }
table.sm-trace { width: 100%; border-collapse: collapse; font-size: .84rem; background: var(--sm-card); }
table.sm-trace th { text-align: left; color: var(--sm-label2); font-weight: 500; padding: 10px 12px 8px 12px; font-size: .75rem;
  border-bottom: 1px solid var(--sm-sep); background: #FAFAFC; }
table.sm-trace td { border-bottom: 1px solid var(--sm-sep); padding: 8px 12px; vertical-align: top; }
table.sm-trace tr:last-child td { border-bottom: none; }
table.sm-trace td.step { font-family: var(--sm-mono); font-weight: 600; font-size: .8rem; white-space: nowrap; }
table.sm-trace td.val { font-family: var(--sm-mono); color: #3A3A3C; font-size: .76rem; word-break: break-word; }
table.sm-trace tr.fail td { background: rgba(255,59,48,0.05); }
.sm-tile { background: var(--sm-card); border-radius: 18px; padding: 16px 18px; box-shadow: var(--sm-shadow); min-height: 150px; }
.sm-tile-title { font-weight: 600; font-size: 1rem; margin-top: 8px; }
.sm-tile-text { color: var(--sm-label2); font-size: .85rem; line-height: 1.4; margin-top: 3px; }
.sm-glyph { width: 34px; height: 34px; border-radius: 9px; display: flex; align-items: center; justify-content: center;
  color: #fff; font-size: 1.05rem; }
</style>
"""


EYEBROWS = {
    "Publish marks": "Teacher · teacher-laptop", "My marks": "Student · student-laptop",
    "Verify and audit": "Exam controller · ctrl-pc", "Keys": "Admin · admin-pc",
    "Crypto playground": "Lab · runs locally", "Attack lab": "Lab · security analysis",
    "Traffic lab": "Lab · ISL modules 7 and 4", "Benchmarks": "Lab · efficiency analysis",
}


def page(title: str, icon: str = "🔐", subtitle: str | None = None, eyebrow: str | None = None) -> None:
    eyebrow = eyebrow or EYEBROWS.get(title, "SecureMarks")
    st.set_page_config(page_title=title if title == "SecureMarks" else f"{title} · SecureMarks", page_icon=icon, layout="wide")
    st.markdown(CSS, unsafe_allow_html=True)
    st.markdown(f'<div class="sm-eyebrow">{esc(eyebrow)}</div><h1 class="sm-title">{esc(title)}</h1>'
                + (f'<p class="sm-subtitle">{esc(subtitle)}</p>' if subtitle else '<div style="height:14px"></div>'),
                unsafe_allow_html=True)
    sidebar()


def section(title: str, caption: str | None = None) -> None:
    """An iOS-style section header above a group of content."""
    st.markdown(f'<h3 style="margin:1.4rem 0 .2rem 0">{esc(title)}</h3>'
                + (f'<div class="sm-muted" style="margin-bottom:.6rem">{esc(caption)}</div>' if caption else ""),
                unsafe_allow_html=True)


def card(markup: str, tone: str = "") -> None:
    st.markdown(f'<div class="sm-card {tone}">{html_block(markup)}</div>', unsafe_allow_html=True)


def esc(text) -> str:
    return html.escape(str(text if text is not None else ""))


def html_block(markup: str) -> str:
    """Collapse multi-line HTML to one line so Markdown never sees an indented code block or a blank line."""
    return " ".join(line.strip() for line in markup.splitlines() if line.strip())


def pill(ok: bool | None, text: str | None = None) -> str:
    cls, default = {True: ("sm-pass", "PASS"), False: ("sm-fail", "FAIL"), None: ("sm-skip", "SKIP")}[ok]
    return f'<span class="sm-pill {cls}">{esc(text or default)}</span>'


# --- login state --------------------------------------------------------------------------------

def client() -> SecureClient | None:
    return st.session_state.get("client")


def user() -> dict | None:
    return st.session_state.get("user")


def login(username: str, password: str) -> tuple[bool, str]:
    accounts = load_accounts()
    role = accounts.get(username, {}).get("role", "student")
    c = SecureClient.for_role(role)
    res = c.login(username, password)
    if not res.ok:
        return False, f"{res.status} {res.code}: {res.detail or ''}"
    signing_key = rsa_key = None
    if c.role == "teacher":
        try:
            signing_key = load_signing_key(username, password)
            rsa_key = load_signing_key(username, password, alg="RSA-PSS-2048")  # P1 legacy-rsa policy
        except (FileNotFoundError, ValueError) as exc:
            return False, f"logged in, but could not unlock the signing key: {exc}"
    dev = load_devices()["roles"][c.role]
    st.session_state.update(
        client=c, signing_key=signing_key, signing_key_rsa=rsa_key,
        user={"username": username, "role": c.role, "roll_no": c.roll_no, "courses": c.courses,
              "device": dev["label"], "ip": dev["ip"], "bound": c.bound})
    return True, "ok"


def logout() -> None:
    c = client()
    if c:
        c.close()
    for k in list(st.session_state):
        del st.session_state[k]


def require(*roles: str) -> SecureClient:
    """Stop the page unless a user with one of `roles` is signed in (token refreshed if expired)."""
    u = user()
    if not u:
        st.info("Sign in on the **Home** page first.")
        st.page_link("Home.py", label="Go to Home to sign in", icon=":material/home:")
        st.stop()
    if roles and u["role"] not in roles:
        st.warning(f"This page is for {' / '.join(ROLE_LABEL[r] for r in roles)}. "
                   f"You are signed in as **{u['username']}** ({ROLE_LABEL[u['role']]}).")
        st.stop()
    c = client()
    if c.token_expires_at - time.time() < 30:
        st.warning("Your 15-minute token expired. Sign in again on the Home page.")
        st.stop()
    return c


# --- sidebar ------------------------------------------------------------------------------------

def sidebar() -> None:
    with st.sidebar:
        u = user()
        if u:
            c = client()
            sess = (c.sessions.get("confidential") or c.sessions.get("normal")) if c else None
            session_line = (f"Session {sess.session_id[:8]}… · {sess.kex} · {max(0, int(sess.expires_at - time.time()))} s left"
                            if sess else "No session yet")
            bound = "" if u.get("bound") else " · unbound"
            st.markdown(html_block(f"""
                <div class="sm-profile">
                  <div class="sm-avatar {esc(u['role'])}">{esc(u['username'][:2].upper())}</div>
                  <div>
                    <div class="sm-profile-name">{esc(u['username'])}</div>
                    <div class="sm-profile-meta">{ROLE_LABEL[u['role']]} · {esc(u['device'])}</div>
                    <div class="sm-profile-meta sm-mono">{esc(u['ip'])}{bound}</div>
                  </div>
                </div>
                <div class="sm-profile-meta" style="margin:0 4px 10px 4px">{esc(session_line)}</div>"""),
                        unsafe_allow_html=True)
            if st.button("Sign out", use_container_width=True):
                logout()
                st.rerun()
        else:
            st.markdown('<div class="sm-profile-meta" style="margin:0 4px 6px 4px">Not signed in. The playground and the '
                        'labs work without an account.</div>', unsafe_allow_html=True)
        health = _health()
        if health:
            st.markdown(f'<div class="sm-status"><span class="sm-dot"></span>Middleware online · {health["sessions"]} '
                        f'sessions · demo mode {"on" if health["demo_mode"] else "off"}</div>', unsafe_allow_html=True)
        else:
            st.markdown('<div class="sm-status"><span class="sm-dot off"></span>Middleware offline · run '
                        '<code>python scripts\\run_demo.py</code></div>', unsafe_allow_html=True)


@st.cache_data(ttl=3, show_spinner=False)
def _health() -> dict | None:
    c = SecureClient(device_label="portal-health", save_last_request=False)
    try:
        return c.health()
    finally:
        c.close()


def health() -> dict | None:
    return _health()


# --- subprocess helpers (analysis always runs in its own process) ------------------------------------

def py_env() -> dict:
    return dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUTF8="1", COLUMNS="140")


def run_module(*args: str, timeout: float = 600) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-m", *args], cwd=ROOT, capture_output=True, text=True, encoding="utf-8",
                          errors="replace", env=py_env(), timeout=timeout)


def stream_module(*args: str, placeholder, timeout: float = 900) -> tuple[int, str]:
    """Run `python -m ...` and stream its output into a code block as it arrives."""
    proc = subprocess.Popen([sys.executable, "-u", "-m", *args], cwd=ROOT, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace", env=py_env())
    lines: list[str] = []
    for line in proc.stdout:
        lines.append(line.rstrip("\n"))
        placeholder.code("\n".join(lines[-40:]) or "…", language=None)
    proc.wait(timeout=timeout)
    return proc.returncode, "\n".join(lines)
