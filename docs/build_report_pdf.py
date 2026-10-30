"""Build docs/SecureMarks_Report.pdf from docs/REPORT.md.

    pip install markdown pypdf pypdfium2        # once (documentation tooling only)
    python docs\\build_report_pdf.py

Markdown -> styled HTML (cover, contents with page numbers, running header and
page numbers) -> PDF with headless Microsoft Edge. The Mermaid sequence
diagrams are drawn here as inline SVG, so the build needs no network.
Two passes: the first finds the page of every section, the second writes those
numbers into the contents page.
"""
from __future__ import annotations

import html
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
from datetime import date
from pathlib import Path

import markdown

DOCS = Path(__file__).resolve().parent
SOURCE = DOCS / "REPORT.md"
OUTPUT = DOCS / "SecureMarks_Report.pdf"
EDGE_PATHS = [Path(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"),
              Path(r"C:\Program Files\Microsoft\Edge\Application\msedge.exe")]
RUNNING_TITLE = "SecureMarks · Concepts, implementation and ISL compliance"

FONT = '"Segoe UI Variable Text", "Segoe UI", -apple-system, "SF Pro Text", "Helvetica Neue", Arial, sans-serif'
MONO = '"Cascadia Mono", "SF Mono", Consolas, Menlo, monospace'


# --- sequence diagrams (the Mermaid subset REPORT.md uses) ---------------------------------------

def _wrap(text: str, width_px: float, font_px: float = 11.0) -> list[str]:
    chars = max(8, int(width_px / (font_px * 0.56)))
    return textwrap.wrap(text, chars) or [""]


def _text(x: float, y: float, lines: list[str], anchor: str = "middle", size: float = 11, color: str = "#1D1D1F",
          weight: int = 400, line_h: float = 14) -> str:
    spans = "".join(f'<tspan x="{x:.1f}" dy="{0 if i == 0 else line_h}">{html.escape(t)}</tspan>'
                    for i, t in enumerate(lines))
    return (f'<text x="{x:.1f}" y="{y:.1f}" text-anchor="{anchor}" font-size="{size}" font-weight="{weight}" '
            f'fill="{color}" font-family=\'{FONT}\'>{spans}</text>')


def sequence_svg(src: str) -> str:
    participants: list[tuple[str, str]] = []
    events: list[tuple] = []
    autonumber = False
    for raw in src.splitlines():
        s = raw.strip()
        if not s or s == "sequenceDiagram":
            continue
        if s == "autonumber":
            autonumber = True
        elif m := re.match(r"participant (\w+) as (.+)", s):
            participants.append((m[1], m[2]))
        elif m := re.match(r"Note over ([\w,]+): (.+)", s):
            events.append(("note", m[1].split(","), m[2]))
        elif m := re.match(r"(\w+)(-->>|->>)(\w+): (.+)", s):
            events.append(("msg", m[1], m[3], m[4], m[2] == "-->>"))

    W, margin = 720, 120 if len(participants) > 2 else 140
    step = (W - 2 * margin) / max(1, len(participants) - 1)
    xs = {pid: margin + i * step for i, (pid, _) in enumerate(participants)}
    order = [pid for pid, _ in participants]
    out: list[str] = []
    y = 66
    n = 0

    def bounds(pid: str) -> tuple[float, float]:
        i = order.index(pid)
        left = xs[order[i - 1]] + 22 if i > 0 else 10
        right = xs[order[i + 1]] - 22 if i < len(order) - 1 else W - 10
        return left, right

    body: list[str] = []
    for ev in events:
        if ev[0] == "msg":
            _, a, b, label, dashed = ev
            n += 1
            if a == b:
                left, right = bounds(a)
                width = min(390.0, right - left)
                x0 = min(max(xs[a] - width / 2, left), right - width)
                lines = _wrap(label, width - 40)
                h = 14 * len(lines) + 14
                body.append(f'<rect x="{x0:.1f}" y="{y:.1f}" width="{width:.1f}" height="{h}" rx="9" fill="#FFFFFF" '
                            f'stroke="#D1D1D6" stroke-width="0.8"/>')
                if autonumber:
                    body.append(f'<circle cx="{x0 + 15:.1f}" cy="{y + h / 2:.1f}" r="8" fill="#007AFF"/>'
                                + _text(x0 + 15, y + h / 2 + 3.4, [str(n)], size=9, color="#FFFFFF", weight=600))
                body.append(_text(x0 + width / 2 + 10, y + 17, lines, size=10.5))
                y += h + 12
            else:
                x1, x2 = xs[a], xs[b]
                lines = _wrap(label, abs(x2 - x1) - 44, 10.5)
                label_h = 13 * len(lines)
                ty = y + 11
                arrow_y = y + label_h + 9
                body.append(_text((x1 + x2) / 2 + (6 if autonumber else 0), ty, lines, size=10.5, line_h=13))
                color = "#8E8E93" if dashed else "#007AFF"
                dash = ' stroke-dasharray="5 4"' if dashed else ""
                direction = 1 if x2 > x1 else -1
                body.append(f'<line x1="{x1:.1f}" y1="{arrow_y:.1f}" x2="{x2 - direction * 2:.1f}" y2="{arrow_y:.1f}" '
                            f'stroke="{color}" stroke-width="1.6"{dash} marker-end="url(#{"ah-grey" if dashed else "ah-blue"})"/>')
                if autonumber:
                    cx = x1 + direction * 14
                    body.append(f'<circle cx="{cx:.1f}" cy="{arrow_y:.1f}" r="8" fill="{color}"/>'
                                + _text(cx, arrow_y + 3.4, [str(n)], size=9, color="#FFFFFF", weight=600))
                y = arrow_y + 16
        else:
            _, ids, label = ev
            x_left, x_right = min(xs[i] for i in ids) - 100, max(xs[i] for i in ids) + 100
            x_left, x_right = max(8, x_left), min(W - 8, x_right)
            lines = _wrap(label, x_right - x_left - 30)
            h = 14 * len(lines) + 14
            body.append(f'<rect x="{x_left:.1f}" y="{y:.1f}" width="{x_right - x_left:.1f}" height="{h}" rx="9" '
                        f'fill="#FFF6D6"/>' + _text((x_left + x_right) / 2, y + 17, lines, size=10.5, color="#6B4E00"))
            y += h + 12

    end_y = y + 4
    out.append('<defs>'
               '<marker id="ah-blue" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto">'
               '<path d="M0,0 L10,5 L0,10 z" fill="#007AFF"/></marker>'
               '<marker id="ah-grey" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto">'
               '<path d="M0,0 L10,5 L0,10 z" fill="#8E8E93"/></marker></defs>')
    for pid, label in participants:
        x = xs[pid]
        out.append(f'<line x1="{x:.1f}" y1="48" x2="{x:.1f}" y2="{end_y:.1f}" stroke="#C7C7CC" stroke-width="1" '
                   f'stroke-dasharray="3 4"/>')
    for pid, label in participants:
        x = xs[pid]
        name, _, rest = label.partition(" (")
        lines = [name] + ([f"({rest}"] if rest else [])
        out.append(f'<rect x="{x - 78:.1f}" y="6" width="156" height="42" rx="11" fill="#F2F2F7"/>'
                   + _text(x, 23 if rest else 31, [lines[0]], size=11.5, weight=600)
                   + (_text(x, 38, [lines[1]], size=9.5, color="#6E6E73") if rest else ""))
    out.extend(body)
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {end_y + 8:.0f}" width="100%" '
            f'role="img">{"".join(out)}</svg>')


# --- markdown -> html ------------------------------------------------------------------------------

def github_slug(value: str, separator: str = "-") -> str:
    value = value.strip().lower()
    value = re.sub(r"[^\w\- ]", "", value)
    return value.replace(" ", separator)


def prepare(md_text: str) -> tuple[str, list[str]]:
    """Strip the title block and the Markdown contents list; lift diagrams and the formula out of Markdown."""
    lines = md_text.splitlines()
    start = next(i for i, ln in enumerate(lines) if ln.startswith("## 1. "))  # the contents page carries the intro
    text = "\n".join(lines[start:])
    text = re.sub(r"\n## Contents\n.*?\n---\n", "\n", text, count=1, flags=re.S)

    diagrams: list[str] = []

    def lift(m: re.Match) -> str:
        diagrams.append(m[1])
        return f'\n<div class="diagram-slot" data-n="{len(diagrams) - 1}"></div>\n'

    text = re.sub(r"```mermaid\n(.*?)```", lift, text, flags=re.S)
    formula = ('<div class="formula"><math display="block"><mi>H</mi><mo>=</mo><mo>&minus;</mo>'
               '<munderover><mo>&sum;</mo><mrow><mi>i</mi><mo>=</mo><mn>0</mn></mrow><mn>255</mn></munderover>'
               '<msub><mi>p</mi><mi>i</mi></msub><mo>&#x2062;</mo><msub><mi>log</mi><mn>2</mn></msub>'
               '<mo>&#x2061;</mo><msub><mi>p</mi><mi>i</mi></msub></math></div>')
    text = re.sub(r"\$\$.*?\$\$", formula, text, flags=re.S)
    text = text.replace("$p_i$", "<i>p</i><sub>i</sub>").replace("$i$", "<i>i</i>")
    return text, diagrams


def to_html(text: str, diagrams: list[str]) -> tuple[str, list[tuple[str, str]]]:
    md = markdown.Markdown(extensions=["tables", "fenced_code", "toc", "sane_lists"],
                           extension_configs={"toc": {"slugify": github_slug}})
    body = md.convert(text)
    body = body.replace("<hr />", "")
    captions = ["Figure 1 · Login and X25519 session handshake. Only public keys cross the wire.",
                "Figure 2 · Teacher publishes marks: the ten checks, then encryption at rest."]
    for i, src in enumerate(diagrams):
        cap = captions[i] if i < len(captions) else f"Figure {i + 1}"
        body = body.replace(f'<div class="diagram-slot" data-n="{i}"></div>',
                            f'<figure class="diagram">{sequence_svg(src)}<figcaption>{html.escape(cap)}</figcaption></figure>')

    def figure(m: re.Match) -> str:
        alt, src = html.unescape(m[1]), m[2]
        path = (DOCS / src).resolve()
        return (f'<figure class="chart"><img src="{path.as_uri()}" alt="{html.escape(alt)}"/>'
                f'<figcaption>{html.escape(alt)}</figcaption></figure>')

    body = re.sub(r'<p><img alt="([^"]*)" src="([^"]+)" /></p>', figure, body)
    # inline code: allow line breaks only after path separators, never mid-token
    def soft_breaks(m: re.Match) -> str:
        code = m[1].replace("/", "/<wbr>")
        return "<code>" + (code.replace("_", "_<wbr>") if len(m[1]) > 18 else code) + "</code>"

    body = re.sub(r"(?<!<pre>)<code>(.*?)</code>", soft_breaks, body)
    body = re.sub(r"<table>", '<div class="table"><table>', body).replace("</table>", "</table></div>")
    headings = re.findall(r'<h2 id="([^"]+)">(.*?)</h2>', body)
    return body, [(hid, re.sub(r"<[^>]+>", "", t)) for hid, t in headings]


# --- page -----------------------------------------------------------------------------------------------

CSS = f"""
@page {{ size: A4; margin: 21mm 18mm 20mm 18mm;
  @top-left {{ content: "{RUNNING_TITLE}"; font: 500 7.6pt {FONT}; color: #8E8E93; }}
  @bottom-right {{ content: counter(page) " / " counter(pages); font: 500 7.6pt {FONT}; color: #8E8E93; }}
  @bottom-left {{ content: "ISL project report · Traffic Analysis and PCAP Analysis"; font: 7.6pt {FONT}; color: #AEAEB2; }} }}
@page :first {{ margin: 0; @top-left {{ content: none; }} @bottom-right {{ content: none; }} @bottom-left {{ content: none; }} }}
* {{ box-sizing: border-box; }}
html {{ -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
body {{ font-family: {FONT}; font-size: 9.6pt; line-height: 1.55; color: #1D1D1F; margin: 0; }}
p {{ margin: 0 0 7pt 0; orphans: 3; widows: 3; }}
a {{ color: #0066CC; text-decoration: none; }}
strong {{ font-weight: 600; }}
code {{ font-family: {MONO}; font-size: 0.86em; background: #F2F2F7; color: #2C2C2E; padding: 0.5pt 3pt; border-radius: 3pt;
  overflow-wrap: break-word; }}
pre {{ background: #F5F5F7; border-radius: 9pt; padding: 9pt 12pt; font-size: 8.2pt; line-height: 1.45;
  white-space: pre-wrap; break-inside: avoid; margin: 4pt 0 10pt 0; }}
pre code {{ background: none; padding: 0; font-size: 1em; }}
h2 {{ break-before: page; font-size: 20pt; font-weight: 700; letter-spacing: -0.02em; line-height: 1.15;
  margin: 0 0 12pt 0; padding-bottom: 8pt; border-bottom: 1px solid #E5E5EA; }}
h3 {{ font-size: 12.5pt; font-weight: 600; letter-spacing: -0.01em; margin: 16pt 0 6pt 0; break-after: avoid; }}
h4 {{ font-size: 10.5pt; font-weight: 600; margin: 12pt 0 4pt 0; break-after: avoid; }}
ul, ol {{ margin: 0 0 8pt 0; padding-left: 15pt; }}
li {{ margin-bottom: 2.5pt; }}
.table {{ margin: 4pt 0 12pt 0; border-radius: 9pt; overflow: hidden; border: 1px solid #E5E5EA; break-inside: avoid; }}
table {{ width: 100%; border-collapse: collapse; font-size: 8.2pt; line-height: 1.42; }}
th {{ text-align: left; font-weight: 600; color: #3A3A3C; background: #F5F5F7; padding: 5pt 7pt; border-bottom: 1px solid #E5E5EA; }}
td {{ padding: 4.5pt 7pt; border-bottom: 1px solid #EFEFF4; vertical-align: top; }}
tr:last-child td {{ border-bottom: none; }}
tr {{ break-inside: avoid; }}
td code, th code {{ font-size: 0.92em; padding: 0 2pt; }}
figure {{ margin: 8pt 0 14pt 0; break-inside: avoid; }}
figure.chart img {{ width: 100%; border-radius: 9pt; border: 1px solid #EFEFF4; }}
figure.diagram {{ background: #FBFBFD; border: 1px solid #EFEFF4; border-radius: 12pt; padding: 10pt 10pt 4pt 10pt; }}
figcaption {{ font-size: 8pt; color: #6E6E73; margin-top: 5pt; line-height: 1.4; }}
.formula {{ margin: 6pt 0 12pt 0; }}
.formula math {{ font-family: "Cambria Math", "STIX Two Math", serif; font-size: 15pt; }}

/* cover */
.cover {{ height: 297mm; padding: 34mm 22mm 20mm 22mm; position: relative; break-after: page;
  background: linear-gradient(180deg, #F2F2F7 0%, #FFFFFF 58%); }}
.cover .eyebrow {{ font-size: 10pt; font-weight: 600; color: #007AFF; letter-spacing: 0.01em; }}
.cover h1 {{ font-size: 46pt; font-weight: 700; letter-spacing: -0.035em; margin: 6pt 0 4pt 0; line-height: 1.02; }}
.cover .sub {{ font-size: 15pt; color: #3A3A3C; line-height: 1.35; max-width: 150mm; margin: 0 0 22pt 0; font-weight: 400; }}
.cover .facts {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 8pt; margin: 0 0 26pt 0; }}
.cover .fact {{ background: #FFFFFF; border-radius: 12pt; padding: 11pt 13pt; box-shadow: 0 1px 2px rgba(0,0,0,0.05), 0 4pt 14pt rgba(0,0,0,0.05); }}
.cover .fact b {{ display: block; font-size: 22pt; font-weight: 700; letter-spacing: -0.02em; line-height: 1.1; }}
.cover .fact span {{ font-size: 8.6pt; color: #6E6E73; }}
.cover table.meta {{ font-size: 9pt; width: 100%; }}
.cover table.meta td {{ border-bottom: 1px solid #E5E5EA; padding: 6pt 0; }}
.cover table.meta td:first-child {{ color: #6E6E73; width: 34mm; }}
.cover .foot {{ position: absolute; left: 22mm; right: 22mm; bottom: 18mm; font-size: 8pt; color: #8E8E93;
  display: flex; justify-content: space-between; }}

/* contents */
.toc h2 {{ break-before: avoid; }}
.toc ol {{ list-style: none; padding: 0; margin: 0; }}
.toc li {{ display: flex; align-items: baseline; padding: 6.5pt 0; border-bottom: 1px solid #EFEFF4; margin: 0; font-size: 10.5pt; }}
.toc li .t {{ flex: 1; }}
.toc a {{ color: #1D1D1F; }}
.toc li .p {{ color: #6E6E73; font-variant-numeric: tabular-nums; min-width: 18pt; text-align: right; }}
.toc .lead {{ font-size: 9.6pt; color: #3A3A3C; margin-bottom: 14pt; }}
"""


def cover_html() -> str:
    facts = [("7", "security goals, each with a test and a cost"), ("10", "checks on every protected request"),
             ("8", "attack scripts in the security analysis"), ("5", "simulated devices with their own IPs"),
             ("2", "ISL modules implemented: 7 and 4"), ("39", "automated tests passing")]
    meta = [("Project", "SecureMarks, a policy-driven security middleware with a student marks portal"),
            ("ISL modules", "Module 7 Traffic Analysis (Wireshark, PyShark) · Module 4 PCAP Analysis (PCAP → SQLite, PCAP → XML)"),
            ("Security goals", "Confidentiality, integrity, authentication, accountability, availability, plus authorisation and replay resistance"),
            ("Group", "2 members, V IT, section B"),
            ("Stack", "Python 3.13 · FastAPI · cryptography · Argon2 · PyJWT · SQLite · Streamlit · PyShark / Wireshark"),
            ("Date", date.today().strftime("%B %Y"))]
    return ('<section class="cover">'
            '<div class="eyebrow">ISL project report</div><h1>SecureMarks</h1>'
            '<p class="sub">Concepts, implementation and ISL compliance of a policy-driven security middleware for a '
            'student marks portal</p>'
            '<div class="facts">' + "".join(f'<div class="fact"><b>{n}</b><span>{html.escape(t)}</span></div>' for n, t in facts)
            + '</div><table class="meta">' + "".join(f"<tr><td>{html.escape(k)}</td><td>{html.escape(v)}</td></tr>" for k, v in meta)
            + '</table><div class="foot"><span>The app only says “confidential”. The middleware decides how, and the capture proves it.</span>'
            '<span>docs/REPORT.md</span></div></section>')


def toc_html(headings: list[tuple[str, str]], pages: dict[str, int]) -> str:
    rows = "".join(f'<li><span class="t"><a href="#{hid}">{html.escape(text)}</a></span>'
                   f'<span class="p">{pages.get(hid, "")}</span></li>' for hid, text in headings)
    return ('<section class="toc"><h2 id="contents">Contents</h2>'
            '<p class="lead">Every security concept the project uses, where exactly it is implemented (file and line, '
            'relative to the project root), how data moves through encryption, decryption, hashing, signing and '
            'verification, and how each ISL instruction is met. Measurements come from the rehearsal run on the demo '
            'laptop; README.md explains how to reproduce them.</p>'
            f'<ol>{rows}</ol></section>')


def page_html(body: str, headings: list[tuple[str, str]], pages: dict[str, int]) -> str:
    return (f'<!doctype html><html lang="en"><head><meta charset="utf-8"><title>SecureMarks report</title>'
            f'<style>{CSS}</style></head><body>{cover_html()}{toc_html(headings, pages)}{body}</body></html>')


# --- render ---------------------------------------------------------------------------------------------

def edge() -> Path:
    for p in EDGE_PATHS:
        if p.exists():
            return p
    found = shutil.which("msedge")
    if found:
        return Path(found)
    sys.exit("Microsoft Edge not found: it is used to print the HTML to PDF.")


def print_pdf(html_text: str, out: Path, workdir: Path) -> None:
    src = workdir / "report.html"
    src.write_text(html_text, encoding="utf-8")
    profile = workdir / "edge-profile"
    cmd = [str(edge()), "--headless=new", "--disable-gpu", "--no-first-run", "--no-default-browser-check",
           f"--user-data-dir={profile}", "--no-pdf-header-footer", "--print-to-pdf-no-header",
           f"--print-to-pdf={out}", src.as_uri()]
    subprocess.run(cmd, check=True, capture_output=True, timeout=180)
    if not out.exists() or out.stat().st_size == 0:
        sys.exit("Edge did not produce a PDF.")


def find_pages(pdf: Path, headings: list[tuple[str, str]]) -> dict[str, int]:
    import pypdfium2 as pdfium

    doc = pdfium.PdfDocument(str(pdf))
    texts = []
    for i in range(len(doc)):
        tp = doc[i].get_textpage()
        texts.append(" ".join(tp.get_text_range().split()))
    doc.close()
    pages, start = {}, 2  # page 1 cover, page 2 contents
    for hid, text in headings:
        needle = " ".join(text.split())
        for i in range(start, len(texts)):
            if needle[:40] in texts[i]:
                pages[hid] = i + 1
                start = i
                break
    return pages


def main() -> None:
    text, diagrams = prepare(SOURCE.read_text(encoding="utf-8"))
    body, headings = to_html(text, diagrams)
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        first = work / "pass1.pdf"
        print_pdf(page_html(body, headings, {}), first, work)
        pages = find_pages(first, headings)
        print_pdf(page_html(body, headings, pages), OUTPUT, work)

    from pypdf import PdfReader, PdfWriter
    reader = PdfReader(str(OUTPUT))
    writer = PdfWriter(clone_from=reader)
    writer.add_metadata({"/Title": "SecureMarks: concepts, implementation and ISL compliance",
                         "/Subject": "ISL project report: Traffic Analysis and PCAP Analysis modules",
                         "/Keywords": "AES-GCM, Ed25519, X25519, SHA-256, PyShark, PCAP, SQLite",
                         "/Creator": "docs/build_report_pdf.py"})
    with open(OUTPUT, "wb") as f:
        writer.write(f)
    print(f"wrote {OUTPUT} ({len(reader.pages)} pages, {OUTPUT.stat().st_size:,} bytes); sections on pages {pages}")


if __name__ == "__main__":
    main()
