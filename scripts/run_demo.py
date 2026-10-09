"""Start the demo: middleware, (tap), portal - each in its own console window.

    python scripts\\run_demo.py            # auto: tap mode if Wireshark/dumpcap is missing
    python scripts\\run_demo.py --tap      # force the recording relay (server on 8001, tap on 8000)
    python scripts\\run_demo.py --tls      # also the P1 HTTPS server on 8443
    python scripts\\run_demo.py --reset    # setup_demo.py --reset first (stop old windows before!)

The server window is the "third screen": one coloured line per check.
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import time
import urllib.request
import webbrowser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from analysis.packets import dumpcap_path  # noqa: E402

PY = sys.executable
ENV = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUTF8="1")


def launch(title: str, args: list[str]) -> None:
    if os.name == "nt":
        cmdline = subprocess.list2cmdline(args)
        subprocess.Popen(["cmd", "/k", f"title {title} && {cmdline}"], cwd=ROOT, env=ENV,
                         creationflags=subprocess.CREATE_NEW_CONSOLE)
    else:
        subprocess.Popen(args, cwd=ROOT, env=ENV)
    print(f"  started {title}: {' '.join(args[1:])}")


def wait_http(url: str, seconds: float = 20) -> bool:
    end = time.time() + seconds
    while time.time() < end:
        try:
            with urllib.request.urlopen(url, timeout=1) as r:
                if r.status == 200:
                    return True
        except OSError:
            time.sleep(0.4)
    return False


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--tap", action="store_true", help="force tap mode (no Npcap needed)")
    ap.add_argument("--tls", action="store_true", help="also run the HTTPS server on 8443 (P1)")
    ap.add_argument("--reset", action="store_true", help="run setup_demo.py --reset first")
    ap.add_argument("--no-portal", action="store_true")
    ap.add_argument("--no-browser", action="store_true")
    a = ap.parse_args()

    if a.reset or not (ROOT / ".env").exists():
        subprocess.run([PY, str(ROOT / "scripts" / "setup_demo.py"), "--reset"], cwd=ROOT, env=ENV, check=True)

    tap = a.tap or not dumpcap_path()
    server_port = 8001 if tap else 8000
    print(f"SecureMarks demo · capture mode: {'tap (recording relay)' if tap else 'dumpcap (Npcap loopback)'}")
    uvicorn = [PY, "-m", "uvicorn", "middleware.main:app", "--host", "127.0.0.1", "--workers", "1", "--no-access-log"]
    launch("SecureMarks server", uvicorn + ["--port", str(server_port)])
    if tap:
        launch("SecureMarks tap", [PY, "-m", "analysis.tap", "--listen", "8000", "--upstream", str(server_port)])
    if a.tls:
        launch("SecureMarks TLS server", uvicorn + ["--port", "8443", "--ssl-keyfile", "secrets/server.key",
                                                    "--ssl-certfile", "secrets/server.crt"])
    ok = wait_http("http://127.0.0.1:8000/health")
    print(f"  middleware {'up' if ok else 'NOT reachable'} at http://127.0.0.1:8000")
    if not a.no_portal:
        launch("SecureMarks portal", [PY, "-m", "streamlit", "run", "portal/Home.py"])
        if wait_http("http://localhost:8501", 40) and not a.no_browser:
            webbrowser.open("http://localhost:8501")
        print("  portal at http://localhost:8501 (open a second window for the student)")
    if not shutil.which("tshark") and not Path(r"C:\Program Files\Wireshark\tshark.exe").exists():
        print("  note: tshark not found - the analyser uses its built-in pcapng reader instead of PyShark")


if __name__ == "__main__":
    main()
