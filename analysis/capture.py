"""Start and stop packet captures, one .pcapng per experiment.

    python -m analysis.capture start --name exp1_plain_vs_protected
    python -m analysis.capture stop
    python -m analysis.capture status | list

Mode `dumpcap` (default when Wireshark is installed) wraps
    dumpcap -i \\Device\\NPF_Loopback -f "tcp port 8000 or tcp port 8443" -w captures\\<name>.pcapng
under a small supervisor process that stops it cleanly with CTRL_BREAK, so the
last packets are flushed. Mode `tap` drives analysis.tap (the recording relay)
for laptops without Npcap. PyShark never runs here: analysis is always a
separate `python -m analysis.analyze` process on the saved file.
"""
from __future__ import annotations

import argparse
import json
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from analysis.packets import dumpcap_path  # noqa: E402
from analysis.pcapfile import iter_packets  # noqa: E402
from middleware.settings import load_settings  # noqa: E402

LOOPBACK_IFACE = r"\Device\NPF_Loopback"
BPF = "tcp port 8000 or tcp port 8443"


def _dir() -> Path:
    d = load_settings().captures_dir
    d.mkdir(parents=True, exist_ok=True)
    return d


def _state_file() -> Path:
    return _dir() / ".capture.json"


def pid_alive(pid: int | None) -> bool:
    if not pid:
        return False
    if os.name == "nt":
        import ctypes
        handle = ctypes.windll.kernel32.OpenProcess(0x1000, False, int(pid))  # QUERY_LIMITED_INFORMATION
        if not handle:
            return False
        code = ctypes.c_ulong()
        ctypes.windll.kernel32.GetExitCodeProcess(handle, ctypes.byref(code))
        ctypes.windll.kernel32.CloseHandle(handle)
        return code.value == 259  # STILL_ACTIVE
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def tap_status() -> dict | None:
    f = _dir() / ".tap_status.json"
    if not f.exists():
        return None
    try:
        st = json.loads(f.read_text(encoding="utf-8"))
    except ValueError:
        return None
    if not pid_alive(st.get("pid")):
        return None
    try:
        with socket.create_connection(("127.0.0.1", st["listen"]), timeout=0.5):
            pass
    except OSError:
        return None
    return st


def status() -> dict | None:
    f = _state_file()
    if not f.exists():
        return None
    try:
        st = json.loads(f.read_text(encoding="utf-8"))
    except ValueError:
        return None
    alive = pid_alive(st.get("supervisor_pid")) if st["mode"] == "dumpcap" else tap_status() is not None
    if not alive:
        f.unlink(missing_ok=True)
        return None
    st["elapsed_s"] = round(time.time() - st["started"], 1)
    st["bytes"] = Path(st["path"]).stat().st_size if Path(st["path"]).exists() else 0
    return st


def available_modes() -> dict:
    return {"dumpcap": dumpcap_path(), "tap": tap_status()}


def start(name: str, mode: str = "auto", iface: str = LOOPBACK_IFACE) -> dict:
    if status():
        raise RuntimeError(f"a capture is already running ({status()['name']}); stop it first")
    name = "".join(ch for ch in name if ch.isalnum() or ch in "-_") or "capture"
    path = _dir() / f"{name}.pcapng"
    if mode == "auto":
        mode = "dumpcap" if dumpcap_path() else "tap" if tap_status() else "none"
    if mode == "none":
        raise RuntimeError("No capture method: install Wireshark with Npcap (tick 'Support loopback traffic capture'), "
                           "or run the recording relay: python scripts\\run_demo.py --tap")
    path.unlink(missing_ok=True)
    (_dir() / ".capture.stop").unlink(missing_ok=True)

    if mode == "tap":
        if not tap_status():
            raise RuntimeError("the tap is not running (python -m analysis.tap, server on port 8001)")
        (_dir() / ".tap_capture.json").write_text(json.dumps({"name": name, "path": str(path)}), encoding="utf-8")
        state = {"mode": "tap", "name": name, "path": str(path), "started": time.time()}
        _state_file().write_text(json.dumps(state), encoding="utf-8")
        for _ in range(20):
            if path.exists():
                break
            time.sleep(0.1)
        return state

    log = _dir() / f".{name}.dumpcap.log"
    flags = 0
    if os.name == "nt":
        flags = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW
    cmd = [sys.executable, "-m", "analysis.capture", "_supervise", "--name", name, "--path", str(path), "--iface", iface]
    with open(log, "w") as lf:
        try:
            subprocess.Popen(cmd, cwd=ROOT, creationflags=flags | getattr(subprocess, "CREATE_BREAKAWAY_FROM_JOB", 0),
                             stdout=lf, stderr=lf)
        except OSError:
            subprocess.Popen(cmd, cwd=ROOT, creationflags=flags, stdout=lf, stderr=lf)
    for _ in range(60):  # wait for dumpcap to open the file (or fail)
        st = status()
        if st and path.exists():
            time.sleep(0.8)  # let dumpcap finish starting before traffic begins
            return st
        if not st and _state_file().exists() is False and (_dir() / f".{name}.failed").exists():
            break
        time.sleep(0.1)
    err = log.read_text(errors="replace").strip() if log.exists() else ""
    (_dir() / f".{name}.failed").unlink(missing_ok=True)
    raise RuntimeError(f"dumpcap did not start. {err[-600:]}")


def stop(timeout: float = 10) -> dict:
    st = status()
    if not st:
        raise RuntimeError("no capture is running")
    path = Path(st["path"])
    if st["mode"] == "tap":
        (_dir() / ".tap_capture.json").unlink(missing_ok=True)
        deadline = time.time() + 3
        while time.time() < deadline:
            ts = tap_status()
            if not ts or ts.get("recording") is None:
                break
            time.sleep(0.1)
        _state_file().unlink(missing_ok=True)
    else:
        (_dir() / ".capture.stop").write_text("stop", encoding="utf-8")
        deadline = time.time() + timeout
        while _state_file().exists() and time.time() < deadline:
            time.sleep(0.1)
    packets = sum(1 for _ in iter_packets(path)) if path.exists() else 0
    return {"name": st["name"], "path": str(path), "mode": st["mode"], "packets": packets,
            "bytes": path.stat().st_size if path.exists() else 0, "seconds": round(time.time() - st["started"], 1)}


def supervise(name: str, path: str, iface: str) -> None:
    """Runs detached: owns dumpcap, stops it with CTRL_BREAK when the stop file appears."""
    d = _dir()
    stop_file, failed = d / ".capture.stop", d / f".{name}.failed"
    exe = dumpcap_path()
    if not exe:
        failed.write_text("dumpcap not found", encoding="utf-8")
        print("dumpcap not found", flush=True)
        return
    flags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
    proc = subprocess.Popen([exe, "-i", iface, "-f", BPF, "-w", path, "-q"], creationflags=flags)
    _state_file().write_text(json.dumps({"mode": "dumpcap", "name": name, "path": path, "supervisor_pid": os.getpid(),
                                         "dumpcap_pid": proc.pid, "iface": iface, "filter": BPF,
                                         "started": time.time()}), encoding="utf-8")
    try:
        while proc.poll() is None and not stop_file.exists():
            time.sleep(0.2)
        if proc.poll() is None:
            try:
                os.kill(proc.pid, signal.CTRL_BREAK_EVENT if os.name == "nt" else signal.SIGINT)
                proc.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                proc.terminate()
                proc.wait(timeout=5)
        else:
            failed.write_text(f"dumpcap exited with {proc.returncode}", encoding="utf-8")
            print(f"dumpcap exited with code {proc.returncode}", flush=True)
    finally:
        stop_file.unlink(missing_ok=True)
        _state_file().unlink(missing_ok=True)


def list_captures() -> list[dict]:
    out = []
    for p in sorted(_dir().glob("*.pcap*"), key=lambda p: p.stat().st_mtime, reverse=True):
        out.append({"name": p.stem, "path": str(p), "bytes": p.stat().st_size, "modified": p.stat().st_mtime})
    return out


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("start")
    s.add_argument("--name", required=True)
    s.add_argument("--mode", choices=["auto", "dumpcap", "tap"], default="auto")
    s.add_argument("--iface", default=LOOPBACK_IFACE)
    sub.add_parser("stop")
    sub.add_parser("status")
    sub.add_parser("list")
    sv = sub.add_parser("_supervise")
    sv.add_argument("--name", required=True)
    sv.add_argument("--path", required=True)
    sv.add_argument("--iface", default=LOOPBACK_IFACE)
    a = ap.parse_args()

    try:
        if a.cmd == "start":
            st = start(a.name, a.mode, a.iface)
            print(f"capturing ({st['mode']}) → {st['path']}")
        elif a.cmd == "stop":
            r = stop()
            print(f"stopped {r['name']} ({r['mode']}): {r['packets']} packets, {r['bytes']:,} bytes in {r['seconds']} s → {r['path']}")
        elif a.cmd == "status":
            st = status()
            modes = available_modes()
            print(json.dumps({"capture": st, "dumpcap": modes["dumpcap"], "tap": modes["tap"]}, indent=2))
        elif a.cmd == "list":
            for c in list_captures():
                print(f"{c['bytes']:>12,}  {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(c['modified']))}  {c['path']}")
        elif a.cmd == "_supervise":
            supervise(a.name, a.path, a.iface)
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
