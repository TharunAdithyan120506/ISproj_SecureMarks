"""Attack lab, traffic lab, benchmarks and the analysis report.

Long jobs (attacks, experiments, benchmark, report) run as `python -m ...` in
their own process and stream their output; only allow-listed modules can run.
PyShark never runs inside this server.
"""
from __future__ import annotations

import csv
import json
import os
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel

from analysis import capture
from analysis.experiments import EXPERIMENTS
from analysis.packets import WIRESHARK_DIR
from attacks import CATALOG
from middleware.settings import ROOT, load_settings

router = APIRouter(prefix="/api/ops")

OUT_DIRS = {"analysis": ROOT / "analysis" / "out", "bench": ROOT / "bench" / "out", "lab": ROOT / "cryptolab" / "out",
            "docs": ROOT / "docs" / "figures"}


def _env() -> dict:
    return dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUTF8="1", COLUMNS="120")


def run_module(*args: str, timeout: float = 600) -> subprocess.CompletedProcess:
    """Run `python -m ...`; a timeout or launch failure comes back as a failed result, never a 500."""
    cmd = [sys.executable, "-m", *args]
    try:
        return subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, encoding="utf-8",
                              errors="replace", env=_env(), timeout=timeout)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(cmd, 1, "", f"python -m {' '.join(args)} timed out after {timeout:.0f} s")
    except OSError as exc:
        return subprocess.CompletedProcess(cmd, 1, "", f"could not start python -m {args[0]}: {exc}")


def stream_module(*args: str) -> StreamingResponse:
    """Run `python -u -m ...` and stream stdout+stderr line by line (text/plain)."""
    def gen():
        proc = subprocess.Popen([sys.executable, "-u", "-m", *args], cwd=ROOT, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace", env=_env())
        yield f"$ python -m {' '.join(args)}\n"
        try:
            for line in proc.stdout:
                yield line
        finally:
            proc.wait(timeout=5)
        yield f"\n[exit {proc.returncode}]\n"
    return StreamingResponse(gen(), media_type="text/plain; charset=utf-8",
                             headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})


def _ro() -> sqlite3.Connection:
    db = load_settings().db_path
    if not db.exists():
        raise HTTPException(503, "no database yet: run python scripts\\setup_demo.py --reset")
    con = sqlite3.connect(f"file:{db.as_posix()}?mode=ro", uri=True, timeout=10)
    con.row_factory = sqlite3.Row
    return con


# --- attack lab --------------------------------------------------------------------------------------

def _attack_args(key: str) -> list[str]:
    for k, _title, _goal, _expected, cli in CATALOG:
        if k == key:
            return cli.split()[2:]  # drop "python -m"
    raise HTTPException(404, f"unknown attack {key}")


@router.get("/attacks")
def attacks():
    return [{"key": k, "title": t, "goal": g, "expected": e, "command": c} for k, t, g, e, c in CATALOG]


@router.post("/attacks/{key}/run")
def run_attack(key: str):
    return stream_module(*_attack_args(key))


@router.post("/attacks/restore")
def restore():
    r = run_module("attacks.tamper_db", "--restore", timeout=60)
    return {"output": (r.stdout or r.stderr)[-3000:], "code": r.returncode}


@router.get("/evidence")
def evidence(limit: int = 50, device: str | None = None):
    con = _ro()
    try:
        q = ("SELECT id, ts, request_id, device, src_ip, actor, action, outcome, code, detail FROM audit_log "
             "WHERE outcome != 'allowed'" + (" AND device = ?" if device else "") + " ORDER BY id DESC LIMIT ?")
        rows = [dict(r) for r in con.execute(q, ([device] if device else []) + [min(limit, 500)])]
    finally:
        con.close()
    counts: dict[str, int] = {}
    for r in rows:
        counts[r["code"]] = counts.get(r["code"], 0) + 1
    return {"rows": rows, "counts": counts}


@router.get("/trace/{request_id}")
def trace(request_id: str):
    con = _ro()
    try:
        steps = [dict(r) for r in con.execute(
            "SELECT step, detail, ok, ts FROM trace_events WHERE request_id = ? ORDER BY id", [request_id])]
    finally:
        con.close()
    return steps


# --- traffic lab -------------------------------------------------------------------------------------

@router.get("/capture")
def capture_status():
    try:
        caps = [c for c in capture.list_captures() if c["path"].endswith((".pcapng", ".pcap"))]
    except OSError:
        caps = []
    for c in caps:
        c["analysed"] = (OUT_DIRS["analysis"] / Path(c["path"]).stem / "summary.json").exists()
    return {"modes": capture.available_modes(), "current": capture.status(), "captures": caps,
            "wireshark": (WIRESHARK_DIR / "Wireshark.exe").exists(),
            "experiments": [{"key": k, "name": v[0], "title": v[1]} for k, v in EXPERIMENTS.items()]}


class CaptureBody(BaseModel):
    name: str = "exp_live"


@router.post("/capture/start")
def capture_start(b: CaptureBody):
    name = "".join(ch for ch in b.name if ch.isalnum() or ch in "_-")[:48] or "exp_live"
    r = run_module("analysis.capture", "start", "--name", name, timeout=60)
    return {"output": (r.stdout or r.stderr).strip(), "code": r.returncode}


@router.post("/capture/stop")
def capture_stop():
    r = run_module("analysis.capture", "stop", timeout=60)
    return {"output": (r.stdout or r.stderr).strip(), "code": r.returncode}


def _capture_path(name: str) -> str:
    for c in capture.list_captures():
        if c["name"] == name:
            return c["path"]
    raise HTTPException(404, f"no capture named {name}")


@router.post("/capture/{name}/{action}")
def capture_action(name: str, action: str):
    path = _capture_path(name)
    if action == "analyse":
        r = run_module("analysis.analyze", path, "--audit", str(load_settings().db_path), "--json")
    elif action == "sqlite":
        r = run_module("analysis.pcap_to_sqlite", path, "--json")
    elif action == "xml":
        r = run_module("analysis.pcap_to_xml", path)
    elif action == "wireshark":
        if (WIRESHARK_DIR / "Wireshark.exe").exists() and hasattr(os, "startfile"):
            os.startfile(path)  # noqa: S606 - opens a local file in the local Wireshark
            return {"output": f"opened {path} in Wireshark", "code": 0}
        return {"output": f"Wireshark is not installed; the capture is at {path}", "code": 1}
    else:
        raise HTTPException(404, "unknown action")
    return {"output": ((r.stdout if r.returncode == 0 else r.stderr) or "").strip()[-3000:], "code": r.returncode}


@router.post("/experiments/{key}/run")
def run_experiment(key: str):
    if key not in EXPERIMENTS:
        raise HTTPException(404, "unknown experiment")
    return stream_module("analysis.experiments", key)


def _read_csv(path: Path, limit: int = 2000) -> list[dict]:
    if not path.exists() or path.stat().st_size < 3:
        return []
    with path.open(encoding="utf-8", newline="") as f:
        return [row for _, row in zip(range(limit), csv.DictReader(f))]


@router.get("/capture/{name}/results")
def capture_results(name: str):
    out = OUT_DIRS["analysis"] / name
    summary = out / "summary.json"
    if not summary.exists():
        raise HTTPException(404, "not analysed yet")
    return {"summary": json.loads(summary.read_text(encoding="utf-8")),
            "figures": [f"analysis/{name}/{p.name}" for p in sorted(out.glob("*.png"))],
            "tables": {n: _read_csv(out / f"{n}.csv") for n in ("messages", "flows", "flags", "audit_join")}}


# --- benchmarks and report ---------------------------------------------------------------------------

@router.post("/bench/run")
def bench_run():
    return stream_module("bench.bench", "--quick")


@router.get("/bench")
def bench_results():
    out = OUT_DIRS["bench"]
    rows = _read_csv(out / "results.csv", 5000)
    meta = json.loads((out / "results.json").read_text(encoding="utf-8")) if (out / "results.json").exists() else {}
    probe = _read_csv(ROOT / "analysis" / "out" / "flood_probe.csv", 5000)
    return {"rows": rows, "meta": {k: v for k, v in meta.items() if k != "rows"}, "flood_probe": probe,
            "figures": [f"bench/{p.name}" for p in sorted(out.glob("*.png"))]}


@router.post("/report/run")
def report_run():
    return stream_module("cryptolab.report")


@router.get("/report")
def report():
    path = OUT_DIRS["lab"] / "report.json"
    if not path.exists():
        raise HTTPException(404, "no report yet: run python -m cryptolab.report")
    data = json.loads(path.read_text(encoding="utf-8"))
    data["figure_urls"] = [f"lab/{name}" for name in data.get("figures", [])]
    data["modified"] = path.stat().st_mtime
    return data


@router.get("/file/{area}/{path:path}")
def file(area: str, path: str):
    """PNG / CSV / JSON / XML outputs, confined to the known output folders."""
    base = OUT_DIRS.get(area)
    if base is None:
        raise HTTPException(404)
    target = (base / path).resolve()
    if base.resolve() not in target.parents or not target.is_file() or target.suffix not in {".png", ".csv", ".json", ".xml"}:
        raise HTTPException(404)
    return FileResponse(target, headers={"Cache-Control": "no-cache"})


@router.get("/time")
def server_time():
    return {"time": time.time()}
