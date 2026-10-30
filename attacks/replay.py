"""Replay resistance: resend a captured protected publish byte for byte.

    python -m attacks.replay --last                     # the SDK's captures\\last_request.bin
    python -m attacks.replay --last --delay 35          # after the 30 s window
    python -m attacks.replay --pcap captures\\exp3_replay.pcapng --path /api/marks/publish

The raw request (JWT, session ID, nonce, ciphertext and all) is sent over a
socket bound to 127.0.0.66. Expected: 409 replay_detected; with --delay 35,
409 stale_request (freshness is checked before the seen-ID set).
"""
from __future__ import annotations

import argparse
import json
import socket
import time
from urllib.parse import urlparse

from analysis.httpparse import parse_response_bytes
from middleware.settings import load_settings
from sdk.client import load_devices

from .common import AttackResult, report, with_evidence

NAME, GOAL = "replay", "Replay resistance"


def raw_from_last() -> tuple[bytes, dict]:
    s = load_settings()
    raw_path, meta_path = s.captures_dir / "last_request.bin", s.captures_dir / "last_request.json"
    if not raw_path.exists():
        raise RuntimeError("no captures\\last_request.bin yet: publish marks as t104 first (DEMO_MODE=1)")
    meta = json.loads(meta_path.read_text(encoding="utf-8")) if meta_path.exists() else {}
    return raw_path.read_bytes(), meta


FRESH_S = 25  # an immediate replay needs a capture younger than the 30 s freshness window


def capture_fresh_publish() -> None:
    """Have t104 publish once (its SDK saves the raw request), so the replay starts from a fresh capture."""
    from .common import device_client, teacher_key
    t = device_client("teacher", "t104")
    t.save_last_request = load_settings().demo_mode
    res = t.publish_marks(teacher_key(), "IT301", "240911608", 27, 45)
    if not res.ok:
        raise RuntimeError(f"could not capture a fresh publish to replay: {res.summary()}")


def raw_from_pcap(pcap: str, path: str = "/api/marks/publish", engine: str = "auto") -> tuple[bytes, dict]:
    from analysis.httpparse import build_messages, pair_messages
    from analysis.packets import HTTP_PORTS, read_capture

    data = read_capture(pcap, engine=engine)
    for req, resp in pair_messages(build_messages(data.segments, HTTP_PORTS)):
        if req.path == path and req.method == "POST" and (resp is None or resp.status == 200):
            return req.raw, {"request_id": req.headers.get("x-request-id"), "path": path, "frame": req.frames[0]}
    raise RuntimeError(f"no successful POST {path} found in {pcap}")


def send_raw(raw: bytes, base_url: str | None = None, source_ip: str | None = None,
             timeout: float = 10.0) -> tuple[int, dict, bytes, float]:
    url = urlparse(base_url or load_settings().server_url)
    host, port = url.hostname or "127.0.0.1", url.port or 80
    source_ip = source_ip or load_devices()["roles"]["attacker"]["ip"]
    t0 = time.perf_counter()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        try:
            sock.bind((source_ip, 0))
        except OSError:
            pass  # Windows fallback: the analyser still has the request ID
        sock.connect((host, port))
        sock.sendall(raw)
        buf = b""
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            buf += chunk
            try:
                status, headers, body = parse_response_bytes(buf)
                if len(body) >= int(headers.get("content-length", len(body))):
                    return status, headers, body, (time.perf_counter() - t0) * 1000
            except ValueError:
                continue
    status, headers, body = parse_response_bytes(buf)
    return status, headers, body, (time.perf_counter() - t0) * 1000


def run(source: str = "last", pcap: str | None = None, path: str = "/api/marks/publish", delay: float = 0,
        on_wait=None) -> AttackResult:
    fresh_note = None
    if source == "last" and delay <= 30:
        try:
            _raw, old = raw_from_last()
            age = time.time() - old.get("saved_at", 0)
        except RuntimeError:
            age = float("inf")
        if age > FRESH_S:
            capture_fresh_publish()
            fresh_note = "the saved publish was too old to replay at once, so t104 published again first"
    raw, meta = raw_from_pcap(pcap, path) if source == "pcap" else raw_from_last()
    expected = "409 stale_request" if delay > 30 else "409 replay_detected"
    if delay:
        end = time.time() + delay
        while time.time() < end:
            if on_wait:
                on_wait(end - time.time())
            time.sleep(min(1.0, max(0.0, end - time.time())))
    status, headers, body, ms = send_raw(raw)
    try:
        err = json.loads(body)
    except ValueError:
        err = {}
    result = AttackResult(NAME, GOAL, expected, status, err.get("error", "ok" if status == 200 else f"http_{status}"),
                          headers.get("x-request-id") or meta.get("request_id"), headers.get("x-trace-id"),
                          err.get("detail", ""))
    age = int(time.time() - meta["saved_at"]) if "saved_at" in meta else None
    result.notes.append(f"resent {len(raw)} raw bytes of POST {meta.get('path', path)} from 127.0.0.66"
                        + (f" (originally sent {age} s ago)" if age is not None else ""))
    result.notes.append(f"original request ID {meta.get('request_id')}; replay answered in {ms:.1f} ms")
    if fresh_note:
        result.notes.append(fresh_note)
    return with_evidence(result)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--last", action="store_true", help="use captures\\last_request.bin saved by the SDK")
    src.add_argument("--pcap", help="extract the request from a capture")
    ap.add_argument("--path", default="/api/marks/publish")
    ap.add_argument("--delay", type=float, default=0, help="seconds to wait before replaying")
    a = ap.parse_args()
    report(run("pcap" if a.pcap else "last", a.pcap, a.path, a.delay,
               on_wait=lambda left: print(f"\rwaiting {left:4.0f} s ", end="", flush=True)))


if __name__ == "__main__":
    main()
