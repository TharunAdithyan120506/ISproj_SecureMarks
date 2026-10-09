"""Packet readers: PyShark (primary, needs tshark from Wireshark) or the pure
Python pcapng reader (fallback). Both return the same Segment list plus
per-stream flow statistics, so everything downstream is engine-agnostic."""
from __future__ import annotations

import shutil
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from .httpparse import Segment
from .pcapfile import TCP_ACK, TCP_FIN, TCP_RST, TCP_SYN, decode_tcp, iter_packets

HTTP_PORTS = (8000, 8001)
TLS_PORTS = (8443,)
WIRESHARK_DIR = Path(r"C:\Program Files\Wireshark")


def tshark_path() -> str | None:
    found = shutil.which("tshark")
    if found:
        return found
    candidate = WIRESHARK_DIR / "tshark.exe"
    return str(candidate) if candidate.exists() else None


def dumpcap_path() -> str | None:
    found = shutil.which("dumpcap")
    if found:
        return found
    candidate = WIRESHARK_DIR / "dumpcap.exe"
    return str(candidate) if candidate.exists() else None


@dataclass
class Flow:
    stream: int
    client: str
    server: str
    cport: int
    sport: int
    packets: int = 0
    bytes: int = 0
    payload_bytes: int = 0
    first_ts: float = 0.0
    last_ts: float = 0.0
    retrans: int = 0
    tls_payload: bytearray = field(default_factory=bytearray)


@dataclass
class CaptureData:
    segments: list[Segment]
    flows: dict[int, Flow]
    engine: str
    packets: int
    # every TCP packet on the server ports: (frame, ts, src, dst, sport, dport, stream, length, payload_len)
    rows: list[tuple] = field(default_factory=list)
    retrans_frames: set[int] = field(default_factory=set)


def _flow_update(flows: dict, stream: int, src: str, dst: str, sport: int, dport: int, ts: float, length: int,
                 payload: bytes, server_ports: tuple[int, ...]) -> None:
    f = flows.get(stream)
    if f is None:
        if sport in server_ports:
            f = Flow(stream, dst, src, dport, sport, first_ts=ts)
        else:
            f = Flow(stream, src, dst, sport, dport, first_ts=ts)
        flows[stream] = f
    f.packets += 1
    f.bytes += length
    f.payload_bytes += len(payload)
    f.last_ts = ts
    if f.sport in TLS_PORTS and len(f.tls_payload) < 1_000_000:
        f.tls_payload.extend(payload)


def read_capture(path: str | Path, engine: str = "auto", ports: tuple[int, ...] = HTTP_PORTS + TLS_PORTS) -> CaptureData:
    if engine == "auto":
        engine = "pyshark" if tshark_path() else "python"
    if engine == "pyshark":
        return _read_pyshark(Path(path), ports)
    return _read_python(Path(path), ports)


# --- PyShark ------------------------------------------------------------------------------------

def _read_pyshark(path: Path, ports: tuple[int, ...]) -> CaptureData:
    import pyshark

    port_filter = " || ".join(f"tcp.port=={p}" for p in ports)
    segments: list[Segment] = []
    flows: dict[int, Flow] = {}
    rows: list[tuple] = []
    retrans: set[int] = set()
    count = 0
    # Pass 1: every TCP packet on the server ports. Segments come from the ones with
    # tcp.len > 0 (the PRD's `tcp.port==8000 && tcp.len>0`); the rest feed flow stats.
    cap = pyshark.FileCapture(str(path), display_filter=f"({port_filter})", keep_packets=False,
                              tshark_path=tshark_path())
    try:
        for pkt in cap:
            count += 1
            if "IP" not in pkt or "TCP" not in pkt:
                continue
            tcp = pkt.tcp
            ts = float(pkt.sniff_timestamp)
            length = int(pkt.length)
            stream = int(tcp.stream)
            src, dst = pkt.ip.src, pkt.ip.dst
            sport, dport = int(tcp.srcport), int(tcp.dstport)
            payload = b""
            if int(getattr(tcp, "len", 0) or 0) > 0 and hasattr(tcp, "payload"):
                payload = bytes.fromhex(str(tcp.payload).replace(":", ""))
                segments.append(Segment(int(pkt.number), ts, src, dst, sport, dport, stream, int(tcp.seq),
                                        payload, length))
            rows.append((int(pkt.number), ts, src, dst, sport, dport, stream, length, len(payload)))
            _flow_update(flows, stream, src, dst, sport, dport, ts, length, payload, ports)
    finally:
        cap.close()

    # Pass 2: tshark's own retransmission analysis, counted per stream.
    cap = pyshark.FileCapture(str(path), display_filter=f"({port_filter}) && tcp.analysis.retransmission",
                              keep_packets=False, tshark_path=tshark_path())
    try:
        for pkt in cap:
            stream = int(pkt.tcp.stream)
            retrans.add(int(pkt.number))
            if stream in flows:
                flows[stream].retrans += 1
    finally:
        cap.close()
    return CaptureData(segments, flows, "pyshark", count, rows, retrans)


# --- pure Python fallback ----------------------------------------------------------------------------

def _read_python(path: Path, ports: tuple[int, ...]) -> CaptureData:
    segments: list[Segment] = []
    flows: dict[int, Flow] = {}
    stream_of: dict[frozenset, int] = {}
    closed: set[int] = set()
    base: dict[tuple, int] = {}
    rows: list[tuple] = []
    retrans: set[int] = set()
    count = next_stream = 0
    for raw in iter_packets(path):
        p = decode_tcp(raw)
        if p is None or (p.sport not in ports and p.dport not in ports):
            continue
        count += 1
        key = frozenset({(p.src, p.sport), (p.dst, p.dport)})
        syn_only = p.flags & TCP_SYN and not p.flags & TCP_ACK
        if key not in stream_of or (syn_only and stream_of[key] in closed):
            stream_of[key] = next_stream  # like tshark's tcp.stream: a new SYN after close is a new stream
            next_stream += 1
        stream = stream_of[key]
        if p.flags & (TCP_FIN | TCP_RST):
            closed.add(stream)
        dkey = (stream, p.src, p.sport)
        if dkey not in base:
            base[dkey] = (p.seq + 1) if p.flags & TCP_SYN else p.seq
        rel = (p.seq - base[dkey]) % (1 << 32)
        if p.payload:
            segments.append(Segment(p.frame, p.ts, p.src, p.dst, p.sport, p.dport, stream, rel, p.payload, p.frame_len))
        rows.append((p.frame, p.ts, p.src, p.dst, p.sport, p.dport, stream, p.frame_len, len(p.payload)))
        _flow_update(flows, stream, p.src, p.dst, p.sport, p.dport, p.ts, p.frame_len, p.payload, ports)

    # retransmissions: payload bytes already covered earlier in the same direction
    covered: dict[tuple, int] = defaultdict(int)
    for s in sorted(segments, key=lambda s: s.frame):
        k = (s.stream, s.src, s.sport)
        if s.seq + len(s.payload) <= covered[k] and len(s.payload) > 0 and covered[k] > 0:
            flows[s.stream].retrans += 1
            retrans.add(s.frame)
        covered[k] = max(covered[k], s.seq + len(s.payload))
    return CaptureData(segments, flows, "python", count, rows, retrans)
