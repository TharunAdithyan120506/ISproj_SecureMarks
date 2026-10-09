"""Rebuild HTTP/1.1 messages from raw TCP payloads.

Working from the raw bytes (not tshark's HTTP dissector) keeps binary
ciphertext bodies intact and avoids dissector quirks: segments are grouped by
stream and direction, ordered by sequence number (retransmitted bytes are
dropped), joined, and split into messages by headers + Content-Length.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field


@dataclass
class Segment:
    frame: int
    ts: float
    src: str
    dst: str
    sport: int
    dport: int
    stream: int
    seq: int
    payload: bytes
    frame_len: int
    retrans: bool = False

    @property
    def direction(self) -> tuple:
        return (self.src, self.sport, self.dst, self.dport)


@dataclass
class HttpMessage:
    kind: str  # request | response
    stream: int
    src: str
    dst: str
    sport: int
    dport: int
    start_ts: float
    end_ts: float
    start_line: str
    headers: dict[str, str]
    body: bytes
    raw: bytes
    wire_bytes: int
    frames: list[int] = field(default_factory=list)
    truncated: bool = False

    @property
    def method(self) -> str | None:
        return self.start_line.split(" ", 1)[0] if self.kind == "request" else None

    @property
    def path(self) -> str | None:
        parts = self.start_line.split(" ")
        return parts[1] if self.kind == "request" and len(parts) > 1 else None

    @property
    def status(self) -> int | None:
        parts = self.start_line.split(" ")
        if self.kind == "response" and len(parts) > 1 and parts[1].isdigit():
            return int(parts[1])
        return None


def _join_direction(segs: list[Segment]) -> tuple[bytes, list[tuple[int, int, Segment]]]:
    """Order by seq, drop already-covered bytes. Returns (stream bytes, [(start, end, segment)])."""
    segs = sorted(segs, key=lambda s: (s.seq, s.frame))
    buf = bytearray()
    spans: list[tuple[int, int, Segment]] = []
    base = segs[0].seq if segs else 0
    next_seq = base
    for s in segs:
        end = s.seq + len(s.payload)
        if end <= next_seq:
            s.retrans = True
            continue
        if s.seq > next_seq:  # gap (lost packet in capture): keep going, offsets stay consistent
            buf.extend(b"\0" * (s.seq - next_seq))
            next_seq = s.seq
        new = s.payload[next_seq - s.seq:]
        if s.seq < next_seq:
            s.retrans = True
        start = len(buf)
        buf.extend(new)
        spans.append((start, len(buf), s))
        next_seq = end
    return bytes(buf), spans


def _parse_messages(data: bytes, kind: str) -> list[tuple[int, int, str, dict, bytes, bool]]:
    """Split a byte stream into (start, end, start_line, headers, body, truncated)."""
    out = []
    pos = 0
    while pos < len(data):
        head_end = data.find(b"\r\n\r\n", pos)
        if head_end < 0:
            break
        head = data[pos:head_end].decode("latin-1")
        lines = head.split("\r\n")
        start_line = lines[0]
        looks_right = start_line.startswith("HTTP/") if kind == "response" else (" HTTP/1." in start_line)
        if not looks_right:
            nxt = data.find(b"\r\n", pos)
            if nxt < 0:
                break
            pos = nxt + 2
            continue
        headers = {}
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        body_start = head_end + 4
        truncated = False
        if headers.get("transfer-encoding", "").lower() == "chunked":
            body, end, truncated = _dechunk(data, body_start)
        else:
            length = int(headers.get("content-length", "0") or 0)
            end = body_start + length
            if end > len(data):
                truncated, end = True, len(data)
            body = data[body_start:end]
        out.append((pos, end, start_line, headers, body, truncated))
        pos = end
    return out


def _dechunk(data: bytes, pos: int) -> tuple[bytes, int, bool]:
    body = bytearray()
    while True:
        line_end = data.find(b"\r\n", pos)
        if line_end < 0:
            return bytes(body), len(data), True
        try:
            size = int(data[pos:line_end].split(b";")[0], 16)
        except ValueError:
            return bytes(body), len(data), True
        pos = line_end + 2
        if size == 0:
            trailer_end = data.find(b"\r\n", pos)
            return bytes(body), (trailer_end + 2 if trailer_end >= 0 else len(data)), False
        body.extend(data[pos:pos + size])
        pos += size + 2
        if pos > len(data):
            return bytes(body), len(data), True


def build_messages(segments: list[Segment], server_ports: tuple[int, ...]) -> list[HttpMessage]:
    by_dir: dict[tuple, list[Segment]] = defaultdict(list)
    for s in segments:
        if s.payload:
            by_dir[(s.stream,) + s.direction].append(s)
    messages: list[HttpMessage] = []
    for key, segs in by_dir.items():
        stream, src, sport, dst, dport = key
        kind = "request" if dport in server_ports else "response" if sport in server_ports else None
        if kind is None:
            continue
        data, spans = _join_direction(segs)
        for start, end, start_line, headers, body, truncated in _parse_messages(data, kind):
            covering = [seg for (a, b, seg) in spans if a < end and b > start]
            if not covering:
                continue
            messages.append(HttpMessage(
                kind=kind, stream=stream, src=src, dst=dst, sport=sport, dport=dport,
                start_ts=min(c.ts for c in covering), end_ts=max(c.ts for c in covering),
                start_line=start_line, headers=headers, body=body, raw=data[start:end],
                wire_bytes=sum(c.frame_len for c in covering), frames=[c.frame for c in covering],
                truncated=truncated))
    messages.sort(key=lambda m: (m.start_ts, m.kind != "request"))
    return messages


def pair_messages(messages: list[HttpMessage]) -> list[tuple[HttpMessage, HttpMessage | None]]:
    """n-th request with n-th response in each stream (keep-alive keeps them in order)."""
    reqs: dict[int, list[HttpMessage]] = defaultdict(list)
    resps: dict[int, list[HttpMessage]] = defaultdict(list)
    for m in messages:
        (reqs if m.kind == "request" else resps)[m.stream].append(m)
    pairs = []
    for stream, rlist in reqs.items():
        rlist.sort(key=lambda m: m.start_ts)
        plist = sorted(resps.get(stream, []), key=lambda m: m.start_ts)
        for i, req in enumerate(rlist):
            pairs.append((req, plist[i] if i < len(plist) else None))
    pairs.sort(key=lambda p: p[0].start_ts)
    return pairs


def parse_response_bytes(data: bytes) -> tuple[int, dict, bytes]:
    """Parse one raw HTTP response (used by replay.py)."""
    parsed = _parse_messages(data, "response")
    if not parsed:
        raise ValueError("no HTTP response in data")
    _, _, start_line, headers, body, _ = parsed[0]
    return int(start_line.split(" ")[1]), headers, body
