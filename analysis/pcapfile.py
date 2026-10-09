"""Minimal pcap / pcapng reader and pcapng writer (standard library only).

The reader is the fallback when tshark (and therefore PyShark) is not
installed; the writer is used by the loopback tap (analysis/tap.py). Both
handle the link types a loopback capture produces: NULL/loopback (Npcap's
\\Device\\NPF_Loopback), Ethernet, raw IPv4 and Linux cooked.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

LINKTYPE_NULL, LINKTYPE_ETHERNET, LINKTYPE_RAW, LINKTYPE_IPV4 = 0, 1, 101, 228
LINKTYPE_SLL, LINKTYPE_SLL2 = 113, 276

TCP_FIN, TCP_SYN, TCP_RST, TCP_PSH, TCP_ACK = 0x01, 0x02, 0x04, 0x08, 0x10


@dataclass
class RawPacket:
    frame: int
    ts: float
    linktype: int
    data: bytes
    orig_len: int


@dataclass
class TcpPacket:
    frame: int
    ts: float
    src: str
    dst: str
    sport: int
    dport: int
    seq: int
    ack: int
    flags: int
    payload: bytes
    frame_len: int


# --- reading ------------------------------------------------------------------------------

def iter_packets(path: str | Path) -> Iterator[RawPacket]:
    with open(path, "rb") as f:
        magic = f.read(4)
        f.seek(0)
        if magic == b"\x0a\x0d\x0d\x0a":
            yield from _iter_pcapng(f)
        elif magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
            yield from _iter_pcap(f)
        else:
            raise ValueError(f"{path} is not a pcap or pcapng file")


def _iter_pcap(f) -> Iterator[RawPacket]:
    header = f.read(24)
    magic = header[:4]
    endian = "<" if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
    nano = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
    linktype = struct.unpack(endian + "I", header[20:24])[0] & 0xFFFF
    frame = 0
    while True:
        rec = f.read(16)
        if len(rec) < 16:
            return
        sec, frac, incl, orig = struct.unpack(endian + "IIII", rec)
        data = f.read(incl)
        if len(data) < incl:
            return
        frame += 1
        yield RawPacket(frame, sec + frac / (1e9 if nano else 1e6), linktype, data, orig)


def _iter_pcapng(f) -> Iterator[RawPacket]:
    endian = "<"
    interfaces: list[tuple[int, float]] = []  # (linktype, seconds per tick)
    frame = 0
    while True:
        head = f.read(8)
        if len(head) < 8:
            return
        btype_raw = head[:4]
        if btype_raw == b"\x0a\x0d\x0d\x0a":
            bom = f.read(4)
            endian = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
            total = struct.unpack(endian + "I", head[4:8])[0]
            f.seek(total - 12, 1)
            interfaces = []
            continue
        btype, total = struct.unpack(endian + "II", head)
        if total < 12:
            return
        body = f.read(total - 8)
        if len(body) < total - 8:
            return  # truncated final block (capture stopped mid-write)
        body = body[:-4]
        if btype == 1:  # Interface Description Block
            linktype = struct.unpack(endian + "H", body[:2])[0]
            interfaces.append((linktype, _tsresol(body[8:], endian)))
        elif btype == 6:  # Enhanced Packet Block
            iface, hi, lo, cap_len, orig_len = struct.unpack(endian + "IIIII", body[:20])
            linktype, unit = interfaces[iface] if iface < len(interfaces) else (LINKTYPE_ETHERNET, 1e-6)
            frame += 1
            yield RawPacket(frame, ((hi << 32) | lo) * unit, linktype, body[20:20 + cap_len], orig_len)
        elif btype == 3:  # Simple Packet Block
            orig_len = struct.unpack(endian + "I", body[:4])[0]
            linktype = interfaces[0][0] if interfaces else LINKTYPE_ETHERNET
            frame += 1
            yield RawPacket(frame, 0.0, linktype, body[4:4 + orig_len], orig_len)
        elif btype == 2:  # obsolete Packet Block
            iface, _drops, hi, lo, cap_len, orig_len = struct.unpack(endian + "HHIIII", body[:20])
            linktype, unit = interfaces[iface] if iface < len(interfaces) else (LINKTYPE_ETHERNET, 1e-6)
            frame += 1
            yield RawPacket(frame, ((hi << 32) | lo) * unit, linktype, body[20:20 + cap_len], orig_len)


def _tsresol(options: bytes, endian: str) -> float:
    pos = 0
    while pos + 4 <= len(options):
        code, length = struct.unpack(endian + "HH", options[pos:pos + 4])
        if code == 0:
            break
        value = options[pos + 4:pos + 4 + length]
        if code == 9 and value:
            v = value[0]
            return 2.0 ** -(v & 0x7F) if v & 0x80 else 10.0 ** -v
        pos += 4 + ((length + 3) & ~3)
    return 1e-6


def _ip_payload(linktype: int, data: bytes) -> bytes | None:
    if linktype == LINKTYPE_NULL:
        family = struct.unpack("<I", data[:4])[0]
        if family not in (2,) and struct.unpack(">I", data[:4])[0] != 2:
            return None
        return data[4:]
    if linktype == LINKTYPE_ETHERNET:
        off, ethertype = 14, struct.unpack(">H", data[12:14])[0]
        while ethertype in (0x8100, 0x88A8):
            ethertype = struct.unpack(">H", data[off + 2:off + 4])[0]
            off += 4
        return data[off:] if ethertype == 0x0800 else None
    if linktype in (LINKTYPE_RAW, LINKTYPE_IPV4, 12, 14):
        return data
    if linktype == LINKTYPE_SLL:
        return data[16:] if struct.unpack(">H", data[14:16])[0] == 0x0800 else None
    if linktype == LINKTYPE_SLL2:
        return data[20:] if struct.unpack(">H", data[0:2])[0] == 0x0800 else None
    return None


def decode_tcp(pkt: RawPacket) -> TcpPacket | None:
    ip = _ip_payload(pkt.linktype, pkt.data)
    if not ip or len(ip) < 20 or ip[0] >> 4 != 4:
        return None
    ihl = (ip[0] & 0x0F) * 4
    total = struct.unpack(">H", ip[2:4])[0] or len(ip)  # 0 = TSO / large-send on loopback
    if ip[9] != 6:
        return None
    src, dst = ".".join(map(str, ip[12:16])), ".".join(map(str, ip[16:20]))
    tcp = ip[ihl:total]
    if len(tcp) < 20:
        return None
    sport, dport, seq, ack, off_flags = struct.unpack(">HHIIH", tcp[:14])
    doff = (off_flags >> 12) * 4
    return TcpPacket(pkt.frame, pkt.ts, src, dst, sport, dport, seq, ack, off_flags & 0x3F, tcp[doff:],
                     max(pkt.orig_len, len(pkt.data)))


# --- writing (used by the tap) --------------------------------------------------------------------

def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack(f">{len(data) // 2}H", data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def ipv4_tcp(src: str, dst: str, sport: int, dport: int, seq: int, ack: int, flags: int,
             payload: bytes = b"", ip_id: int = 0, window: int = 65535) -> bytes:
    s, d = bytes(map(int, src.split("."))), bytes(map(int, dst.split(".")))
    tcp_wo = struct.pack(">HHIIBBHHH", sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF, 5 << 4, flags, window, 0, 0)
    pseudo = s + d + struct.pack(">BBH", 0, 6, len(tcp_wo) + len(payload))
    csum = _checksum(pseudo + tcp_wo + payload)
    tcp = tcp_wo[:16] + struct.pack(">H", csum) + tcp_wo[18:]
    total = 20 + len(tcp) + len(payload)
    ip_wo = struct.pack(">BBHHHBBH4s4s", 0x45, 0, total, ip_id & 0xFFFF, 0x4000, 128, 6, 0, s, d)
    ip = ip_wo[:10] + struct.pack(">H", _checksum(ip_wo)) + ip_wo[12:]
    return ip + tcp + payload


class PcapngWriter:
    """Writes LINKTYPE_NULL frames (4-byte AF_INET header + IPv4), like Npcap's loopback adapter."""

    def __init__(self, path: str | Path, if_name: str = "SecureMarks loopback tap"):
        self.f = open(path, "wb")
        shb_body = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1) + _opt(4, b"SecureMarks analysis.tap") + _opt(0, b"")
        self._block(0x0A0D0D0A, shb_body)
        idb_body = struct.pack("<HHI", LINKTYPE_NULL, 0, 262144) + _opt(2, if_name.encode()) + _opt(9, b"\x06") + _opt(0, b"")
        self._block(1, idb_body)
        self.f.flush()

    def _block(self, btype: int, body: bytes) -> None:
        total = 12 + len(body)
        self.f.write(struct.pack("<II", btype, total) + body + struct.pack("<I", total))

    def write(self, ts: float, ip_packet: bytes) -> None:
        frame = struct.pack("<I", 2) + ip_packet
        ticks = int(ts * 1e6)
        pad = b"\0" * ((4 - len(frame) % 4) % 4)
        body = struct.pack("<IIIII", 0, ticks >> 32, ticks & 0xFFFFFFFF, len(frame), len(frame)) + frame + pad
        self._block(6, body)

    def flush(self) -> None:
        self.f.flush()

    def close(self) -> None:
        self.f.close()


def _opt(code: int, value: bytes) -> bytes:
    if code == 0:
        return struct.pack("<HH", 0, 0)
    pad = b"\0" * ((4 - len(value) % 4) % 4)
    return struct.pack("<HH", code, len(value)) + value + pad
