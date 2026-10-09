"""Loopback tap: fallback capture for a laptop without Npcap's loopback adapter.

    python -m analysis.tap                    # listen 127.0.0.1:8000 -> server on 127.0.0.1:8001

A transparent TCP relay. Every connection is forwarded byte for byte to the
middleware; the upstream socket is bound to the client's own loopback address,
so the server still sees 127.0.0.2 / .3 / .66. While a capture is active
(`python -m analysis.capture start --name X` writes the control file), each
chunk is written to captures\\X.pcapng as an IPv4/TCP frame on a LINKTYPE_NULL
interface - the same shape Npcap's \\Device\\NPF_Loopback produces - so
Wireshark, PyShark and the analyser read it like a dumpcap file.

Honest limits: the frames are synthesised from what the relay saw (real
payload bytes, real timing, real endpoints) rather than sniffed from the
kernel, and segment sizes reflect read() chunks, not the TCP stack's.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import random
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from analysis.pcapfile import TCP_ACK, TCP_FIN, TCP_PSH, TCP_SYN, PcapngWriter, ipv4_tcp  # noqa: E402
from middleware.settings import load_settings  # noqa: E402

MSS = 65495


class Recorder:
    def __init__(self, captures_dir: Path):
        self.dir = captures_dir
        self.control = captures_dir / ".tap_capture.json"
        self.writer: PcapngWriter | None = None
        self.current: str | None = None
        self.frames = 0
        self.ip_id = random.randrange(1 << 16)

    @property
    def active(self) -> bool:
        return self.writer is not None

    def poll(self) -> None:
        want = None
        if self.control.exists():
            try:
                want = json.loads(self.control.read_text(encoding="utf-8"))["path"]
            except (ValueError, KeyError, OSError):
                want = None
        if want != self.current:
            if self.writer:
                self.writer.close()
                print(f"[tap] capture closed: {self.current} ({self.frames} frames)", flush=True)
            self.writer, self.current, self.frames = None, want, 0
            if want:
                self.writer = PcapngWriter(want)
                print(f"[tap] capturing → {want}", flush=True)

    def packet(self, src, dst, sport, dport, seq, ack, flags, payload=b"") -> None:
        if not self.writer:
            return
        self.ip_id = (self.ip_id + 1) & 0xFFFF
        self.writer.write(time.time(), ipv4_tcp(src, dst, sport, dport, seq, ack, flags, payload, self.ip_id))
        self.writer.flush()
        self.frames += 1


class Conn:
    def __init__(self, client: tuple[str, int], server: tuple[str, int]):
        self.c_ip, self.c_port = client
        self.s_ip, self.s_port = server
        self.seq = {"c2s": random.randrange(1 << 32), "s2c": random.randrange(1 << 32)}

    def ends(self, direction: str):
        if direction == "c2s":
            return self.c_ip, self.s_ip, self.c_port, self.s_port
        return self.s_ip, self.c_ip, self.s_port, self.c_port

    def other(self, direction: str) -> str:
        return "s2c" if direction == "c2s" else "c2s"


def handshake(rec: Recorder, c: Conn) -> None:
    cs, ss = c.seq["c2s"], c.seq["s2c"]
    rec.packet(c.c_ip, c.s_ip, c.c_port, c.s_port, cs, 0, TCP_SYN)
    rec.packet(c.s_ip, c.c_ip, c.s_port, c.c_port, ss, cs + 1, TCP_SYN | TCP_ACK)
    rec.packet(c.c_ip, c.s_ip, c.c_port, c.s_port, cs + 1, ss + 1, TCP_ACK)
    c.seq["c2s"], c.seq["s2c"] = cs + 1, ss + 1


def data(rec: Recorder, c: Conn, direction: str, payload: bytes) -> None:
    src, dst, sport, dport = c.ends(direction)
    back = c.other(direction)
    for i in range(0, len(payload), MSS):
        chunk = payload[i:i + MSS]
        rec.packet(src, dst, sport, dport, c.seq[direction], c.seq[back], TCP_PSH | TCP_ACK, chunk)
        c.seq[direction] = (c.seq[direction] + len(chunk)) % (1 << 32)
    rec.packet(dst, src, dport, sport, c.seq[back], c.seq[direction], TCP_ACK)


def fin(rec: Recorder, c: Conn, direction: str) -> None:
    src, dst, sport, dport = c.ends(direction)
    back = c.other(direction)
    rec.packet(src, dst, sport, dport, c.seq[direction], c.seq[back], TCP_FIN | TCP_ACK)
    c.seq[direction] = (c.seq[direction] + 1) % (1 << 32)
    rec.packet(dst, src, dport, sport, c.seq[back], c.seq[direction], TCP_ACK)


async def main_async(listen_port: int, upstream_port: int) -> None:
    settings = load_settings()
    rec = Recorder(settings.captures_dir)
    status_file = settings.captures_dir / ".tap_status.json"
    settings.captures_dir.mkdir(parents=True, exist_ok=True)

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")[:2]
        try:
            up_r, up_w = await asyncio.open_connection("127.0.0.1", upstream_port, local_addr=(peer[0], 0))
        except OSError:
            try:
                up_r, up_w = await asyncio.open_connection("127.0.0.1", upstream_port)
            except OSError:
                writer.close()
                return
        conn = Conn(peer, ("127.0.0.1", listen_port))
        rec.poll()
        handshake(rec, conn)
        closed = {"done": False}

        async def pipe(src: asyncio.StreamReader, dst: asyncio.StreamWriter, direction: str) -> None:
            try:
                while True:
                    chunk = await src.read(65536)
                    if not chunk:
                        break
                    data(rec, conn, direction, chunk)
                    dst.write(chunk)
                    await dst.drain()
            except (ConnectionError, OSError):
                pass
            finally:
                if not closed["done"]:
                    closed["done"] = True
                    fin(rec, conn, direction)
                    fin(rec, conn, conn.other(direction))
                for w in (dst, writer, up_w):
                    try:
                        w.close()
                    except (ConnectionError, OSError, RuntimeError):
                        pass

        await asyncio.gather(pipe(reader, up_w, "c2s"), pipe(up_r, writer, "s2c"), return_exceptions=True)

    async def poller() -> None:
        while True:
            rec.poll()
            status_file.write_text(json.dumps({"pid": os.getpid(), "listen": listen_port, "upstream": upstream_port,
                                               "recording": rec.current, "updated": time.time()}), encoding="utf-8")
            await asyncio.sleep(0.2)

    server = await asyncio.start_server(handle, "127.0.0.1", listen_port)
    print(f"[tap] relaying 127.0.0.1:{listen_port} → 127.0.0.1:{upstream_port}; "
          f"start/stop recording with python -m analysis.capture", flush=True)
    poll_task = asyncio.create_task(poller())
    try:
        async with server:
            await server.serve_forever()
    finally:
        poll_task.cancel()
        status_file.unlink(missing_ok=True)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--listen", type=int, default=8000)
    ap.add_argument("--upstream", type=int, default=8001)
    a = ap.parse_args()
    try:
        asyncio.run(main_async(a.listen, a.upstream))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
