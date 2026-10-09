"""PCAP -> XML (P1).

    python -m analysis.pcap_to_xml captures\\exp1_plain_vs_protected.pcapng

With Wireshark installed this is exactly
    tshark -r <pcap> -T pdml > analysis\\out\\<name>.xml
Without tshark it writes a compact XML of the packets and HTTP messages that
the pure-Python reader recovers (same shape every time, not PDML).
"""
from __future__ import annotations

import argparse
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from analysis.analyze import device_map  # noqa: E402
from analysis.httpparse import build_messages  # noqa: E402
from analysis.packets import HTTP_PORTS, read_capture, tshark_path  # noqa: E402
from middleware.crypto.hashing import entropy  # noqa: E402


def to_xml(pcap: Path, out: Path | None = None, engine: str = "auto") -> tuple[Path, str]:
    out = out or ROOT / "analysis" / "out" / f"{pcap.stem}.xml"
    out.parent.mkdir(parents=True, exist_ok=True)
    tshark = tshark_path()
    if tshark and engine != "python":
        with open(out, "wb") as f:
            subprocess.run([tshark, "-r", str(pcap), "-T", "pdml"], stdout=f, check=True)
        return out, "pdml"

    data = read_capture(pcap, engine="python")
    devices = device_map()
    root = ET.Element("capture", file=pcap.name, engine="python", packets=str(data.packets))
    pk = ET.SubElement(root, "packets")
    for s in data.segments:
        ET.SubElement(pk, "packet", frame=str(s.frame), ts=f"{s.ts:.6f}", src=s.src, dst=s.dst, sport=str(s.sport),
                      dport=str(s.dport), stream=str(s.stream), length=str(s.frame_len), payload=str(len(s.payload)))
    msgs = ET.SubElement(root, "http_messages")
    for m in build_messages(data.segments, HTTP_PORTS):
        el = ET.SubElement(msgs, m.kind, stream=str(m.stream), ts=f"{m.start_ts:.6f}", src=m.src,
                           device=devices.get(m.src, m.headers.get("x-device", "unknown")),
                           body_bytes=str(len(m.body)), wire_bytes=str(m.wire_bytes),
                           body_entropy=f"{entropy(m.body):.3f}")
        ET.SubElement(el, "start_line").text = m.start_line
        hdrs = ET.SubElement(el, "headers")
        for k, v in m.headers.items():
            ET.SubElement(hdrs, "header", name=k).text = v
        body = ET.SubElement(el, "body", encoding="text" if m.headers.get("content-type", "").startswith("application/json") else "hex")
        body.text = m.body.decode("utf-8", "replace") if body.get("encoding") == "text" else m.body[:256].hex()
    ET.indent(root)
    ET.ElementTree(root).write(out, encoding="utf-8", xml_declaration=True)
    return out, "simple-xml"


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pcap", type=Path)
    ap.add_argument("--out", type=Path)
    ap.add_argument("--engine", choices=["auto", "python"], default="auto")
    a = ap.parse_args()
    path, kind = to_xml(a.pcap, a.out, a.engine)
    print(f"wrote {path} ({kind}, {path.stat().st_size:,} bytes)")


if __name__ == "__main__":
    main()
