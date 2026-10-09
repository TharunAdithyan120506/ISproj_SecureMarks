"""Self-signed TLS certificate for the P1 HTTPS run (SAN IP:127.0.0.1).

    python scripts\\make_cert.py            -> secrets\\server.key, secrets\\server.crt
"""
from __future__ import annotations

import datetime as dt
import ipaddress
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

ROOT = Path(__file__).resolve().parents[1]


def make_cert(secrets_dir: Path) -> tuple[Path, Path]:
    secrets_dir.mkdir(parents=True, exist_ok=True)
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SecureMarks demo server"),
                      x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureMarks ISL demo")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                                                    x509.DNSName("localhost")]), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    key_path, crt_path = secrets_dir / "server.key", secrets_dir / "server.crt"
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                                           serialization.NoEncryption()))
    crt_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return key_path, crt_path


if __name__ == "__main__":
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "secrets"
    k, c = make_cert(out)
    print(f"wrote {k} and {c}")
