"""One-time (and pre-demo) setup.

    python scripts\\setup_demo.py           # create whatever is missing
    python scripts\\setup_demo.py --reset   # wipe the DB and keys for a clean demo
    python scripts\\setup_demo.py --rekey t104   # new signing key after a revocation

Writes .env secrets, the master key (KEK), data key v1, the seed users, t104's
Ed25519 keypair (private half encrypted with t104's password, client side
only), the server RSA key and TLS certificate (P1), and one seeded record for
roll 240911612 so the swap and IDOR attacks have a target.
"""
from __future__ import annotations

import argparse
import secrets
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import yaml  # noqa: E402
from rich.console import Console  # noqa: E402
from rich.table import Table  # noqa: E402

from middleware import records  # noqa: E402
from middleware.audit import AuditLogWriter  # noqa: E402
from middleware.auth.passwords import hash_password  # noqa: E402
from middleware.crypto import kex, sign  # noqa: E402
from middleware.crypto.canonical import build_record, canonical_record  # noqa: E402
from middleware.crypto.hashing import sha256  # noqa: E402
from middleware.db.models import User  # noqa: E402
from middleware.db.session import Database  # noqa: E402
from middleware.keys.manager import KeyManager  # noqa: E402
from middleware.settings import Settings, load_settings  # noqa: E402

console = Console(highlight=False)
SEED_RECORD = {"course": "IT301", "roll_no": "240911612", "midsem": 38, "endsem": 41}


def load_accounts(settings: Settings) -> dict:
    return yaml.safe_load((settings.config_dir / "demo_accounts.yaml").read_text(encoding="utf-8"))


def write_env(path: Path, reset: bool) -> None:
    existing = {}
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                k, v = line.split("=", 1)
                existing[k.strip()] = v.strip()
    values = {
        "DEMO_MODE": existing.get("DEMO_MODE", "1"),
        "JWT_SECRET": secrets.token_hex(32) if reset or not existing.get("JWT_SECRET") else existing["JWT_SECRET"],
        "DB_PATH": existing.get("DB_PATH", "data/securemarks.db"),
        "SERVER_URL": existing.get("SERVER_URL", "http://127.0.0.1:8000"),
        "TLS_URL": existing.get("TLS_URL", "https://127.0.0.1:8443"),
    }
    path.write_text("".join(f"{k}={v}\n" for k, v in values.items()), encoding="utf-8")


def _wipe_db(path: Path) -> None:
    for suffix in ("", "-wal", "-shm"):
        p = Path(str(path) + suffix)
        if p.exists():
            try:
                p.unlink()
            except PermissionError:
                raise SystemExit(f"{p} is in use: stop the server and portal first, then re-run --reset")


def make_teacher_keys(settings: Settings, keys: KeyManager, username: str, password: str) -> str:
    settings.client_keys_dir.mkdir(parents=True, exist_ok=True)
    priv, pub = sign.ed25519_keypair()
    (settings.client_keys_dir / f"{username}_ed25519.pem").write_bytes(sign.save_private_pem(priv, password))
    row = keys.register_signing_key(username, sign.ED25519, pub)
    # P1: an RSA-PSS-2048 key for the legacy-rsa comparison policy
    rsa_priv = kex.rsa_keypair()
    (settings.client_keys_dir / f"{username}_rsa.pem").write_bytes(sign.save_private_pem(rsa_priv, password))
    keys.register_signing_key(username, sign.RSA_PSS, sign.public_bytes(rsa_priv))
    return row.fingerprint


def run_setup(settings: Settings, *, reset: bool = False, seed: bool = True, env_file: Path | None = None,
              tls: bool = True, quiet: bool = False) -> dict:
    say = (lambda *a, **k: None) if quiet else console.print
    if env_file is not None:
        write_env(env_file, reset)
        say(f"[green]✓[/] {env_file.name} secrets")

    for d in (settings.secrets_dir, settings.client_keys_dir, settings.captures_dir, settings.db_path.parent):
        d.mkdir(parents=True, exist_ok=True)
    if reset:
        _wipe_db(settings.db_path)
    if reset or not settings.master_key_path.exists():
        KeyManager.create_master_key(settings.master_key_path)
        say(f"[green]✓[/] master key (KEK) → {settings.master_key_path}")

    db = Database(settings.db_path)
    db.create_all()
    keys = KeyManager(db, settings.master_key_path, settings.server_rsa_path)
    accounts = load_accounts(settings)
    summary: dict = {"fingerprints": {}}

    with db.session() as s:
        fresh = s.query(User).count() == 0
    if fresh:
        dek = keys.create_data_key(1)
        say(f"[green]✓[/] data key v{dek.version} (AES-256-GCM, wrapped by KEK, expires {dek.expires_at:%Y-%m-%d})")
        with db.session() as s:
            for username, a in accounts.items():
                s.add(User(username=username, pw_hash=hash_password(a["password"]), role=a["role"],
                           roll_no=a.get("roll_no"), courses=",".join(a.get("courses", []))))
        say(f"[green]✓[/] {len(accounts)} users (Argon2id password hashes)")
        for username, a in accounts.items():
            if a["role"] == "teacher":
                fp = make_teacher_keys(settings, keys, username, a["password"])
                summary["fingerprints"][username] = fp
                say(f"[green]✓[/] {username} Ed25519 keypair, fingerprint {fp}; private key → "
                    f"{settings.client_keys_dir / (username + '_ed25519.pem')} (encrypted with {username}'s password)")
        if reset or not settings.server_rsa_path.exists():
            from cryptography.hazmat.primitives import serialization
            rsa_priv = kex.rsa_keypair()
            settings.server_rsa_path.write_bytes(rsa_priv.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
            say("[green]✓[/] server RSA-OAEP-2048 key (legacy-rsa policy, P1)")
        if seed:
            seed_record(settings, keys, db, accounts)
            say(f"[green]✓[/] seeded {SEED_RECORD['course']} marks for roll {SEED_RECORD['roll_no']} (signed by t104)")
        AuditLogWriter(db).record(request_id="setup", action="setup", outcome="allowed", code="ok",
                                  actor="setup_demo", detail="fresh database initialised")
    else:
        say("[yellow]•[/] database already initialised (use --reset for a clean demo)")

    if tls and (reset or not (settings.secrets_dir / "server.crt").exists()):
        from scripts.make_cert import make_cert
        make_cert(settings.secrets_dir)
        say("[green]✓[/] self-signed TLS certificate (SAN IP:127.0.0.1) → secrets\\server.crt (P1)")
    db.dispose()
    return summary


def seed_record(settings: Settings, keys: KeyManager, db: Database, accounts: dict) -> None:
    teacher = "t104"
    priv = sign.load_private_pem((settings.client_keys_dir / f"{teacher}_ed25519.pem").read_bytes(),
                                 accounts[teacher]["password"])
    record = build_record(teacher=teacher, **SEED_RECORD)
    canon = canonical_record(record)
    signature = sign.ed25519_sign(priv, sha256(canon))
    fp = sign.fingerprint(sign.ed25519_public_bytes(priv))
    records.store(keys, db, record=record, canonical_bytes=canon, signature=signature, signer=teacher,
                  sig_alg=sign.ED25519, key_fingerprint=fp, request_id="seed-setup")


def rekey(settings: Settings, username: str) -> str:
    accounts = load_accounts(settings)
    db = Database(settings.db_path)
    keys = KeyManager(db, settings.master_key_path, settings.server_rsa_path)
    fp = make_teacher_keys(settings, keys, username, accounts[username]["password"])
    AuditLogWriter(db).record(request_id=f"rekey-{username}", action="signing_rekey", outcome="allowed", code="ok",
                              actor="setup_demo", detail=f"new signing keys for {username}, fingerprint {fp}")
    db.dispose()
    return fp


def print_accounts(settings: Settings) -> None:
    devices = yaml.safe_load((settings.config_dir / "devices.yaml").read_text(encoding="utf-8"))["roles"]
    t = Table(title="Demo accounts (demo-only passwords)")
    for col in ("user", "password", "role", "roll / courses", "device"):
        t.add_column(col)
    for username, a in load_accounts(settings).items():
        dev = devices[a["role"]]
        t.add_row(username, a["password"], a["role"], a.get("roll_no") or ",".join(a.get("courses", [])) or "-",
                  f"{dev['label']} {dev['ip']}")
    console.print(t)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--reset", action="store_true", help="wipe the database and keys for a clean demo")
    ap.add_argument("--rekey", metavar="USER", help="issue a fresh signing key for USER (old one stays revoked)")
    ap.add_argument("--no-seed", action="store_true", help="do not seed the 240911612 record")
    args = ap.parse_args()

    env_file = ROOT / ".env"
    if args.rekey:
        settings = load_settings(env_file)
        console.print(f"[green]✓[/] new signing key for {args.rekey}: fingerprint {rekey(settings, args.rekey)}")
        return
    write_env(env_file, args.reset)
    settings = load_settings(env_file)
    console.rule("[bold cyan]SecureMarks setup")
    run_setup(settings, reset=args.reset, seed=not args.no_seed)
    print_accounts(settings)
    console.print("\nNext:  [bold]pytest -q[/]   then   [bold]python scripts\\run_demo.py[/]")


if __name__ == "__main__":
    main()
