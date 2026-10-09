"""Runtime settings, read from `.env` (written by scripts/setup_demo.py) with
environment variables taking precedence."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import dotenv_values

ROOT = Path(__file__).resolve().parents[1]


def _flag(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    root: Path = ROOT
    demo_mode: bool = True
    jwt_secret: str = ""
    db_path: Path = ROOT / "data" / "securemarks.db"
    server_url: str = "http://127.0.0.1:8000"
    tls_url: str = "https://127.0.0.1:8443"
    config_dir: Path = ROOT / "config"
    secrets_dir: Path = ROOT / "secrets"
    client_keys_dir: Path = ROOT / "client_keys"
    captures_dir: Path = ROOT / "captures"
    # Fixed limits from the PRD (section 5)
    jwt_ttl_s: int = 15 * 60
    session_ttl_s: int = 15 * 60
    concurrency_cap: int = 20
    handler_timeout_s: float = 10.0
    hard_cap_bytes: int = 5 * 1024 * 1024
    # Unauthenticated calls (login) are rate limited per source IP
    login_rate_capacity: int = 5
    login_rate_refill: float = 0.5
    console_trace: bool = True
    extra: dict = field(default_factory=dict)

    @property
    def master_key_path(self) -> Path:
        return self.secrets_dir / "master.key"

    @property
    def server_rsa_path(self) -> Path:
        return self.secrets_dir / "server_rsa.pem"


def _resolve(path: str | None, default: Path) -> Path:
    if not path:
        return default
    p = Path(path)
    return p if p.is_absolute() else ROOT / p


def load_settings(env_file: Path | None = None, **overrides) -> Settings:
    env_file = env_file or ROOT / ".env"
    values: dict[str, str | None] = {}
    if env_file.exists():
        values.update(dotenv_values(env_file))
    values.update({k: v for k, v in os.environ.items() if k.startswith(("DEMO_MODE", "JWT_SECRET", "DB_PATH", "SERVER_URL", "TLS_URL", "SECRETS_DIR", "CLIENT_KEYS_DIR", "CAPTURES_DIR", "CONSOLE_TRACE"))})

    kwargs = dict(
        demo_mode=_flag(values.get("DEMO_MODE"), True),
        jwt_secret=values.get("JWT_SECRET") or "",
        db_path=_resolve(values.get("DB_PATH"), ROOT / "data" / "securemarks.db"),
        server_url=values.get("SERVER_URL") or "http://127.0.0.1:8000",
        tls_url=values.get("TLS_URL") or "https://127.0.0.1:8443",
        secrets_dir=_resolve(values.get("SECRETS_DIR"), ROOT / "secrets"),
        client_keys_dir=_resolve(values.get("CLIENT_KEYS_DIR"), ROOT / "client_keys"),
        captures_dir=_resolve(values.get("CAPTURES_DIR"), ROOT / "captures"),
        console_trace=_flag(values.get("CONSOLE_TRACE"), True),
    )
    kwargs.update(overrides)
    return Settings(**kwargs)
