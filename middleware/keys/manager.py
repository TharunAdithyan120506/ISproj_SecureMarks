"""Key manager: master key (KEK), wrapped data keys (DEKs) and the registry of
teacher signing keys.

* KEK: 32 random bytes in secrets/master.key, never in the DB or git.
* DEK: AES-256-GCM key, stored wrapped by the KEK (AES-256-GCM, AAD = b"dek|v<version>").
  Encrypt always uses the active DEK; decrypt looks up the record's dek_id,
  refuses a revoked key, and treats an expired key as decrypt-only.
* Signing keys: only public keys are stored. Revoking one blocks further
  publishes; records signed before `revoked_at` still verify.
"""
from __future__ import annotations

import os
import threading
from datetime import datetime, timedelta
from pathlib import Path

from sqlalchemy import func, select

from ..crypto import aead, kex
from ..crypto.sign import fingerprint
from ..db.models import DataKey, SigningKey, utcnow
from ..db.session import Database
from ..errors import ApiError

DEK_LIFETIME = timedelta(days=180)


def _dek_aad(version: int) -> bytes:
    return f"dek|v{version}".encode()


class KeyManager:
    def __init__(self, db: Database, master_key_path: Path, server_rsa_path: Path | None = None):
        self.db = db
        self.master_key_path = master_key_path
        self.server_rsa_path = server_rsa_path
        self._kek: bytes | None = None
        self._dek_cache: dict[int, bytes] = {}
        self._rsa = None
        self._lock = threading.Lock()

    # --- master key ---------------------------------------------------------

    @property
    def kek(self) -> bytes:
        if self._kek is None:
            data = self.master_key_path.read_bytes()
            if len(data) != 32:
                raise RuntimeError(f"{self.master_key_path} must hold exactly 32 bytes")
            self._kek = data
        return self._kek

    @staticmethod
    def create_master_key(path: Path) -> bytes:
        path.parent.mkdir(parents=True, exist_ok=True)
        key = os.urandom(32)
        path.write_bytes(key)
        return key

    # --- data keys ------------------------------------------------------------

    def create_data_key(self, version: int, status: str = "active") -> DataKey:
        dek = os.urandom(32)
        nonce, wrapped = aead.encrypt(self.kek, dek, _dek_aad(version))
        row = DataKey(version=version, alg="AES-256-GCM", wrapped_key=wrapped, wrap_nonce=nonce,
                      status=status, created_at=utcnow(), expires_at=utcnow() + DEK_LIFETIME)
        with self.db.session() as s:
            s.add(row)
        self._dek_cache[row.id] = dek
        return row

    def _unwrap(self, row: DataKey) -> bytes:
        if row.id not in self._dek_cache:
            self._dek_cache[row.id] = aead.decrypt(self.kek, row.wrap_nonce, row.wrapped_key, _dek_aad(row.version))
        return self._dek_cache[row.id]

    def active_dek(self) -> tuple[DataKey, bytes]:
        with self.db.session() as s:
            row = s.scalars(select(DataKey).where(DataKey.status == "active").order_by(DataKey.version.desc())).first()
        if row is None:
            raise ApiError("dek_unavailable", "no active data key; ask the admin to rotate")
        if row.expires_at < utcnow():
            raise ApiError("dek_unavailable", f"data key v{row.version} expired; it is decrypt-only until rotated")
        return row, self._unwrap(row)

    def dek_for(self, dek_id: int) -> tuple[DataKey, bytes]:
        with self.db.session() as s:
            row = s.get(DataKey, dek_id)
        if row is None:
            raise ApiError("dek_unavailable", f"data key id {dek_id} not found")
        if row.status == "revoked":
            raise ApiError("dek_unavailable", f"data key v{row.version} is revoked")
        return row, self._unwrap(row)

    def rotate(self) -> int:
        with self._lock:
            with self.db.session() as s:
                current = s.scalar(select(func.max(DataKey.version))) or 0
                for row in s.scalars(select(DataKey).where(DataKey.status == "active")):
                    row.status = "retired"
            return self.create_data_key(current + 1).version

    # --- signing keys -----------------------------------------------------------

    def register_signing_key(self, username: str, alg: str, public_key: bytes) -> SigningKey:
        row = SigningKey(username=username, alg=alg, public_key=public_key,
                         fingerprint=fingerprint(public_key), status="active", created_at=utcnow())
        with self.db.session() as s:
            s.add(row)
        return row

    def signing_key(self, username: str, alg: str | None = None, fp: str | None = None) -> SigningKey | None:
        """By fingerprint when given; otherwise the newest key (active first) for that alg."""
        q = select(SigningKey).where(SigningKey.username == username)
        if fp:
            q = q.where(SigningKey.fingerprint == fp)
        if alg:
            q = q.where(SigningKey.alg == alg)
        q = q.order_by((SigningKey.status == "active").desc(), SigningKey.id.desc())
        with self.db.session() as s:
            return s.scalars(q).first()

    def revoke_signing(self, username: str) -> int:
        with self.db.session() as s:
            rows = list(s.scalars(select(SigningKey).where(SigningKey.username == username, SigningKey.status == "active")))
            for row in rows:
                row.status = "revoked"
                row.revoked_at = utcnow()
        return len(rows)

    # --- listing (metadata only, never key bytes) ---------------------------------

    def list_keys(self) -> dict:
        with self.db.session() as s:
            deks = list(s.scalars(select(DataKey).order_by(DataKey.version)))
            sks = list(s.scalars(select(SigningKey).order_by(SigningKey.id)))
        return {
            "data_keys": [
                {"id": d.id, "version": d.version, "alg": d.alg, "status": d.status,
                 "created_at": _iso(d.created_at), "expires_at": _iso(d.expires_at),
                 "wrapped_by": "KEK (AES-256-GCM)", "wrapped_len": len(d.wrapped_key)}
                for d in deks
            ],
            "signing_keys": [
                {"id": k.id, "username": k.username, "alg": k.alg, "fingerprint": k.fingerprint,
                 "status": k.status, "public_key_len": len(k.public_key),
                 "created_at": _iso(k.created_at), "revoked_at": _iso(k.revoked_at)}
                for k in sks
            ],
        }

    # --- server RSA key (legacy-rsa policy, P1) -------------------------------------

    def server_rsa(self):
        if self._rsa is None:
            from cryptography.hazmat.primitives import serialization
            if self.server_rsa_path is None or not self.server_rsa_path.exists():
                raise ApiError("bad_request", "legacy-rsa is not set up; run scripts/setup_demo.py")
            self._rsa = serialization.load_pem_private_key(self.server_rsa_path.read_bytes(), password=None)
        return self._rsa

    def server_rsa_public(self) -> bytes:
        return kex.rsa_public_der(self.server_rsa())


def _iso(dt: datetime | None) -> str | None:
    return dt.replace(microsecond=0).isoformat() + "Z" if dt else None
