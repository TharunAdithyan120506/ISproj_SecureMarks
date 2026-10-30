"""SQLAlchemy models: the six tables of PRD section 7, plus answer-sheet attachments.

Sessions, seen request IDs and token buckets are deliberately *not* here: they
live in memory because the demo runs a single Uvicorn worker.
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, LargeBinary, String, Text, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    pw_hash: Mapped[str] = mapped_column(String(256), nullable=False)
    role: Mapped[str] = mapped_column(String(16), nullable=False)  # teacher, student, ctrl, admin
    roll_no: Mapped[str | None] = mapped_column(String(16))
    courses: Mapped[str | None] = mapped_column(String(256))  # comma list
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    @property
    def course_list(self) -> list[str]:
        return [c for c in (self.courses or "").split(",") if c]


class SigningKey(Base):
    __tablename__ = "signing_keys"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    alg: Mapped[str] = mapped_column(String(32), nullable=False)  # Ed25519 (RSA-PSS-2048 for legacy-rsa)
    public_key: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    fingerprint: Mapped[str] = mapped_column(String(16), nullable=False)
    status: Mapped[str] = mapped_column(String(16), default="active")  # active, revoked
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime)


class DataKey(Base):
    __tablename__ = "data_keys"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    version: Mapped[int] = mapped_column(Integer, unique=True, nullable=False)
    alg: Mapped[str] = mapped_column(String(32), default="AES-256-GCM")
    wrapped_key: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    wrap_nonce: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    status: Mapped[str] = mapped_column(String(16), default="active")  # active, retired, revoked
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)


class Mark(Base):
    __tablename__ = "marks"
    __table_args__ = (UniqueConstraint("course", "roll_no", "version"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    course: Mapped[str] = mapped_column(String(16), index=True, nullable=False)
    roll_no: Mapped[str] = mapped_column(String(16), index=True, nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    nonce: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    dek_id: Mapped[int] = mapped_column(ForeignKey("data_keys.id"), nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    signature: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    signer: Mapped[str] = mapped_column(String(64), nullable=False)
    sig_alg: Mapped[str] = mapped_column(String(32), nullable=False)
    key_fingerprint: Mapped[str] = mapped_column(String(16), nullable=False)
    published_at: Mapped[str] = mapped_column(String(32), nullable=False)
    request_id: Mapped[str] = mapped_column(String(64), nullable=False)
    sign_ms: Mapped[float | None] = mapped_column(Float)    # measured on the teacher's device
    verify_ms: Mapped[float | None] = mapped_column(Float)  # measured by the server at publish


class Attachment(Base):
    """Answer-sheet image of one marks version: AES-256-GCM under the DEK,
    AAD = sheet|course|roll|version. Its SHA-256 is inside the signed record."""
    __tablename__ = "attachments"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    mark_id: Mapped[int] = mapped_column(ForeignKey("marks.id"), unique=True, nullable=False)
    mime: Mapped[str] = mapped_column(String(32), nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    width: Mapped[int | None] = mapped_column(Integer)
    height: Mapped[int | None] = mapped_column(Integer)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    nonce: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    dek_id: Mapped[int] = mapped_column(ForeignKey("data_keys.id"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class AuditLog(Base):
    __tablename__ = "audit_log"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ts: Mapped[float] = mapped_column(Float, nullable=False)  # unix seconds
    request_id: Mapped[str] = mapped_column(String(64), index=True)
    actor: Mapped[str | None] = mapped_column(String(64))
    role: Mapped[str | None] = mapped_column(String(16))
    src_ip: Mapped[str | None] = mapped_column(String(64))
    device: Mapped[str | None] = mapped_column(String(32))
    action: Mapped[str] = mapped_column(String(32), nullable=False)
    outcome: Mapped[str] = mapped_column(String(16), nullable=False)  # allowed, denied, error
    code: Mapped[str] = mapped_column(String(32), nullable=False)
    detail: Mapped[str | None] = mapped_column(Text)
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    entry_hash: Mapped[str] = mapped_column(String(64), nullable=False)


class TraceEvent(Base):
    __tablename__ = "trace_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    request_id: Mapped[str] = mapped_column(String(64), index=True)
    side: Mapped[str] = mapped_column(String(8), nullable=False)  # client, server
    step: Mapped[str] = mapped_column(String(32), nullable=False)
    detail: Mapped[str | None] = mapped_column(Text)
    ok: Mapped[bool | None] = mapped_column(Boolean)  # None = skipped
    ts: Mapped[float] = mapped_column(Float, nullable=False)
