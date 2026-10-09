"""Everything one running middleware holds: settings, policies, DB, keys and the
in-memory stores. Built once by create_app(); tests build their own."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .audit import AuditLogWriter
from .db.session import Database
from .errors import STATUS
from .guards.ratelimit import RateLimiter
from .guards.replay import ReplayStore
from .keys.manager import KeyManager
from .policy.engine import PolicySet, load_policies
from .sessions import SessionStore
from .settings import Settings
from .trace import Tracer


def load_devices(path: Path) -> dict:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return data


@dataclass
class AppState:
    settings: Settings
    policies: PolicySet
    devices: dict
    db: Database
    keys: KeyManager
    sessions: SessionStore
    replay: ReplayStore
    limiter: RateLimiter
    audit: AuditLogWriter
    tracer: Tracer
    plain_store: dict = field(default_factory=dict)

    @classmethod
    def build(cls, settings: Settings) -> "AppState":
        db = Database(settings.db_path)
        return cls(
            settings=settings,
            policies=load_policies(settings.config_dir / "policies.yaml"),
            devices=load_devices(settings.config_dir / "devices.yaml"),
            db=db,
            keys=KeyManager(db, settings.master_key_path, settings.server_rsa_path),
            sessions=SessionStore(settings.session_ttl_s),
            replay=ReplayStore(),
            limiter=RateLimiter(),
            audit=AuditLogWriter(db),
            tracer=Tracer(db, enabled=settings.demo_mode, console=settings.console_trace),
        )

    def device_for_ip(self, ip: str) -> str:
        for role in self.devices.get("roles", {}).values():
            if role["ip"] == ip:
                return role["label"]
        return "unknown"

    # --- end of a request: audit + trace + console ---------------------------------------

    def audit_outcome(self, meta, outcome: str, code: str, detail: str, action: str | None = None) -> dict:
        entry = self.audit.record(
            request_id=meta.request_id, actor=meta.actor, role=meta.role, src_ip=meta.src_ip,
            device=meta.device, action=action or meta.action, outcome=outcome, code=code,
            detail=detail + (f" [trace {meta.trace_id}]" if meta.trace_id != meta.request_id else ""),
        )
        self.tracer.step(meta.trace_id, "audit_write",
                         f"#{entry['id']} {entry['action']} {outcome} {code} ({entry['write_ms']:.2f} ms, hash-chained)")
        return entry

    def finish_ok(self, meta, detail: str = "", audit: bool = True) -> None:
        if audit:
            self.audit_outcome(meta, "allowed", "ok", detail)
        self.tracer.headline(meta.trace_id, "◀── 200 ok", style="bold green")
        self.tracer.flush(meta.trace_id)
        self.tracer.decision(f"200 {meta.method} {meta.path} {meta.device} {meta.actor or '-'}", True)

    def finish_error(self, meta, code: str, detail: str, action: str | None = None, plan: list[str] | None = None) -> None:
        if plan:
            done = self.tracer.recorded_steps(meta.trace_id)
            for step in plan:
                if step not in done:
                    self.tracer.step(meta.trace_id, step, "not reached", ok=None)
        status = STATUS[code]
        self.audit_outcome(meta, "error" if status >= 500 else "denied", code, detail, action)
        self.tracer.headline(meta.trace_id, f"◀── {status} {code}", style="bold red")
        self.tracer.flush(meta.trace_id)
        self.tracer.decision(f"{status} {code} {meta.method} {meta.path} {meta.device} {meta.actor or '-'}", False)
