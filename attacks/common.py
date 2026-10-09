"""Shared plumbing for the attack scripts: the attacker's client, evidence lookup
(audit rows and server trace straight from the DB, read-only) and reporting."""
from __future__ import annotations

import hashlib
import json
import sqlite3
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from middleware.settings import load_settings  # noqa: E402
from sdk.client import SecureClient, load_accounts, load_signing_key  # noqa: E402


@dataclass
class AttackResult:
    name: str
    goal: str
    expected: str                      # e.g. "400 integrity_failed"
    status: int = 0
    code: str = ""
    request_id: str | None = None
    trace_id: str | None = None
    detail: str = ""
    notes: list[str] = field(default_factory=list)
    client_trace: list[dict] = field(default_factory=list)
    extra: dict = field(default_factory=dict)
    audit: list[dict] = field(default_factory=list)
    server_trace: list[dict] = field(default_factory=list)

    @property
    def actual(self) -> str:
        return f"{self.status} {self.code}"

    @property
    def passed(self) -> bool:
        return self.actual == self.expected

    def to_dict(self) -> dict:
        d = asdict(self)
        d.update(actual=self.actual, passed=self.passed)
        return d


def from_call(name: str, goal: str, expected: str, res, *notes: str) -> AttackResult:
    return AttackResult(name, goal, expected, res.status, res.code, res.request_id, res.trace_id,
                        res.detail or "", list(notes), res.trace)


# --- clients ----------------------------------------------------------------------------

def accounts() -> dict:
    return load_accounts()


def token_for(username: str) -> dict:
    """Simulates token theft: the JWT is issued to the victim's own device (its IP and
    login bucket), then cached in the attacker's loot file and reused from 127.0.0.66."""
    settings = load_settings()
    loot_path = settings.captures_dir / "attacker_loot.json"
    epoch = hashlib.sha256(settings.jwt_secret.encode()).hexdigest()[:8]  # changes on setup --reset
    loot = {}
    if loot_path.exists():
        try:
            loot = json.loads(loot_path.read_text(encoding="utf-8"))
        except ValueError:
            loot = {}
    if loot.get("_epoch") != epoch:
        loot = {"_epoch": epoch}
    entry = loot.get(username)
    if entry and entry["expires_at"] - time.time() > 60:
        return entry
    acc = accounts()[username]
    victim = SecureClient.for_role(acc["role"], save_last_request=False)
    res = victim.login(username, acc["password"])
    victim.close()
    if not res.ok:
        raise RuntimeError(f"could not obtain a token for {username}: {res.summary()}")
    entry = {"token": victim.token, "role": victim.role, "roll_no": victim.roll_no, "courses": victim.courses,
             "expires_at": victim.token_expires_at}
    loot[username] = entry
    loot_path.parent.mkdir(parents=True, exist_ok=True)
    loot_path.write_text(json.dumps(loot), encoding="utf-8")
    return entry


def attacker(stolen_login: str | None = None) -> SecureClient:
    """Client bound to 127.0.0.66 with X-Device: attacker, optionally holding a stolen token."""
    c = SecureClient.for_role("attacker", save_last_request=False)
    if stolen_login:
        t = token_for(stolen_login)
        c.token, c.username, c.role = t["token"], stolen_login, t["role"]
        c.roll_no, c.courses, c.token_expires_at = t["roll_no"], t["courses"], t["expires_at"]
    return c


def device_client(role: str, username: str) -> SecureClient:
    """A legitimate user's client on their own device (token cached like the portal's)."""
    c = SecureClient.for_role(role, save_last_request=False)
    t = token_for(username)
    c.token, c.username, c.role = t["token"], username, t["role"]
    c.roll_no, c.courses, c.token_expires_at = t["roll_no"], t["courses"], t["expires_at"]
    return c


def teacher_key(username: str = "t104"):
    return load_signing_key(username, accounts()[username]["password"])


def ensure_published(roll_no: str = "240911608", course: str = "IT301", midsem: int = 27, endsem: int = 45) -> None:
    """Make sure t104 has a record for this roll (the tamper target)."""
    s = load_settings()
    con = sqlite3.connect(f"file:{s.db_path.as_posix()}?mode=ro", uri=True)
    try:
        n = con.execute("SELECT COUNT(*) FROM marks WHERE roll_no=? AND course=?", (roll_no, course)).fetchone()[0]
    finally:
        con.close()
    if n == 0:
        t = device_client("teacher", "t104")
        res = t.publish_marks(teacher_key(), course, roll_no, midsem, endsem)
        if not res.ok:
            raise RuntimeError(f"could not publish the target record: {res.summary()}")


# --- evidence ------------------------------------------------------------------------------

def _ro():
    s = load_settings()
    con = sqlite3.connect(f"file:{s.db_path.as_posix()}?mode=ro", uri=True, timeout=10)
    con.row_factory = sqlite3.Row
    return con


def audit_for(request_id: str | None, retries: int = 5) -> list[dict]:
    if not request_id:
        return []
    for _ in range(retries):
        con = _ro()
        try:
            rows = [dict(r) for r in con.execute(
                "SELECT id, ts, request_id, actor, role, src_ip, device, action, outcome, code, detail "
                "FROM audit_log WHERE request_id=? ORDER BY id", (request_id,))]
        finally:
            con.close()
        if rows:
            return rows
        time.sleep(0.1)
    return []


def trace_for(trace_id: str | None) -> list[dict]:
    if not trace_id:
        return []
    con = _ro()
    try:
        return [dict(r) for r in con.execute(
            "SELECT side, step, detail, ok, ts FROM trace_events WHERE request_id=? ORDER BY id", (trace_id,))]
    finally:
        con.close()


def with_evidence(result: AttackResult) -> AttackResult:
    result.audit = audit_for(result.request_id)
    if result.trace_id:
        # the replayed request's own audit row mentions its trace ID; keep only that attempt
        if result.trace_id != result.request_id:
            mine = [a for a in result.audit if result.trace_id in (a.get("detail") or "")]
            result.audit = mine or result.audit
        result.server_trace = trace_for(result.trace_id)
    return result


# --- reporting -------------------------------------------------------------------------------

def report(result: AttackResult) -> None:
    from rich.console import Console
    from rich.markup import escape
    from rich.table import Table

    c = Console(highlight=False, width=None if sys.stdout.isatty() else 140)
    verdict = "[bold green]AS EXPECTED[/]" if result.passed else "[bold red]UNEXPECTED[/]"
    c.rule(f"[bold]{escape(result.name)}[/]  ·  {escape(result.goal)}")
    c.print(f"expected [bold]{escape(result.expected)}[/]   got [bold]{escape(result.actual)}[/]   {verdict}")
    if result.detail:
        c.print(f"detail: {escape(result.detail)}")
    if result.request_id:
        c.print(f"request ID: {result.request_id}" + (f"   trace: {result.trace_id}" if result.trace_id != result.request_id else ""))
    for note in result.notes:
        c.print(f"• {escape(note)}")
    if result.audit:
        t = Table(title="audit_log rows with this request ID")
        for col in ("id", "device", "src_ip", "actor", "action", "outcome", "code"):
            t.add_column(col)
        for a in result.audit:
            t.add_row(*(escape(str(a.get(k))) for k in ("id", "device", "src_ip", "actor", "action", "outcome", "code")))
        c.print(t)
    if result.server_trace:
        for s in result.server_trace:
            mark = {1: "[green]PASS[/]", 0: "[red]FAIL[/]", None: "[dim]SKIP[/]"}[s["ok"] if s["ok"] is None else int(s["ok"])]
            c.print(f"  {mark} {escape(s['step'])}  [dim]{escape((s['detail'] or '')[:110])}[/]")
