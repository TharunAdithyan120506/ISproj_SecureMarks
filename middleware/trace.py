"""Demo-mode trace events and the coloured server console.

Every check the middleware runs is recorded as one step `{side, step, detail,
ok, ts}` (ok = None means skipped) and printed as one `rich` line, e.g.
`[7f3a] PASS aesgcm_decrypt AES-256-GCM 812 B`. Steps are kept in memory for
the inspector and persisted to `trace_events` when the request finishes.

A request ID that arrives a second time (a replay) gets its own trace ID,
`<request_id>~2`, so the original publish's trace stays clean.
"""
from __future__ import annotations

import threading
import time
from collections import OrderedDict

from rich.console import Console
from rich.markup import escape

from .db.models import TraceEvent
from .db.session import Database

MAX_TRACES = 5000
_STYLE = {True: ("PASS", "bold green"), False: ("FAIL", "bold red"), None: ("SKIP", "dim")}


class Tracer:
    def __init__(self, db: Database, enabled: bool, console: bool = True):
        self.db = db
        self.enabled = enabled
        self.console = Console(highlight=False, soft_wrap=True) if console else None
        self._traces: OrderedDict[str, list[dict]] = OrderedDict()
        self._attempts: dict[str, int] = {}
        self._lock = threading.Lock()

    # --- lifecycle ---------------------------------------------------------------

    def begin(self, request_id: str) -> str:
        """Allocate the trace ID for one request attempt."""
        with self._lock:
            n = self._attempts.get(request_id, 0) + 1
            self._attempts[request_id] = n
            trace_id = request_id if n == 1 else f"{request_id}~{n}"
            self._traces[trace_id] = []
            while len(self._traces) > MAX_TRACES:
                self._traces.popitem(last=False)
            if len(self._attempts) > MAX_TRACES * 2:
                for key in list(self._attempts)[: MAX_TRACES]:
                    self._attempts.pop(key, None)
        return trace_id

    def step(self, trace_id: str, step: str, detail: str = "", ok: bool | None = True, side: str = "server") -> None:
        event = {"side": side, "step": step, "detail": detail, "ok": ok, "ts": time.time()}
        if self.enabled:
            with self._lock:
                self._traces.setdefault(trace_id, []).append(event)
        self._print(trace_id, step, detail, ok)

    def headline(self, trace_id: str, text: str, style: str = "bold cyan") -> None:
        if self.console and self.enabled:
            self.console.print(f"[{style}]{escape(f'[{trace_id[:4]}]')}[/] {escape(text)}")

    def flush(self, trace_id: str) -> None:
        if not self.enabled:
            return
        with self._lock:
            events = list(self._traces.get(trace_id, []))
        if not events:
            return
        with self.db.session() as s:
            s.add_all(TraceEvent(request_id=trace_id, side=e["side"], step=e["step"], detail=e["detail"],
                                 ok=e["ok"], ts=e["ts"]) for e in events)

    # --- reads -----------------------------------------------------------------------

    def get(self, trace_id: str) -> list[dict]:
        with self._lock:
            events = self._traces.get(trace_id)
            if events is not None:
                return list(events)
        from sqlalchemy import select
        with self.db.session() as s:
            rows = s.scalars(select(TraceEvent).where(TraceEvent.request_id == trace_id).order_by(TraceEvent.id))
            return [{"side": r.side, "step": r.step, "detail": r.detail, "ok": r.ok, "ts": r.ts} for r in rows]

    def recorded_steps(self, trace_id: str) -> set[str]:
        with self._lock:
            return {e["step"] for e in self._traces.get(trace_id, [])}

    # --- console -----------------------------------------------------------------------

    def _print(self, trace_id: str, step: str, detail: str, ok: bool | None) -> None:
        if not self.console or not self.enabled:
            return
        label, style = _STYLE[ok]
        self.console.print(f"[dim]{escape(f'[{trace_id[:4]}]')}[/] [{style}]{label}[/] [bold]{step}[/] {escape(detail)}")

    def decision(self, line: str, ok: bool) -> None:
        """One line per request when DEMO_MODE=0 (no step trace)."""
        if self.console and not self.enabled:
            self.console.print(f"[{'green' if ok else 'red'}]{escape(line)}[/]")
