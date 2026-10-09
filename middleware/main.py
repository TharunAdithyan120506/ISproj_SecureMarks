"""SecureMarks middleware: FastAPI app, guard order and routers.

Run:  uvicorn middleware.main:app --host 127.0.0.1 --port 8000 --workers 1

Check order for guarded paths (/api/*, /plain/*, /demo/echo):
  1 concurrency cap  2 size cap  3 rate limit     <- Starlette middleware
  4-9 auth, session, freshness, replay, decrypt, RBAC  <- secure_request() dependency
  10 handler under a 10 s timeout                <- SecureRequest.respond()
  11 audit entry for every outcome (+ trace events in DEMO_MODE)
Starlette runs the last-added middleware first, so they are added in reverse.
"""
from __future__ import annotations

import time

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from rich.console import Console
from sqlalchemy import inspect

from .api import admin, audit, auth, demo, marks, plain, session
from .errors import STATUS, ApiError, error_body
from .guards.base import meta_for, response_headers
from .guards.concurrency import ConcurrencyMiddleware
from .guards.ratelimit import RateLimitMiddleware
from .guards.size import SizeLimitMiddleware
from .settings import Settings, load_settings
from .state import AppState


def _error_response(request: Request, code: str, detail: str, action: str | None = None,
                    headers: dict | None = None) -> JSONResponse:
    state: AppState = request.app.state.sm
    meta = meta_for(request.scope, state)
    ctx = getattr(request.state, "sm_ctx", None)
    state.finish_error(meta, code, detail, action=action, plan=ctx.plan if ctx else None)
    return JSONResponse(error_body(code, detail, meta.request_id), status_code=STATUS[code],
                        headers=response_headers(meta, headers))


def _check_setup(settings: Settings, state: AppState) -> None:
    problems = []
    if not settings.jwt_secret:
        problems.append("JWT_SECRET missing from .env")
    if not settings.master_key_path.exists():
        problems.append(f"master key missing ({settings.master_key_path})")
    if not settings.db_path.exists() or not inspect(state.db.engine).has_table("users"):
        problems.append(f"database not initialised ({settings.db_path})")
    if problems:
        raise RuntimeError("SecureMarks is not set up: " + "; ".join(problems)
                           + ". Run:  python scripts\\setup_demo.py --reset")


def create_app(settings: Settings | None = None, check_setup: bool = True) -> FastAPI:
    settings = settings or load_settings()
    state = AppState.build(settings)
    if check_setup:
        _check_setup(settings, state)

    app = FastAPI(title="SecureMarks middleware", version="1.0",
                  description="Policy-driven security middleware for a student marks portal.")
    app.state.sm = state

    @app.exception_handler(ApiError)
    async def on_api_error(request: Request, exc: ApiError):
        return _error_response(request, exc.code, exc.detail, exc.action, exc.headers)

    @app.exception_handler(RequestValidationError)
    async def on_validation_error(request: Request, exc: RequestValidationError):
        fields = ", ".join(".".join(str(x) for x in e.get("loc", ())) for e in exc.errors())
        return _error_response(request, "bad_request", f"invalid request body: {fields}")

    @app.exception_handler(Exception)
    async def on_unexpected(request: Request, exc: Exception):
        return _error_response(request, "internal_error", f"{type(exc).__name__}")

    for router in (auth.router, session.router, marks.router, admin.router, audit.router):
        app.include_router(router)
    if settings.demo_mode:
        app.include_router(plain.router)
        app.include_router(demo.router)

    @app.get("/health")
    def health():
        return {"ok": True, "demo_mode": settings.demo_mode, "time": time.time(),
                "sessions": len(state.sessions), "seen_request_ids": len(state.replay)}

    # Reverse order: the last one added runs first.
    app.add_middleware(RateLimitMiddleware, state=state)    # 3
    app.add_middleware(SizeLimitMiddleware, state=state)    # 2
    app.add_middleware(ConcurrencyMiddleware, state=state)  # 1

    if settings.console_trace:
        _banner(settings, state)
    return app


def _banner(settings: Settings, state: AppState) -> None:
    c = Console(highlight=False)
    c.rule("[bold cyan]SecureMarks middleware")
    c.print(f"DEMO_MODE={'1' if settings.demo_mode else '0'}   DB={settings.db_path}")
    for name, p in state.policies.policies.items():
        c.print(f"  policy [bold]{name:<12}[/] {p.cipher:<12} {p.key_exchange:<14} sig={p.signature:<13} "
                f"max={p.max_payload_kb} KB  rate={p.rate_limit.capacity}/{p.rate_limit.refill_per_sec:g}/s  window={p.replay_window_s}s")
    c.print("  devices: " + ", ".join(f"{r['label']}={r['ip']}" for r in state.devices["roles"].values()))
    c.rule()


def __getattr__(name: str):
    # `uvicorn middleware.main:app` builds the app on first access, so tests can
    # import create_app() without touching the real .env and database.
    if name == "app":
        globals()["app"] = application = create_app()
        return application
    raise AttributeError(name)
