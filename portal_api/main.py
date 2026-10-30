"""Portal API app: JSON routes under /api, the built React app (web/dist) everywhere else.

    uvicorn portal_api.main:app --host 127.0.0.1 --port 8501
"""
from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from middleware.settings import ROOT

from . import routes_lab, routes_ops, routes_portal

DIST = ROOT / "web" / "dist"

NOT_BUILT = """<!doctype html><meta charset="utf-8"><title>SecureMarks</title>
<body style="font-family:system-ui;max-width:640px;margin:15vh auto;color:#1d1d1f">
<h1 style="font-size:28px">The portal is not built yet</h1>
<p>Build the React app once, then reload:</p>
<pre style="background:#f2f2f7;padding:14px;border-radius:12px">cd web
npm ci
npm run build</pre>
<p>or run <code>python scripts\\run_demo.py</code>, which builds it for you.</p></body>"""


def create_app() -> FastAPI:
    app = FastAPI(title="SecureMarks portal API", version="2.0", docs_url="/api/docs", openapi_url="/api/openapi.json")
    for r in (routes_portal.router, routes_lab.router, routes_ops.router):
        app.include_router(r)

    @app.exception_handler(ValueError)
    async def on_value_error(_request: Request, exc: ValueError):
        return JSONResponse({"detail": str(exc)}, status_code=400)

    if (DIST / "assets").exists():
        app.mount("/assets", StaticFiles(directory=DIST / "assets"), name="assets")

    @app.get("/{path:path}", include_in_schema=False)
    def spa(path: str):
        if path.startswith("api/"):
            return JSONResponse({"detail": "not found"}, status_code=404)
        target = (DIST / path).resolve()
        if path and DIST.resolve() in target.parents and target.is_file():
            return FileResponse(target)
        index = DIST / "index.html"
        if index.exists():
            return FileResponse(index, headers={"Cache-Control": "no-cache"})
        return HTMLResponse(NOT_BUILT)

    return app


app = create_app()
