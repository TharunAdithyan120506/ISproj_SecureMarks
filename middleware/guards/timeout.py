"""Handler timeout: crypto-heavy handlers run in the thread pool under
asyncio.wait_for, so one slow request can neither freeze the event loop nor
hold a client forever."""
from __future__ import annotations

import asyncio
from typing import Any, Callable

from starlette.concurrency import run_in_threadpool

from ..errors import ApiError


async def run_with_timeout(fn: Callable[..., Any], *args, timeout_s: float) -> Any:
    try:
        return await asyncio.wait_for(run_in_threadpool(fn, *args), timeout=timeout_s)
    except asyncio.TimeoutError as exc:
        raise ApiError("timeout", f"handler exceeded {timeout_s:g} s") from exc
