"""
Process-wide asyncpg pool holder.

Lives outside `main.py` to break the circular-import dodge that previously
forced `deps.py` and `routers/admin.py` to do `from main import get_pool`
inside function bodies (audit F-13). Now both can do a clean module-level
`from db import get_pool`.

main.py is responsible for calling `set_pool()` on FastAPI startup and
`close_pool()` on shutdown. Everyone else only ever reads via `get_pool()`.
"""
from __future__ import annotations

from typing import Optional

import asyncpg

_pool: Optional[asyncpg.Pool] = None


def set_pool(pool: asyncpg.Pool) -> None:
    """Install the process-wide pool. Called once from main.startup."""
    global _pool
    _pool = pool


def get_pool() -> asyncpg.Pool:
    """Return the live pool or raise if startup hasn't run yet."""
    if _pool is None:
        raise RuntimeError("DB pool not initialised")
    return _pool


async def close_pool() -> None:
    """Close and forget the pool. Called from main.shutdown."""
    global _pool
    if _pool is not None:
        await _pool.close()
        _pool = None
