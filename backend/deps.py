"""
FastAPI dependencies for auth + DB.

Auth (Sprint B C13): the preferred transport is the HttpOnly `session` cookie
set by POST /auth/google. We also accept `Authorization: Bearer <jwt>` as a
fallback so non-browser API clients and the transition window keep working —
this is gated by ALLOW_BEARER_AUTH (default "1"). Flip to "0" after the
frontend has fully moved to cookies.
"""
import os
from typing import Any, Optional

import asyncpg
from fastapi import Cookie, Depends, HTTPException, Request, status

from auth_utils import decode_jwt


async def get_pool() -> asyncpg.Pool:
    """
    Re-export the pool stored on app state.
    Import the app object lazily to avoid circular imports.
    """
    from main import get_pool as _get_pool
    return _get_pool()


def _extract_token(request: Request, session_cookie: Optional[str]) -> str:
    """Cookie first, then Authorization header (when allowed). 401 otherwise."""
    if session_cookie:
        return session_cookie
    if os.environ.get("ALLOW_BEARER_AUTH", "1") == "1":
        auth = request.headers.get("authorization", "")
        if auth.lower().startswith("bearer "):
            return auth.split(" ", 1)[1].strip()
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated",
        headers={"WWW-Authenticate": "Bearer"},
    )


async def get_current_customer(
    request: Request,
    session: Optional[str] = Cookie(default=None),
    pool: asyncpg.Pool = Depends(get_pool),
) -> dict[str, Any]:
    """Validate session and return the customer row.

    Raises 401 if the token is missing or invalid, 404 if the customer no
    longer exists or is deactivated.
    """
    token = _extract_token(request, session)
    payload = decode_jwt(token)
    customer_id = payload.get("sub")
    if not customer_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload",
        )

    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT * FROM customers WHERE id = $1 AND active = true",
            customer_id,
        )
    if not row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Customer not found",
        )
    return dict(row)
