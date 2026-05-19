"""
FastAPI dependency: extract and validate the current customer from the
Authorization: Bearer <jwt> header.
"""
from typing import Any

import asyncpg
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from auth_utils import decode_jwt

bearer_scheme = HTTPBearer()


async def get_pool() -> asyncpg.Pool:
    """
    Re-export the pool stored on app state.
    Import the app object lazily to avoid circular imports.
    """
    from main import get_pool as _get_pool
    return _get_pool()


async def get_current_customer(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    pool: asyncpg.Pool = Depends(get_pool),
) -> dict[str, Any]:
    """
    Dependency that:
    1. Validates the JWT from the Authorization header.
    2. Loads and returns the customer row from Postgres.
    Raises 401 if token is invalid, 404 if customer no longer exists.
    """
    payload = decode_jwt(credentials.credentials)
    customer_id = payload.get("sub")
    if not customer_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload")

    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT * FROM customers WHERE id = $1 AND active = true",
            customer_id,
        )
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Customer not found")

    return dict(row)
