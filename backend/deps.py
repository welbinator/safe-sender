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
from repositories import (
    AdminAuditRepository,
    CustomerRepository,
    RuleRepository,
    ScanLogRepository,
    SuppressionRepository,
)

# Sprint C1 hotfix (audit C-3): mutating requests authenticated by the
# `session` cookie MUST carry this custom header. Browsers won't attach
# custom headers cross-origin without a CORS preflight (which the backend
# only grants to its own dashboard origin), so a third-party site cannot
# forge a state-changing call even while the cookie is live.
_CSRF_HEADER = "X-Requested-With"
_CSRF_EXPECTED = "sender-safety"
_MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


async def get_pool() -> asyncpg.Pool:
    """
    Re-export the pool stored on app state.
    Import the app object lazily to avoid circular imports.
    """
    from main import get_pool as _get_pool
    return _get_pool()


def _extract_token(request: Request, session_cookie: Optional[str]) -> str:
    """Cookie first, then Authorization header (when allowed). 401 otherwise.

    When the cookie path is used and the request mutates state, require the
    CSRF custom header (see C-3 hotfix). Bearer-token requests bypass the
    check because non-browser clients can't be CSRF'd.
    """
    if session_cookie:
        if request.method in _MUTATING_METHODS:
            header_val = request.headers.get(_CSRF_HEADER, "")
            if header_val != _CSRF_EXPECTED:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=(
                        "Missing or invalid CSRF header. "
                        f"Cookie-authenticated {request.method} requests must "
                        f"include `{_CSRF_HEADER}: {_CSRF_EXPECTED}`."
                    ),
                )
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
        row = await CustomerRepository(conn).get_active_by_id(customer_id)
    if not row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Customer not found",
        )
    return row


# ---------------------------------------------------------------------------
# Repository factory dependencies
#
# Each factory acquires a connection from the pool for the lifetime of the
# request via FastAPI's generator-based dependency contract. Routers receive a
# fully-constructed repo and never touch raw SQL or the pool themselves.
# ---------------------------------------------------------------------------

async def get_customer_repo(
    pool: asyncpg.Pool = Depends(get_pool),
):
    async with pool.acquire() as conn:
        yield CustomerRepository(conn)


async def get_rule_repo(
    pool: asyncpg.Pool = Depends(get_pool),
):
    async with pool.acquire() as conn:
        yield RuleRepository(conn)


async def get_scan_log_repo(
    pool: asyncpg.Pool = Depends(get_pool),
):
    async with pool.acquire() as conn:
        yield ScanLogRepository(conn)


async def get_suppression_repo(
    pool: asyncpg.Pool = Depends(get_pool),
):
    async with pool.acquire() as conn:
        yield SuppressionRepository(conn)


async def get_admin_audit_repo(
    pool: asyncpg.Pool = Depends(get_pool),
):
    async with pool.acquire() as conn:
        yield AdminAuditRepository(conn)


# ---------------------------------------------------------------------------
# Service factory dependencies
#
# Services compose 1+ repository over a single request-scoped connection. We
# acquire once per dependency so the repos inside share that connection — this
# is what lets services run multi-step operations transactionally if they need
# to (today they don't, but the seam is here when we want it).
# ---------------------------------------------------------------------------

async def get_customer_service(
    pool: asyncpg.Pool = Depends(get_pool),
):
    """CustomerService with scan-log access wired in.

    A single repo+service stack would be enough for profile/SMTP creds, but
    test-connection needs scan_logs too. One acquire, both repos, one service.
    """
    from services import CustomerService
    async with pool.acquire() as conn:
        yield CustomerService(
            customers=CustomerRepository(conn),
            scan_logs=ScanLogRepository(conn),
        )


async def get_rule_service(
    pool: asyncpg.Pool = Depends(get_pool),
):
    from services import RuleService
    async with pool.acquire() as conn:
        yield RuleService(RuleRepository(conn))


async def get_auth_service(
    pool: asyncpg.Pool = Depends(get_pool),
):
    """AuthService wraps CustomerRepository — Google login upsert path."""
    from services import AuthService
    async with pool.acquire() as conn:
        yield AuthService(CustomerRepository(conn))


async def get_log_service(
    pool: asyncpg.Pool = Depends(get_pool),
):
    from services import LogService
    async with pool.acquire() as conn:
        yield LogService(ScanLogRepository(conn))


async def get_admin_service(
    pool: asyncpg.Pool = Depends(get_pool),
):
    from services import AdminService
    async with pool.acquire() as conn:
        yield AdminService(
            admin_audit=AdminAuditRepository(conn),
            suppressions=SuppressionRepository(conn),
        )


async def get_webhook_service(
    pool: asyncpg.Pool = Depends(get_pool),
):
    from services import SesWebhookService
    async with pool.acquire() as conn:
        yield SesWebhookService(SuppressionRepository(conn))
