"""
FastAPI dependencies for auth + DB.

Auth (Sprint B C13): the preferred transport is the HttpOnly `session` cookie
set by POST /auth/google. We also accept `Authorization: Bearer <jwt>` as a
fallback so non-browser API clients and the transition window keep working —
this is gated by ALLOW_BEARER_AUTH (default "0" as of Sprint C2 F-10 — flip
to "1" explicitly if a non-browser client still needs it).

CSRF (Sprint C3 F-11): cookie-authenticated mutating requests must pass the
double-submit-cookie check: the `csrf_token` cookie (non-HttpOnly, set at login)
must equal the `X-CSRF-Token` request header. Cross-origin attackers can't read
the cookie, so they can't forge the header. Bearer-auth bypasses (no cookie =
no CSRF surface).
"""
import os
import secrets
from typing import Any, Optional

import asyncpg
from fastapi import Cookie, Depends, HTTPException, Request, status

from db import get_pool  # F-13: real module, no more circular-import dodge
from security import decode_jwt
from repositories import (
    AdminAuditRepository,
    CustomerRepository,
    RuleRepository,
    ScanLogRepository,
    SuppressionRepository,
)

# Sprint C3 F-11: double-submit-cookie CSRF.
#   - On login we set a non-HttpOnly `csrf_token` cookie (JS can read it).
#   - The frontend mirrors it into the `X-CSRF-Token` header on every mutation.
#   - We compare cookie value vs header value with constant-time equality.
# A cross-origin attacker can neither read the cookie (Same-Origin Policy) nor
# guess the random 256-bit token, so they can't satisfy the header check even
# while the browser auto-sends the session cookie.
#
# This replaces the C1 hotfix that only checked for `X-Requested-With:
# sender-safety` — a constant string that a same-site XSS or any client could
# trivially attach.
_CSRF_HEADER = "X-CSRF-Token"
_CSRF_COOKIE = "csrf_token"
_MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def issue_csrf_token() -> str:
    """Mint a 256-bit URL-safe random token for the csrf_token cookie."""
    return secrets.token_urlsafe(32)


# F-13: get_pool is imported from db at top of file; Depends(get_pool) works
# directly because FastAPI accepts sync callables that return the resource.


def _extract_token(request: Request, session_cookie: Optional[str]) -> str:
    """Cookie first, then Authorization header (when allowed). 401 otherwise.

    When the cookie path is used and the request mutates state, require the
    CSRF custom header (see C-3 hotfix). Bearer-token requests bypass the
    check because non-browser clients can't be CSRF'd.
    """
    if session_cookie:
        if request.method in _MUTATING_METHODS:
            header_val = request.headers.get(_CSRF_HEADER, "")
            cookie_val = request.cookies.get(_CSRF_COOKIE, "")
            # Both must be present and constant-time equal. Empty strings
            # fail by definition (compare_digest of "" == "" returns True,
            # so we must also reject empty explicitly).
            if not header_val or not cookie_val or not secrets.compare_digest(
                header_val, cookie_val
            ):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=(
                        "CSRF check failed. Cookie-authenticated "
                        f"{request.method} requests must mirror the "
                        f"`{_CSRF_COOKIE}` cookie into the `{_CSRF_HEADER}` header."
                    ),
                )
        return session_cookie
    if os.environ.get("ALLOW_BEARER_AUTH", "0") == "1":
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
