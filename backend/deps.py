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


# Sprint C3 F-20: ALLOW_BEARER_AUTH=1 disables CSRF protection (no cookie, no
# header). It exists for test runs and curl-debugging from the operator's
# machine. In production environments it must NEVER be on — fail the boot
# loudly rather than silently exposing an auth bypass.
_APP_ENV = os.environ.get("APP_ENV", "development").lower()
_ALLOW_BEARER_AUTH = os.environ.get("ALLOW_BEARER_AUTH", "0") == "1"
if _ALLOW_BEARER_AUTH and _APP_ENV in {"production", "prod"}:
    raise RuntimeError(
        "ALLOW_BEARER_AUTH=1 is forbidden when APP_ENV=production. "
        "Bearer auth bypasses CSRF protection and must only be enabled "
        "in dev/test environments."
    )


def issue_csrf_token() -> str:
    """Mint a 256-bit URL-safe random token for the csrf_token cookie."""
    return secrets.token_urlsafe(32)


# F-13: get_pool is imported from db at top of file; Depends(get_pool) works
# directly because FastAPI accepts sync callables that return the resource.


async def get_conn(pool: asyncpg.Pool = Depends(get_pool)):
    """Acquire a single connection from the pool for the request lifetime.

    See F-12 comment block below for rationale.
    """
    async with pool.acquire() as conn:
        yield conn


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
    if _ALLOW_BEARER_AUTH:
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
    conn=Depends(get_conn),
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

    row = await CustomerRepository(conn).get_active_by_id(customer_id)
    if not row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Customer not found",
        )
    return row


# ---------------------------------------------------------------------------
# Request-scoped connection (Sprint C3 F-12).
#
# Before: every repo/service dep called pool.acquire() independently, so a
# single request that touched N services pulled N connections out of the pool.
# With max_size=10 you'd exhaust the pool at ~3 concurrent requests.
#
# Now: get_conn yields ONE connection for the whole request. FastAPI caches
# dependency results per-request, so every Depends(get_conn) downstream
# resolves to the same connection object. Repo and service factories no longer
# touch the pool directly — they take the cached conn.
#
# Side benefit: services that compose multiple repos now share a connection
# automatically, so multi-step operations on the same request are trivially
# transactionable (`async with conn.transaction(): ...`).
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Repository factory dependencies — one connection per request (F-12).
# ---------------------------------------------------------------------------

async def get_customer_repo(conn=Depends(get_conn)):
    return CustomerRepository(conn)


async def get_rule_repo(conn=Depends(get_conn)):
    return RuleRepository(conn)


async def get_scan_log_repo(conn=Depends(get_conn)):
    return ScanLogRepository(conn)


async def get_suppression_repo(conn=Depends(get_conn)):
    return SuppressionRepository(conn)


async def get_admin_audit_repo(conn=Depends(get_conn)):
    return AdminAuditRepository(conn)


# ---------------------------------------------------------------------------
# Rate-limit dependencies (F-49).
#
# Two flavors:
#   - rate_limit_read / rate_limit_write apply per authenticated customer
#     (subject = customer UUID). Use on customer-facing CRUD.
#   - rate_limit_auth_ip applies per source IP. Use on login endpoints,
#     where there's no authenticated subject yet.
#
# All are FastAPI deps that 429 on breach with a Retry-After header. Fail-open
# when Redis is unreachable — the rate_limit module handles that.
# ---------------------------------------------------------------------------

from security import (
    check_auth_by_ip,
    check_customer_read,
    check_customer_write,
)


def _retry_after_headers(retry_after_s: float) -> dict[str, str]:
    # RFC 7231: Retry-After can be HTTP-date or seconds. Use integer seconds,
    # min 1 (a 0 doesn't tell the client to wait at all).
    return {"Retry-After": str(max(1, int(retry_after_s + 0.999)))}


async def rate_limit_read(
    customer: dict[str, Any] = Depends(get_current_customer),
) -> None:
    result = await check_customer_read(str(customer["id"]))
    if not result.allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded for read operations. Slow down.",
            headers=_retry_after_headers(result.retry_after_seconds),
        )


async def rate_limit_write(
    customer: dict[str, Any] = Depends(get_current_customer),
) -> None:
    result = await check_customer_write(str(customer["id"]))
    if not result.allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded for write operations. Slow down.",
            headers=_retry_after_headers(result.retry_after_seconds),
        )


# Code Audit Two — H-1: client-IP spoofing in auth rate limiter.
#
# Previously this returned the LEFTMOST X-Forwarded-For value, which is the
# segment a client can set freely — nginx APPENDS the real source IP via
# $proxy_add_x_forwarded_for, it does NOT strip whatever the client sent.
# That let an attacker rotate `X-Forwarded-For: 1.2.3.4` per request and
# never trip the per-IP auth limit, defeating credential-stuffing protection.
#
# Trust model: we sit behind exactly one trusted proxy hop (our own nginx).
# Nginx writes `X-Real-IP: $remote_addr` on every proxied request. That value
# is the TCP peer nginx saw — the actual client (or upstream proxy if one
# day we add Cloudflare in front). Clients cannot influence it because nginx
# OVERWRITES the header rather than appending. So X-Real-IP is the
# authoritative client IP for rate-limit keying.
#
# Fallbacks in priority order:
#   1. X-Real-IP            — set by nginx, not appendable.
#   2. rightmost XFF hop    — also nginx-appended (resists left-side spoof).
#   3. request.client.host  — direct connection (e.g. tests, bypassed nginx).
#
# We deliberately do NOT trust the leftmost XFF token. If we ever add a
# second trusted proxy hop in front of nginx, revisit this and parse XFF
# from right-to-left, popping one entry per trusted hop.
def _client_ip(request: Request) -> str:
    real_ip = request.headers.get("x-real-ip", "").strip()
    if real_ip:
        return real_ip
    xff = request.headers.get("x-forwarded-for", "")
    if xff:
        # Rightmost token = nearest proxy we trust appended it.
        return xff.rsplit(",", 1)[-1].strip()
    return request.client.host if request.client else "unknown"


async def rate_limit_auth_ip(request: Request) -> None:
    ip = _client_ip(request)
    result = await check_auth_by_ip(ip)
    if not result.allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many auth attempts from this IP. Slow down.",
            headers=_retry_after_headers(result.retry_after_seconds),
        )


# ---------------------------------------------------------------------------
# Service factory dependencies — share the request connection (F-12).
# ---------------------------------------------------------------------------

async def get_customer_service(conn=Depends(get_conn)):
    """CustomerService with scan-log access wired in over the shared conn."""
    from services.customers import CustomerService
    return CustomerService(
        customers=CustomerRepository(conn),
        scan_logs=ScanLogRepository(conn),
    )


async def get_rule_service(conn=Depends(get_conn)):
    from services.rules import RuleService
    return RuleService(RuleRepository(conn))


async def get_auth_service(conn=Depends(get_conn)):
    """AuthService wraps CustomerRepository — Google login upsert path."""
    from services.auth import AuthService
    return AuthService(CustomerRepository(conn))


async def get_log_service(conn=Depends(get_conn)):
    from services.logs import LogService
    return LogService(ScanLogRepository(conn))


async def get_admin_service(conn=Depends(get_conn)):
    from services.admin import AdminService
    return AdminService(
        admin_audit=AdminAuditRepository(conn),
        suppressions=SuppressionRepository(conn),
    )


async def get_webhook_service(conn=Depends(get_conn)):
    from services.webhooks import MailgunWebhookService
    return MailgunWebhookService(SuppressionRepository(conn))
