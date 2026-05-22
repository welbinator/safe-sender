"""
Admin panel endpoints — Sprint 6.

Protected by ADMIN_SECRET env var (Bearer token).

Sprint C1 hotfix (audit C-4):
  - Optional IP allowlist via ADMIN_IP_ALLOWLIST (comma-separated CIDRs/IPs).
  - admin_audit_log: every authenticated admin action writes one row
    (ip, method, path, status, optional detail).
  - Per-IP rate limit (in-process token bucket): default 30 req/min per IP.

Sprint C1 t7: data access moved into AdminService + AdminAuditRepository.
Router keeps the auth/allowlist/rate-limit dependency (security primitive) and
end-of-handler audit calls; everything else goes through the service.

Endpoints:
  GET    /admin/customers           — list all customers with stats
  GET    /admin/stats               — system-wide stats
  GET    /admin/suppressed          — list suppressed addresses
  DELETE /admin/suppressed/{email}  — remove from suppression list
  GET    /admin/audit               — recent audit log entries
"""
from __future__ import annotations

import hmac
import ipaddress
import json
import logging
import os
import time
from collections import deque
from threading import Lock
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from deps import get_admin_service
from db import get_pool
from services import AdminService, NotFoundError

logger = logging.getLogger(__name__)

# ── Configuration ────────────────────────────────────────────────────────────
ADMIN_SECRET = os.environ.get("ADMIN_SECRET", "")
_WEAK_ADMIN = {"", "changeme", "secret", "password", "admin", "default"}
if ADMIN_SECRET and (ADMIN_SECRET.lower() in _WEAK_ADMIN or len(ADMIN_SECRET) < 32):
    raise RuntimeError(
        "ADMIN_SECRET is weak/default/short (<32 chars). "
        "Generate one with: python -c 'import secrets; print(secrets.token_urlsafe(48))'"
    )


def _parse_allowlist(raw: str) -> list:
    nets = []
    for chunk in raw.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        try:
            nets.append(ipaddress.ip_network(chunk, strict=False))
        except ValueError:
            logger.warning("admin: ignoring invalid ADMIN_IP_ALLOWLIST entry: %r", chunk)
    return nets


_ADMIN_ALLOWLIST = _parse_allowlist(os.environ.get("ADMIN_IP_ALLOWLIST", ""))
_RATE_LIMIT_PER_MIN = int(os.environ.get("ADMIN_RATE_LIMIT_PER_MIN", "30"))


def _client_ip(request: Request) -> str:
    """Return the request's client IP, trusting X-Forwarded-For only when set
    by our own nginx (we always set it on /api/admin/* in nginx.conf)."""
    xff = request.headers.get("x-forwarded-for", "")
    if xff:
        return xff.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "unknown"


def _ip_allowed(ip: str) -> bool:
    if not _ADMIN_ALLOWLIST:
        return True  # No allowlist configured → allow (auth still required).
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in _ADMIN_ALLOWLIST)


# ── Per-IP rate limiter (in-process; sufficient for the single-replica admin
# panel — if we ever scale we'll move it into Postgres). ─────────────────────
_rate_lock = Lock()
_rate_buckets: "dict[str, deque]" = {}


def _check_rate_limit(ip: str) -> bool:
    now = time.monotonic()
    window = 60.0
    with _rate_lock:
        bucket = _rate_buckets.setdefault(ip, deque())
        while bucket and now - bucket[0] > window:
            bucket.popleft()
        if len(bucket) >= _RATE_LIMIT_PER_MIN:
            return False
        bucket.append(now)
        return True


# ── Audit writer used by the auth dependency. Handlers use AdminService.write_audit
# (same target table, different transport). We can't hand AdminService to the
# dependency cleanly (it needs to fail-audit BEFORE auth resolves), so the
# dependency gets the pool directly and writes through asyncpg. The repository
# class is the only thing that knows the SQL — we mirror that here as a single
# parameterized INSERT to avoid duplicating it. ──────────────────────────────
async def _audit_from_dependency(
    ip: str, method: str, path: str, status_code: int, detail: Optional[dict] = None
) -> None:
    """Fire-and-forget audit write from the auth dependency."""
    try:
        pool = get_pool()
        async with pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO admin_audit_log (ip, method, path, status_code, detail)
                VALUES ($1, $2, $3, $4, $5::jsonb)
                """,
                ip, method, path, status_code,
                json.dumps(detail) if detail else None,
            )
    except Exception:  # never let audit failures break the admin response
        logger.exception("admin: failed to write audit log")


# ── FastAPI dependency ───────────────────────────────────────────────────────
router = APIRouter(prefix="/admin", tags=["admin"])
_bearer = HTTPBearer(auto_error=False)


async def _require_admin(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(_bearer),
) -> str:
    """Authn + IP allowlist + rate-limit + audit. Returns the client IP."""
    if not ADMIN_SECRET:
        raise HTTPException(status_code=503, detail="Admin panel not configured")

    ip = _client_ip(request)

    if not _ip_allowed(ip):
        await _audit_from_dependency(
            ip, request.method, request.url.path, 403,
            {"reason": "ip_not_allowlisted"},
        )
        raise HTTPException(status_code=403, detail="IP not allowed")

    if not _check_rate_limit(ip):
        await _audit_from_dependency(
            ip, request.method, request.url.path, 429,
            {"reason": "rate_limited"},
        )
        raise HTTPException(status_code=429, detail="Too many requests")

    if not credentials or not hmac.compare_digest(
        credentials.credentials or "", ADMIN_SECRET
    ):
        await _audit_from_dependency(
            ip, request.method, request.url.path, 401,
            {"reason": "bad_secret"},
        )
        raise HTTPException(status_code=401, detail="Unauthorized")

    # Success path — audit at the end of each handler so we capture
    # method-specific detail (e.g. which email was removed).
    return ip


async def _audit_ok(
    admin: AdminService,
    request: Request,
    ip: str,
    status_code: int,
    detail: Optional[dict[str, Any]] = None,
) -> None:
    """End-of-handler audit shortcut that goes through the service."""
    await admin.write_audit(
        ip=ip,
        method=request.method,
        path=request.url.path,
        status_code=status_code,
        detail=detail,
    )


# ── Endpoints ────────────────────────────────────────────────────────────────
@router.get("/customers")
async def list_customers(
    request: Request,
    ip: str = Depends(_require_admin),
    admin: AdminService = Depends(get_admin_service),
):
    rows = await admin.list_customers()
    await _audit_ok(admin, request, ip, 200, {"count": len(rows)})
    return [
        {
            "id": str(r["id"]),
            "email": r["email"],
            "name": r["name"],
            "domain": r["domain"],
            "domain_verified": r["domain_verified"],
            "created_at": r["created_at"].isoformat() if r["created_at"] else None,
            "emails_allowed": r["emails_allowed"] or 0,
            "emails_blocked": r["emails_blocked"] or 0,
            "last_activity": r["last_activity"].isoformat() if r["last_activity"] else None,
        }
        for r in rows
    ]


@router.get("/stats")
async def system_stats(
    request: Request,
    ip: str = Depends(_require_admin),
    admin: AdminService = Depends(get_admin_service),
):
    stats = await admin.system_stats()
    await _audit_ok(admin, request, ip, 200)
    return stats


@router.get("/suppressed")
async def list_suppressed(
    request: Request,
    ip: str = Depends(_require_admin),
    admin: AdminService = Depends(get_admin_service),
):
    rows = await admin.list_suppressed()
    await _audit_ok(admin, request, ip, 200, {"count": len(rows)})
    return [
        {
            "email": r["email"],
            "reason": r["reason"],
            "detail": r["detail"],
            "suppressed_at": r["suppressed_at"].isoformat(),
        }
        for r in rows
    ]


@router.delete("/suppressed/{email}")
async def remove_suppressed(
    email: str,
    request: Request,
    ip: str = Depends(_require_admin),
    admin: AdminService = Depends(get_admin_service),
):
    try:
        deleted = await admin.remove_suppression(email)
    except NotFoundError:
        await _audit_ok(admin, request, ip, 404, {"email": email.lower()})
        raise HTTPException(status_code=404, detail="Address not found in suppression list")
    await _audit_ok(admin, request, ip, 200, {"email": email.lower(), "deleted": deleted})
    return {"status": "removed", "email": email.lower()}


@router.get("/audit")
async def list_audit(
    request: Request,
    ip: str = Depends(_require_admin),
    limit: int = 200,
    admin: AdminService = Depends(get_admin_service),
):
    """Recent admin audit entries (newest first)."""
    rows = await admin.list_audit(limit=limit)
    await _audit_ok(admin, request, ip, 200, {"returned": len(rows)})
    return [
        {
            "id": r["id"],
            "created_at": r["created_at"].isoformat(),
            "ip": r["ip"],
            "method": r["method"],
            "path": r["path"],
            "status_code": r["status_code"],
            "detail": r["detail"],
        }
        for r in rows
    ]
