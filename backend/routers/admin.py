"""
Admin panel endpoints — Sprint 6.

Protected by ADMIN_SECRET env var (Bearer token).

Sprint C1 hotfix (audit C-4):
  - Optional IP allowlist via ADMIN_IP_ALLOWLIST (comma-separated CIDRs/IPs).
  - admin_audit_log: every authenticated admin action writes one row
    (ip, method, path, status, optional detail).
  - Per-IP rate limit (Postgres-backed sliding window, F-19): default 30 req/min per IP.

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
import logging
import os
import random
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from deps import get_admin_service
from db import get_pool
from services import NotFoundError
from services.admin import AdminService

logger = logging.getLogger(__name__)

# ── Configuration ────────────────────────────────────────────────────────────
ADMIN_SECRET = os.environ.get("ADMIN_SECRET", "")
_WEAK_ADMIN = {"", "changeme", "secret", "password", "admin", "default"}
if ADMIN_SECRET and (ADMIN_SECRET.lower() in _WEAK_ADMIN or len(ADMIN_SECRET) < 48):
    raise RuntimeError(
        "ADMIN_SECRET is weak/default/short (<48 chars). "
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
    """Return the request's client IP.

    F-18: nginx uses ``proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for``
    which *appends* to whatever the client sent. Trusting the first hop lets an
    attacker spoof the admin allowlist / rate-limit key. We instead prefer
    ``X-Real-IP`` (which nginx overwrites with ``$remote_addr``) and fall back to
    the *last* hop of XFF — the address closest to our trust boundary — never
    the first.
    """
    real_ip = request.headers.get("x-real-ip", "").strip()
    if real_ip:
        return real_ip
    xff = request.headers.get("x-forwarded-for", "")
    if xff:
        parts = [p.strip() for p in xff.split(",") if p.strip()]
        if parts:
            return parts[-1]
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


# ── Per-IP rate limiter — Postgres-backed sliding window (F-19) ──────────────
# The previous in-process limiter died on every container restart and was
# bypassed entirely by horizontal scale-out. Each call goes to AdminRateLimit
# Repository which does a single atomic UPSERT + RETURNING.
async def _check_rate_limit(ip: str) -> bool:
    try:
        pool = get_pool()
        async with pool.acquire() as conn:
            from repositories import AdminRateLimitRepository
            limiter = AdminRateLimitRepository(conn)
            ok = await limiter.hit(ip, _RATE_LIMIT_PER_MIN)
            # Opportunistic GC: 1% of requests purge stale windows.
            if random.random() < 0.01:
                await limiter.purge_expired()
            return ok
    except Exception:
        # Fail-open on DB error — the alternative is locking out the admin
        # panel during an outage, which makes recovery harder. Audit log
        # records the rate-limit-skipped path implicitly (the admin call
        # itself is logged).
        logger.exception("admin: rate limiter DB call failed; allowing request")
        try:
            import sentry_sdk
            sentry_sdk.capture_message(
                "admin_rate_limit_fail_open",
                level="warning",
                extras={"ip": ip},
            )
        except Exception:  # noqa: BLE001
            pass
        return True


# ── Audit writer used by the auth dependency. Handlers use AdminService.write_audit
# (same target table, different transport). We can't hand AdminService to the
# dependency cleanly (it needs to fail-audit BEFORE auth resolves), so the
# dependency gets the pool directly and writes through asyncpg. The repository
# class is the only thing that knows the SQL — we mirror that here as a single
# parameterized INSERT to avoid duplicating it. ──────────────────────────────
# F-14 / F-21: route the dependency-level audit through the service layer too,
# so there is exactly one INSERT statement for admin_audit_log in the codebase
# (in AdminAuditRepository) and the router is data-access free.
async def _audit_from_dependency(
    ip: str, method: str, path: str, status_code: int, detail: Optional[dict] = None
) -> None:
    """Fire-and-forget audit write from the auth dependency."""
    try:
        pool = get_pool()
        async with pool.acquire() as conn:
            from repositories import AdminAuditRepository, SuppressionRepository
            from services.admin import AdminService
            admin = AdminService(
                admin_audit=AdminAuditRepository(conn),
                suppressions=SuppressionRepository(conn),
            )
            await admin.write_audit(
                ip=ip,
                method=method,
                path=path,
                status_code=status_code,
                detail=detail,
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

    if not await _check_rate_limit(ip):
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


@router.get("/performance")
async def performance(
    request: Request,
    days: int = 30,
    ip: str = Depends(_require_admin),
    admin: AdminService = Depends(get_admin_service),
):
    """Owner performance dashboard data.

    Returns:
      - daily_volume: emails/day for the last `days` days (allowed + blocked)
      - timing: avg and p95 processing_ms per day (only rows with timing data)
      - customer_breakdown: per-customer totals for the period
      - summary: headline numbers for the whole period
    """
    pool = get_pool()
    async with pool.acquire() as conn:
        # ── Daily volume + block rate ────────────────────────────────────────
        daily_rows = await conn.fetch(
            """
            SELECT
                date_trunc('day', created_at AT TIME ZONE 'UTC') AS day,
                COUNT(*)                                           AS total,
                COUNT(*) FILTER (WHERE outcome = 'blocked')       AS blocked,
                COUNT(*) FILTER (WHERE outcome = 'allowed')       AS allowed
            FROM scan_logs
            WHERE created_at >= NOW() - ($1 || ' days')::interval
            GROUP BY 1
            ORDER BY 1
            """,
            str(days),
        )

        # ── Daily timing (avg + p95) ─────────────────────────────────────────
        timing_rows = await conn.fetch(
            """
            SELECT
                date_trunc('day', created_at AT TIME ZONE 'UTC') AS day,
                ROUND(AVG(processing_ms))                         AS avg_ms,
                PERCENTILE_CONT(0.95) WITHIN GROUP
                    (ORDER BY processing_ms)                      AS p95_ms
            FROM scan_logs
            WHERE created_at >= NOW() - ($1 || ' days')::interval
              AND processing_ms IS NOT NULL
            GROUP BY 1
            ORDER BY 1
            """,
            str(days),
        )

        # ── Per-customer breakdown ────────────────────────────────────────────
        customer_rows = await conn.fetch(
            """
            SELECT
                c.id,
                c.domain,
                c.email,
                COUNT(*)                                            AS total,
                COUNT(*) FILTER (WHERE sl.outcome = 'blocked')     AS blocked,
                COUNT(*) FILTER (WHERE sl.outcome = 'allowed')     AS allowed,
                ROUND(AVG(sl.processing_ms))                       AS avg_ms,
                MAX(sl.created_at)                                  AS last_seen
            FROM scan_logs sl
            JOIN customers c ON c.id = sl.customer_id
            WHERE sl.created_at >= NOW() - ($1 || ' days')::interval
            GROUP BY c.id, c.domain, c.email
            ORDER BY total DESC
            """,
            str(days),
        )

        # ── Summary totals ────────────────────────────────────────────────────
        summary_row = await conn.fetchrow(
            """
            SELECT
                COUNT(*)                                          AS total,
                COUNT(*) FILTER (WHERE outcome = 'blocked')      AS blocked,
                COUNT(*) FILTER (WHERE outcome = 'allowed')      AS allowed,
                ROUND(AVG(processing_ms))                        AS avg_ms,
                ROUND(PERCENTILE_CONT(0.95) WITHIN GROUP
                    (ORDER BY processing_ms)::numeric, 0)        AS p95_ms,
                COUNT(DISTINCT customer_id)                      AS active_customers
            FROM scan_logs
            WHERE created_at >= NOW() - ($1 || ' days')::interval
            """,
            str(days),
        )


        # -- Recent emails (last 10, no date filter) --
        recent_rows = await conn.fetch(
            """
            SELECT
                sl.sender,
                sl.recipient,
                sl.outcome,
                sl.processing_ms,
                sl.created_at,
                sl.ai_decision,
                sl.ai_confidence,
                COALESCE(r.name, r.pattern) AS rule_triggered,
                c.domain
            FROM scan_logs sl
            JOIN customers c ON c.id = sl.customer_id
            LEFT JOIN rules r ON r.id = sl.matched_rule_id
            ORDER BY sl.created_at DESC
            LIMIT 10
            """
        )

    await _audit_ok(admin, request, ip, 200, {"days": days})

    return {
        "period_days": days,
        "summary": {
            "total": summary_row["total"],
            "blocked": summary_row["blocked"],
            "allowed": summary_row["allowed"],
            "block_rate_pct": round(
                (summary_row["blocked"] / summary_row["total"] * 100), 1
            ) if summary_row["total"] else 0,
            "avg_ms": summary_row["avg_ms"],
            "p95_ms": summary_row["p95_ms"],
            "active_customers": summary_row["active_customers"],
        },
        "daily_volume": [
            {
                "day": r["day"].strftime("%Y-%m-%d"),
                "total": r["total"],
                "blocked": r["blocked"],
                "allowed": r["allowed"],
            }
            for r in daily_rows
        ],
        "daily_timing": [
            {
                "day": r["day"].strftime("%Y-%m-%d"),
                "avg_ms": int(r["avg_ms"]) if r["avg_ms"] else None,
                "p95_ms": int(r["p95_ms"]) if r["p95_ms"] else None,
            }
            for r in timing_rows
        ],
        "customer_breakdown": [
            {
                "id": str(r["id"]),
                "domain": r["domain"],
                "email": r["email"],
                "total": r["total"],
                "blocked": r["blocked"],
                "allowed": r["allowed"],
                "block_rate_pct": round(
                    (r["blocked"] / r["total"] * 100), 1
                ) if r["total"] else 0,
                "avg_ms": int(r["avg_ms"]) if r["avg_ms"] else None,
                "last_seen": r["last_seen"].isoformat() if r["last_seen"] else None,
            }
            for r in customer_rows
        ],
        "recent_emails": [
            {
                "sender": r["sender"],
                "recipient": r["recipient"],
                "outcome": r["outcome"],
                "processing_ms": r["processing_ms"],
                "created_at": r["created_at"].isoformat() if r["created_at"] else None,
                "ai_decision": r["ai_decision"],
                "ai_confidence": r["ai_confidence"],
                "rule_triggered": r["rule_triggered"],
                "domain": r["domain"],
            }
            for r in recent_rows
        ],
    }
