"""
Admin panel endpoints — Sprint 6.

Protected by ADMIN_SECRET env var (Bearer token).
Not exposed to regular customers — nginx should block /api/admin/* from public
access or at minimum it's protected by the secret.

Endpoints:
  GET  /admin/customers     — list all customers with stats
  GET  /admin/stats         — system-wide stats
  GET  /admin/suppressed    — list suppressed addresses
  DELETE /admin/suppressed/{email} — remove from suppression list
"""

import os
import logging
from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from main import get_pool

logger = logging.getLogger(__name__)

ADMIN_SECRET = os.environ.get("ADMIN_SECRET", "")

router = APIRouter(prefix="/admin", tags=["admin"])
_bearer = HTTPBearer(auto_error=False)


def _require_admin(credentials: HTTPAuthorizationCredentials = Depends(_bearer)):
    if not ADMIN_SECRET:
        raise HTTPException(status_code=503, detail="Admin panel not configured")
    if not credentials or credentials.credentials != ADMIN_SECRET:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return True


@router.get("/customers")
async def list_customers(_=Depends(_require_admin)):
    """List all customers with their scan stats."""
    pool = get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT
                c.id,
                c.email,
                c.name,
                c.domain,
                c.domain_verified,
                c.created_at,
                COUNT(sl.id) FILTER (WHERE sl.outcome = 'allowed') AS emails_allowed,
                COUNT(sl.id) FILTER (WHERE sl.outcome = 'blocked') AS emails_blocked,
                MAX(sl.created_at) AS last_activity
            FROM customers c
            LEFT JOIN scan_logs sl ON sl.customer_id = c.id
            GROUP BY c.id
            ORDER BY c.created_at DESC
            """
        )
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
async def system_stats(_=Depends(_require_admin)):
    """System-wide stats."""
    pool = get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT
                (SELECT COUNT(*) FROM customers) AS total_customers,
                (SELECT COUNT(*) FROM customers WHERE domain_verified = true) AS verified_customers,
                (SELECT COUNT(*) FROM scan_logs) AS total_scans,
                (SELECT COUNT(*) FROM scan_logs WHERE outcome = 'blocked') AS total_blocked,
                (SELECT COUNT(*) FROM scan_logs WHERE created_at > NOW() - INTERVAL '24 hours') AS scans_24h,
                (SELECT COUNT(*) FROM scan_logs WHERE outcome = 'blocked' AND created_at > NOW() - INTERVAL '24 hours') AS blocked_24h,
                (SELECT COUNT(*) FROM suppressed_addresses) AS suppressed_addresses
            """
        )
    return dict(row)


@router.get("/suppressed")
async def list_suppressed(_=Depends(_require_admin)):
    """List suppressed email addresses."""
    pool = get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT email, reason, detail, suppressed_at FROM suppressed_addresses ORDER BY suppressed_at DESC LIMIT 500"
        )
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
async def remove_suppressed(email: str, _=Depends(_require_admin)):
    """Remove an address from the suppression list."""
    pool = get_pool()
    async with pool.acquire() as conn:
        result = await conn.execute(
            "DELETE FROM suppressed_addresses WHERE email = $1", email.lower()
        )
    deleted = int(result.split()[-1])
    if deleted == 0:
        raise HTTPException(status_code=404, detail="Address not found in suppression list")
    return {"status": "removed", "email": email.lower()}
