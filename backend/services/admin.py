"""Admin-panel read/write service.

Wraps AdminAuditRepository + SuppressionRepository so the admin router becomes
a thin layer that handles auth, IP allowlisting, rate limiting, and audit
write-back. The audit row itself is still written from the router because it
needs Request metadata (method, path, status_code).
"""
from __future__ import annotations

from typing import Any, Optional

from repositories import AdminAuditRepository, SuppressionRepository

from .errors import NotFoundError


class AdminService:
    __slots__ = ("admin_audit", "suppressions")

    def __init__(
        self,
        admin_audit: AdminAuditRepository,
        suppressions: SuppressionRepository,
    ) -> None:
        self.admin_audit = admin_audit
        self.suppressions = suppressions

    # ── reads ────────────────────────────────────────────────────────────────
    async def list_customers(self) -> list[dict[str, Any]]:
        return await self.admin_audit.list_customers_with_stats()

    async def system_stats(self) -> dict[str, Any]:
        return await self.admin_audit.system_stats()

    async def list_suppressed(self, limit: int = 500) -> list[dict[str, Any]]:
        return await self.suppressions.list_recent(limit=limit)

    async def list_audit(self, limit: int = 200) -> list[dict[str, Any]]:
        limit = max(1, min(limit, 1000))
        return await self.admin_audit.list_audit(limit=limit)

    # ── writes ───────────────────────────────────────────────────────────────
    async def remove_suppression(self, email: str) -> int:
        deleted = await self.suppressions.delete_by_email(email.lower())
        if deleted == 0:
            raise NotFoundError("Address not found in suppression list")
        return deleted

    async def write_audit(
        self,
        *,
        ip: str,
        method: str,
        path: str,
        status_code: int,
        detail: Optional[dict[str, Any]] = None,
    ) -> None:
        # Pure pass-through — but routed through the service so callers don't
        # have to know the repository exists. Failures are swallowed by the
        # repository (audit must never break the response path).
        await self.admin_audit.write_audit(
            ip=ip,
            method=method,
            path=path,
            status_code=status_code,
            detail=detail,
        )
