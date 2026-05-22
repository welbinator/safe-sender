"""admin_audit_log + admin-side customer/stats reads."""
from __future__ import annotations

import json
from typing import Any, Optional

from .base import BaseRepository, _as_dict, _as_dicts


class AdminAuditRepository(BaseRepository):
    """Cross-aggregate reads/writes used exclusively by the admin panel.

    Lives alongside the audit log because every admin endpoint touches the
    audit table on the same connection, so colocating them keeps the
    transactional story simple.
    """

    # --- audit log ------------------------------------------------------

    async def write_audit(
        self,
        *,
        ip: str,
        method: str,
        path: str,
        status_code: int,
        detail: Optional[dict] = None,
    ) -> None:
        await self.conn.execute(
            """
            INSERT INTO admin_audit_log (ip, method, path, status_code, detail)
            VALUES ($1, $2, $3, $4, $5::jsonb)
            """,
            ip, method, path, status_code,
            json.dumps(detail) if detail else None,
        )

    async def list_audit(self, limit: int = 200) -> list[dict[str, Any]]:
        rows = await self.conn.fetch(
            """
            SELECT id, created_at, ip, method, path, status_code, detail
            FROM admin_audit_log
            ORDER BY id DESC
            LIMIT $1
            """,
            limit,
        )
        return _as_dicts(rows)

    # --- customer overview (admin /customers) ---------------------------

    async def list_customers_with_stats(self) -> list[dict[str, Any]]:
        rows = await self.conn.fetch(
            """
            SELECT
                c.id, c.email, c.name, c.domain, c.domain_verified, c.created_at,
                COUNT(sl.id) FILTER (WHERE sl.outcome = 'allowed') AS emails_allowed,
                COUNT(sl.id) FILTER (WHERE sl.outcome = 'blocked') AS emails_blocked,
                MAX(sl.created_at) AS last_activity
            FROM customers c
            LEFT JOIN scan_logs sl ON sl.customer_id = c.id
            GROUP BY c.id
            ORDER BY c.created_at DESC
            """
        )
        return _as_dicts(rows)

    # --- system stats (admin /stats) ------------------------------------

    async def system_stats(self) -> dict[str, Any]:
        row = await self.conn.fetchrow(
            """
            SELECT
                (SELECT COUNT(*) FROM customers) AS total_customers,
                (SELECT COUNT(*) FROM customers WHERE domain_verified = true) AS verified_customers,
                (SELECT COUNT(*) FROM scan_logs) AS total_scans,
                (SELECT COUNT(*) FROM scan_logs WHERE outcome = 'blocked') AS total_blocked,
                (SELECT COUNT(*) FROM scan_logs WHERE created_at > NOW() - INTERVAL '24 hours') AS scans_24h,
                (SELECT COUNT(*) FROM scan_logs WHERE outcome = 'blocked'
                   AND created_at > NOW() - INTERVAL '24 hours') AS blocked_24h,
                (SELECT COUNT(*) FROM suppressed_addresses) AS suppressed_addresses
            """
        )
        return dict(row) if row else {}
