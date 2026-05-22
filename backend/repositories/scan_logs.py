"""scan_logs table access — read-side only (writes happen in SMTP worker)."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from .base import BaseRepository, _as_dicts


class ScanLogRepository(BaseRepository):
    """Reads for the customer-facing /logs endpoint and the test-connection poll."""

    async def count_for_customer(self, customer_id: Any) -> int:
        return await self.conn.fetchval(
            "SELECT COUNT(*) FROM scan_logs WHERE customer_id = $1",
            customer_id,
        )

    async def search(
        self,
        *,
        customer_id: Any,
        outcome: Optional[str],
        sender: Optional[str],
        date_from: Optional[datetime],
        date_to: Optional[datetime],
        limit: int,
        offset: int,
    ) -> tuple[int, list[dict[str, Any]]]:
        """Paginated, filtered scan-log search joined with rule metadata.

        Returns ``(total_count, rows)``. Builds the WHERE clause once and
        runs the COUNT + SELECT against the same parameter list.
        """
        filters = ["l.customer_id = $1"]
        params: list[Any] = [customer_id]
        idx = 2

        if outcome:
            filters.append(f"l.outcome = ${idx}")
            params.append(outcome)
            idx += 1
        if sender:
            filters.append(f"l.sender ILIKE ${idx}")
            params.append(f"%{sender}%")
            idx += 1
        if date_from:
            filters.append(f"l.created_at >= ${idx}")
            params.append(date_from)
            idx += 1
        if date_to:
            filters.append(f"l.created_at <= ${idx}")
            params.append(date_to)
            idx += 1

        where = " AND ".join(filters)

        total: int = await self.conn.fetchval(
            f"SELECT COUNT(*) FROM scan_logs l WHERE {where}", *params
        )
        rows = await self.conn.fetch(
            f"""
            SELECT
                l.id, l.sender, l.recipient, l.outcome,
                l.matched_rule_id, l.created_at,
                r.name        AS matched_rule_name,
                r.pattern     AS matched_rule_pattern,
                r.description AS matched_rule_description
            FROM scan_logs l
            LEFT JOIN rules r ON r.id = l.matched_rule_id
            WHERE {where}
            ORDER BY l.created_at DESC
            LIMIT ${idx} OFFSET ${idx + 1}
            """,
            *params, limit, offset,
        )
        return total, _as_dicts(rows)
