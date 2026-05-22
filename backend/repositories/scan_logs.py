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

    async def today_stats(
        self,
        *,
        customer_id: Any,
        tz_offset_minutes: int = 0,
    ) -> dict[str, Any]:
        """Server-side aggregation for the dashboard Overview card.

        F-39: previously the dashboard pulled `/logs?limit=500` and tallied
        client-side, capping accurate stats at 500 rows/day. This computes
        scanned/blocked/allowed + top-5 rules in SQL.

        F-56: `tz_offset_minutes` is the client's `Date.getTimezoneOffset()`
        — minutes WEST of UTC, positive in the Americas. We bracket the
        client's local "today" in UTC so users east of UTC don't see
        yesterday's evening scans bleed into today.
        """
        # Convert JS offset (minutes west of UTC, positive in Americas) to a
        # signed-minute shift we can add to UTC to get the client's wall
        # clock. JS: PDT = +420, so client_now = utc_now - 420min.
        # We treat "today" as [client_midnight_today, client_midnight_tomorrow)
        # then convert that window back to UTC for the query.
        async with self.conn.transaction():
            counts_row = await self.conn.fetchrow(
                """
                WITH bounds AS (
                    SELECT
                        date_trunc(
                            'day',
                            (now() AT TIME ZONE 'UTC')
                                - make_interval(mins => $2)
                        ) + make_interval(mins => $2) AS day_start
                ),
                day_window AS (
                    SELECT
                        day_start AS lo,
                        day_start + interval '1 day' AS hi
                    FROM bounds
                )
                SELECT
                    COUNT(*) FILTER (WHERE TRUE)                  AS scanned,
                    COUNT(*) FILTER (WHERE outcome = 'blocked')   AS blocked,
                    COUNT(*) FILTER (WHERE outcome = 'allowed')   AS allowed
                FROM scan_logs, day_window
                WHERE customer_id = $1
                  AND created_at >= day_window.lo
                  AND created_at <  day_window.hi
                """,
                customer_id, tz_offset_minutes,
            )
            top_rows = await self.conn.fetch(
                """
                WITH bounds AS (
                    SELECT
                        date_trunc(
                            'day',
                            (now() AT TIME ZONE 'UTC')
                                - make_interval(mins => $2)
                        ) + make_interval(mins => $2) AS day_start
                ),
                day_window AS (
                    SELECT
                        day_start AS lo,
                        day_start + interval '1 day' AS hi
                    FROM bounds
                )
                SELECT
                    l.matched_rule_id,
                    COALESCE(r.name, r.pattern, '(deleted rule)') AS label,
                    COUNT(*) AS triggers
                FROM scan_logs l
                LEFT JOIN rules r ON r.id = l.matched_rule_id
                CROSS JOIN day_window
                WHERE l.customer_id = $1
                  AND l.matched_rule_id IS NOT NULL
                  AND l.created_at >= day_window.lo
                  AND l.created_at <  day_window.hi
                GROUP BY l.matched_rule_id, label
                ORDER BY triggers DESC
                LIMIT 5
                """,
                customer_id, tz_offset_minutes,
            )
        return {
            "scanned": int(counts_row["scanned"] or 0),
            "blocked": int(counts_row["blocked"] or 0),
            "allowed": int(counts_row["allowed"] or 0),
            "top_rules": [
                {"label": r["label"], "triggers": int(r["triggers"])}
                for r in top_rows
            ],
        }
