"""Postgres-backed sliding-window rate limiter for the admin panel (F-19).

The previous in-process limiter on ``routers.admin`` was reset on every
container restart and useless under multi-replica scale-out. We use a
fixed one-minute window keyed by (ip, window_start) with an atomic
``INSERT … ON CONFLICT DO UPDATE … RETURNING request_count`` so a single
roundtrip both increments the counter and returns the new value.

This is intentionally not a leaky-bucket. Fixed windows have an edge
case (a client can burst 2x the limit straddling a window boundary)
that's acceptable for an admin panel guarding low-QPS endpoints.
"""
from __future__ import annotations

from datetime import datetime, timezone

from .base import BaseRepository


class AdminRateLimitRepository(BaseRepository):
    """One-minute fixed-window rate limiter."""

    async def hit(self, ip: str, limit_per_minute: int) -> bool:
        """Record one request from ``ip``; return ``True`` if under limit.

        The window key is the current minute, truncated to second-zero.
        A single UPSERT returns the post-increment count, which we
        compare against ``limit_per_minute``.
        """
        now = datetime.now(timezone.utc).replace(second=0, microsecond=0)
        count = await self.conn.fetchval(
            """
            INSERT INTO admin_rate_limit (ip, window_start, request_count)
            VALUES ($1, $2, 1)
            ON CONFLICT (ip, window_start) DO UPDATE
                SET request_count = admin_rate_limit.request_count + 1
            RETURNING request_count
            """,
            ip, now,
        )
        return count <= limit_per_minute

    async def purge_expired(self, older_than_minutes: int = 10) -> None:
        """Best-effort cleanup of windows older than ``older_than_minutes``.

        Called opportunistically; the table is keyed on (ip, window_start)
        so it cannot grow unbounded for a single attacker — but distinct
        IPs over weeks will. Keep it small.
        """
        await self.conn.execute(
            """
            DELETE FROM admin_rate_limit
            WHERE window_start < NOW() - ($1 || ' minutes')::interval
            """,
            str(older_than_minutes),
        )
