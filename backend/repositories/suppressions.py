"""suppressed_addresses table access."""
from __future__ import annotations

from typing import Any, Optional

from .base import BaseRepository, _as_dicts


class SuppressionRepository(BaseRepository):
    """Reads for the admin panel + writes from the SES bounce/complaint webhook.

    The unique constraint on ``suppressed_addresses`` is split between two
    partial indexes (per-customer vs legacy global NULL), so the two upsert
    paths can't share a single ON CONFLICT clause.
    """

    # --- admin reads ----------------------------------------------------

    async def list_recent(self, limit: int = 500) -> list[dict[str, Any]]:
        rows = await self.conn.fetch(
            """
            SELECT email, reason, detail, suppressed_at
            FROM suppressed_addresses
            ORDER BY suppressed_at DESC
            LIMIT $1
            """,
            limit,
        )
        return _as_dicts(rows)

    async def delete_by_email(self, email: str) -> int:
        """Remove all suppression rows for ``email``. Returns rowcount."""
        result = await self.conn.execute(
            "DELETE FROM suppressed_addresses WHERE email = $1",
            email.lower(),
        )
        # asyncpg returns "DELETE n"
        try:
            return int(result.split()[-1])
        except (ValueError, IndexError):
            return 0

    # --- webhook writes -------------------------------------------------

    async def upsert_for_customer(
        self, *, email: str, reason: str, detail: str, customer_id: str
    ) -> None:
        await self.conn.execute(
            """
            INSERT INTO suppressed_addresses (email, reason, detail, customer_id)
            VALUES ($1, $2, $3, $4::uuid)
            ON CONFLICT (customer_id, email) WHERE customer_id IS NOT NULL
            DO UPDATE SET reason = EXCLUDED.reason,
                          detail = EXCLUDED.detail,
                          suppressed_at = NOW()
            """,
            email, reason, detail, customer_id,
        )

    async def upsert_global(
        self, *, email: str, reason: str, detail: str
    ) -> None:
        await self.conn.execute(
            """
            INSERT INTO suppressed_addresses (email, reason, detail, customer_id)
            VALUES ($1, $2, $3, NULL)
            ON CONFLICT (email) WHERE customer_id IS NULL
            DO UPDATE SET reason = EXCLUDED.reason,
                          detail = EXCLUDED.detail,
                          suppressed_at = NOW()
            """,
            email, reason, detail,
        )
