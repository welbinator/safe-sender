"""Customer table access."""
from __future__ import annotations

from typing import Any, Optional
from uuid import UUID

from .base import BaseRepository, _as_dict


class CustomerRepository(BaseRepository):
    """All reads/writes against the `customers` table."""

    # --- reads ----------------------------------------------------------

    async def get_active_by_id(self, customer_id: Any) -> Optional[dict[str, Any]]:
        row = await self.conn.fetchrow(
            "SELECT * FROM customers WHERE id = $1 AND active = true",
            customer_id,
        )
        return _as_dict(row)

    async def get_by_google_sub(self, google_sub: str) -> Optional[dict[str, Any]]:
        row = await self.conn.fetchrow(
            "SELECT id, email FROM customers WHERE google_sub = $1",
            google_sub,
        )
        return _as_dict(row)

    async def get_by_domain(self, domain: str) -> Optional[dict[str, Any]]:
        row = await self.conn.fetchrow(
            "SELECT id FROM customers WHERE domain = $1",
            domain,
        )
        return _as_dict(row)

    async def get_verification_token(self, customer_id: Any) -> Optional[str]:
        return await self.conn.fetchval(
            "SELECT domain_verification_token FROM customers WHERE id = $1",
            customer_id,
        )

    async def get_smtp_username(self, customer_id: Any) -> Optional[str]:
        return await self.conn.fetchval(
            "SELECT smtp_username FROM customers WHERE id = $1",
            customer_id,
        )

    # --- writes ---------------------------------------------------------

    async def create(
        self,
        *,
        domain: str,
        name: Optional[str],
        email: str,
        google_sub: str,
        smtp_username: str,
        smtp_password_hash: str,
    ) -> dict[str, Any]:
        row = await self.conn.fetchrow(
            """
            INSERT INTO customers
              (domain, name, email, google_sub, plan, smtp_username, smtp_password_hash)
            VALUES ($1, $2, $3, $4, 'basic', $5, $6)
            RETURNING id, email
            """,
            domain, name, email, google_sub, smtp_username, smtp_password_hash,
        )
        return dict(row)

    async def update_name(
        self, customer_id: Any, name: Optional[str]
    ) -> dict[str, Any]:
        row = await self.conn.fetchrow(
            """
            UPDATE customers
            SET name = COALESCE($1, name),
                updated_at = NOW()
            WHERE id = $2
            RETURNING *
            """,
            name, customer_id,
        )
        return dict(row)

    async def set_verification_token(
        self, customer_id: Any, token: str
    ) -> None:
        await self.conn.execute(
            "UPDATE customers SET domain_verification_token = $1 WHERE id = $2",
            token, customer_id,
        )

    async def mark_domain_verified(self, customer_id: Any) -> None:
        await self.conn.execute(
            "UPDATE customers SET domain_verified = TRUE WHERE id = $1",
            customer_id,
        )

    async def update_smtp_password_hash(
        self, customer_id: Any, password_hash: str
    ) -> Optional[dict[str, Any]]:
        row = await self.conn.fetchrow(
            """
            UPDATE customers
            SET smtp_password_hash = $1
            WHERE id = $2
            RETURNING smtp_username
            """,
            password_hash, customer_id,
        )
        return _as_dict(row)
