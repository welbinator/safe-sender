"""Rule (customer keyword/regex) table access."""
from __future__ import annotations

from typing import Any, Optional

from .base import BaseRepository, _as_dict, _as_dicts


# F-32 — Columns returned by all rule list/CRUD endpoints. Held as a
# *tuple of identifiers* (not a free-form string) so we never grow toward
# the "interpolate user input into SELECT" shape. `_RULE_COLS_SQL` is the
# only thing we ever embed in an f-string; it is built from a frozen
# literal list at import time and validated to contain only ASCII
# identifiers + commas. Adding a column means editing the tuple here —
# you can't accidentally inject a fragment from anywhere else.
_RULE_COLUMNS: tuple[str, ...] = (
    "id",
    "customer_id",
    "name",
    "pattern",
    "match_type",
    "scope",
    "applies_to_email",
    "is_exception",
    "active",
    "description",
)


def _validate_identifiers(cols: tuple[str, ...]) -> None:
    """Belt-and-suspenders guard: every column name must be a bare ASCII
    identifier. Prevents a future maintainer from sneaking a SQL fragment
    (`name AS foo`, `(SELECT ...)`) into the tuple."""
    import re as _re
    _IDENT = _re.compile(r"^[a-z_][a-z0-9_]*$")
    for c in cols:
        if not _IDENT.match(c):
            raise AssertionError(f"_RULE_COLUMNS contains non-identifier: {c!r}")


_validate_identifiers(_RULE_COLUMNS)
_RULE_COLS_SQL: str = ", ".join(_RULE_COLUMNS)


class RuleRepository(BaseRepository):
    """All reads/writes against the `rules` table."""

    # --- reads ----------------------------------------------------------

    async def list_active_for_customer(
        self, customer_id: Any
    ) -> list[dict[str, Any]]:
        rows = await self.conn.fetch(
            f"""
            SELECT {_RULE_COLS_SQL}
            FROM rules
            WHERE customer_id = $1 AND active = TRUE
            ORDER BY created_at ASC
            """,
            customer_id,
        )
        return _as_dicts(rows)

    async def get_for_customer(
        self, rule_id: Any, customer_id: Any
    ) -> Optional[dict[str, Any]]:
        """Tenant-scoped fetch — used to verify ownership before update.

        Returns the *full* row (including timestamps) so callers can
        merge updates against the existing values.
        """
        row = await self.conn.fetchrow(
            "SELECT * FROM rules WHERE id = $1 AND customer_id = $2",
            rule_id, customer_id,
        )
        return _as_dict(row)

    async def count_active_for_customer(self, customer_id: Any) -> int:
        """F-52 — used to enforce the per-customer active-rule cap."""
        return await self.conn.fetchval(
            "SELECT COUNT(*) FROM rules WHERE customer_id = $1 AND active = TRUE",
            customer_id,
        ) or 0

    # --- writes ---------------------------------------------------------

    async def create(
        self,
        *,
        customer_id: Any,
        name: Optional[str],
        pattern: str,
        match_type: str,
        scope: str,
        applies_to_email: Optional[str],
        is_exception: bool,
        description: Optional[str],
    ) -> dict[str, Any]:
        row = await self.conn.fetchrow(
            f"""
            INSERT INTO rules
                (customer_id, name, pattern, match_type, scope,
                 applies_to_email, is_exception, description)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING {_RULE_COLS_SQL}
            """,
            customer_id, name, pattern, match_type, scope,
            applies_to_email, is_exception, description,
        )
        return dict(row)

    async def update(
        self,
        *,
        rule_id: Any,
        customer_id: Any,
        name: Optional[str],
        pattern: Optional[str],
        match_type: Optional[str],
        scope: Optional[str],
        applies_to_email: Optional[str],
        is_exception: Optional[bool],
        description: Optional[str],
        active: Optional[bool],
    ) -> Optional[dict[str, Any]]:
        row = await self.conn.fetchrow(
            f"""
            UPDATE rules SET
                name             = COALESCE($1, name),
                pattern          = COALESCE($2, pattern),
                match_type       = COALESCE($3, match_type),
                scope            = COALESCE($4, scope),
                applies_to_email = COALESCE($5, applies_to_email),
                is_exception     = COALESCE($6, is_exception),
                description      = COALESCE($7, description),
                active           = COALESCE($8, active),
                updated_at       = NOW()
            WHERE id = $9 AND customer_id = $10
            RETURNING {_RULE_COLS_SQL}
            """,
            name, pattern, match_type, scope, applies_to_email,
            is_exception, description, active, rule_id, customer_id,
        )
        return _as_dict(row)

    async def soft_delete(self, rule_id: Any, customer_id: Any) -> bool:
        """Deactivate a rule. Returns True iff a row was flipped."""
        result = await self.conn.execute(
            """
            UPDATE rules
               SET active = FALSE,
                   updated_at = NOW()
             WHERE id = $1 AND customer_id = $2 AND active = TRUE
            """,
            rule_id, customer_id,
        )
        # asyncpg returns "UPDATE n"
        return result != "UPDATE 0"
