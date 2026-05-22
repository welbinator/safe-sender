"""Rules CRUD business logic.

The bulk of complexity is regex validation. We prefer google-re2 (linear time,
ReDoS-immune) and fall back to stdlib `re` only for dev checkouts — with a
loud warning.
"""
from __future__ import annotations

import logging
from typing import Any, Optional

from repositories.rules import RuleRepository

from .errors import InvalidRegexPattern, NotFoundError

_log = logging.getLogger(__name__)

# google-re2 — RE2 has linear-time guarantees and is immune to ReDoS.
try:
    import re2 as _regex_engine  # type: ignore

    _USING_RE2 = True
except ImportError:  # pragma: no cover - dev fallback
    import re as _regex_engine  # type: ignore

    _USING_RE2 = False
    _log.warning(
        "google-re2 not installed — falling back to stdlib `re`. "
        "Customer regexes will NOT be ReDoS-safe. Install google-re2 in prod."
    )

VALID_MATCH_TYPES = {"string", "regex"}
VALID_SCOPES = {"external", "internal", "both"}


class RuleService:
    """Business operations on the rules collection for a single customer."""

    def __init__(self, rules: RuleRepository):
        self.rules = rules

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    @staticmethod
    def assert_valid_regex(pattern: str, match_type: str) -> None:
        """Compile-check a regex pattern. No-op for string matches."""
        if match_type != "regex":
            return
        try:
            _regex_engine.compile(pattern)
        except Exception as e:
            raise InvalidRegexPattern(f"Invalid regex pattern: {e}")

    # ------------------------------------------------------------------
    # Reads
    # ------------------------------------------------------------------

    async def list_for_customer(self, customer_id: Any) -> list[dict[str, Any]]:
        return await self.rules.list_active_for_customer(customer_id)

    # ------------------------------------------------------------------
    # Writes
    # ------------------------------------------------------------------

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
        self.assert_valid_regex(pattern, match_type)
        return await self.rules.create(
            customer_id=customer_id,
            name=name,
            pattern=pattern,
            match_type=match_type,
            scope=scope,
            applies_to_email=applies_to_email,
            is_exception=is_exception,
            description=description,
        )

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
    ) -> dict[str, Any]:
        existing = await self.rules.get_for_customer(rule_id, customer_id)
        if not existing:
            raise NotFoundError("Rule not found")

        # Validate the *effective* regex — merge incoming partial against existing.
        effective_pattern = pattern if pattern is not None else existing["pattern"]
        effective_match_type = (
            match_type if match_type is not None else existing["match_type"]
        )
        self.assert_valid_regex(effective_pattern, effective_match_type)

        row = await self.rules.update(
            rule_id=rule_id,
            customer_id=customer_id,
            name=name,
            pattern=pattern,
            match_type=match_type,
            scope=scope,
            applies_to_email=applies_to_email,
            is_exception=is_exception,
            description=description,
            active=active,
        )
        if not row:
            # Race: deleted between ownership check and update.
            raise NotFoundError("Rule not found")
        return row

    async def soft_delete(self, rule_id: Any, customer_id: Any) -> None:
        """Deactivate a rule. Raises NotFoundError if it was already inactive."""
        ok = await self.rules.soft_delete(rule_id, customer_id)
        if not ok:
            raise NotFoundError("Rule not found")
