"""
GET /internal/suppressed/{customer_id}/{email} — per-tenant suppression check.

Extracted from main.py (#22 audit refactor).
"""
from __future__ import annotations

import os

from fastapi import APIRouter, Depends, HTTPException

from db import get_pool
from internal_auth import require_internal_secret

router = APIRouter()


@router.get(
    "/internal/suppressed/{customer_id}/{email}",
    dependencies=[Depends(require_internal_secret)],
)
async def check_suppressed(customer_id: str, email: str):
    """Returns 200 if address is suppressed for this customer, 404 if not.

    M-6: Default is strict per-tenant scoping (SUPPRESSION_LEGACY_NULL=0).
    Set SUPPRESSION_LEGACY_NULL=1 only during backfill windows when legacy
    NULL-customer_id rows must still be treated as global suppressions.
    """
    pool = get_pool()
    addr = email.lower().strip()
    include_legacy = os.environ.get("SUPPRESSION_LEGACY_NULL", "0") == "1"
    async with pool.acquire() as conn:
        if include_legacy:
            row = await conn.fetchrow(
                """
                SELECT email FROM suppressed_addresses
                WHERE email = $1
                  AND (customer_id = $2::uuid OR customer_id IS NULL)
                LIMIT 1
                """,
                addr,
                customer_id,
            )
        else:
            row = await conn.fetchrow(
                """
                SELECT email FROM suppressed_addresses
                WHERE email = $1
                  AND customer_id = $2::uuid
                LIMIT 1
                """,
                addr,
                customer_id,
            )
    if row:
        return {"suppressed": True}
    raise HTTPException(status_code=404, detail="Not suppressed")
