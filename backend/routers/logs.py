"""
GET /logs — paginated scan logs for the authenticated customer.

Query params:
  - page (int, default 1)
  - page_size (int, default 50, max 200)
  - outcome (str: "allowed" | "blocked")
  - sender (str: filter by sender substring)
  - date_from (ISO date string)
  - date_to (ISO date string)
"""
from datetime import datetime
from typing import Any, List, Optional

import asyncpg
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel

from deps import get_current_customer, get_pool

router = APIRouter(prefix="/logs", tags=["logs"])


class LogEntry(BaseModel):
    id: str
    sender: str
    recipient: str
    outcome: str
    matched_rule_id: Optional[str]
    created_at: datetime


class LogsResponse(BaseModel):
    total: int
    page: int
    page_size: int
    results: List[LogEntry]


@router.get("", response_model=LogsResponse)
async def list_logs(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    outcome: Optional[str] = Query(default=None, pattern="^(allowed|blocked)$"),
    sender: Optional[str] = None,
    date_from: Optional[datetime] = None,
    date_to: Optional[datetime] = None,
    customer: dict[str, Any] = Depends(get_current_customer),
    pool: asyncpg.Pool = Depends(get_pool),
):
    offset = (page - 1) * page_size
    filters = ["customer_id = $1"]
    params: list = [customer["id"]]
    idx = 2

    if outcome:
        filters.append(f"outcome = ${idx}")
        params.append(outcome)
        idx += 1

    if sender:
        filters.append(f"sender ILIKE ${idx}")
        params.append(f"%{sender}%")
        idx += 1

    if date_from:
        filters.append(f"created_at >= ${idx}")
        params.append(date_from)
        idx += 1

    if date_to:
        filters.append(f"created_at <= ${idx}")
        params.append(date_to)
        idx += 1

    where = " AND ".join(filters)

    async with pool.acquire() as conn:
        total: int = await conn.fetchval(
            f"SELECT COUNT(*) FROM scan_logs WHERE {where}", *params
        )
        rows = await conn.fetch(
            f"""
            SELECT id, sender, recipient, outcome, matched_rule_id, created_at
            FROM scan_logs
            WHERE {where}
            ORDER BY created_at DESC
            LIMIT ${idx} OFFSET ${idx + 1}
            """,
            *params,
            page_size,
            offset,
        )

    return LogsResponse(
        total=total,
        page=page,
        page_size=page_size,
        results=[
            LogEntry(
                id=str(r["id"]),
                sender=r["sender"],
                recipient=r["recipient"],
                outcome=r["outcome"],
                matched_rule_id=str(r["matched_rule_id"]) if r["matched_rule_id"] else None,
                created_at=r["created_at"],
            )
            for r in rows
        ],
    )
