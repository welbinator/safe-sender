"""
GET /logs — paginated scan logs for the authenticated customer.
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
    matched_rule_name: Optional[str]
    matched_rule_pattern: Optional[str]
    matched_rule_description: Optional[str]
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
    filters = ["l.customer_id = $1"]
    params: list = [customer["id"]]
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

    async with pool.acquire() as conn:
        total: int = await conn.fetchval(
            f"SELECT COUNT(*) FROM scan_logs l WHERE {where}", *params
        )
        rows = await conn.fetch(
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
                matched_rule_name=r["matched_rule_name"],
                matched_rule_pattern=r["matched_rule_pattern"],
                matched_rule_description=r["matched_rule_description"],
                created_at=r["created_at"],
            )
            for r in rows
        ],
    )
