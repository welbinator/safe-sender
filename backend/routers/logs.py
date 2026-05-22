"""
GET /logs — paginated scan logs for the authenticated customer.

Thin router: parses query params, delegates to LogService, shapes response.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, List, Optional

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel

from deps import get_current_customer, get_log_service, rate_limit_read
from services import LogService

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


@router.get("", response_model=LogsResponse, dependencies=[Depends(rate_limit_read)])
async def list_logs(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    outcome: Optional[str] = Query(default=None, pattern="^(allowed|blocked)$"),
    sender: Optional[str] = None,
    date_from: Optional[datetime] = None,
    date_to: Optional[datetime] = None,
    customer: dict[str, Any] = Depends(get_current_customer),
    logs: LogService = Depends(get_log_service),
):
    page_data = await logs.search(
        customer_id=customer["id"],
        page=page,
        page_size=page_size,
        outcome=outcome,
        sender=sender,
        date_from=date_from,
        date_to=date_to,
    )
    return LogsResponse(
        total=page_data.total,
        page=page_data.page,
        page_size=page_data.page_size,
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
            for r in page_data.results
        ],
    )


class TopRuleStat(BaseModel):
    label: str
    triggers: int


class TodayStatsResponse(BaseModel):
    scanned: int
    blocked: int
    allowed: int
    block_rate: float
    top_rules: List[TopRuleStat]


@router.get("/stats/today", response_model=TodayStatsResponse, dependencies=[Depends(rate_limit_read)])
async def stats_today(
    # JS `Date.getTimezoneOffset()` — minutes WEST of UTC. Out-of-range
    # values are clamped (not rejected) so a misbehaving client can't 422
    # the dashboard out of its overview card.
    tz_offset_minutes: int = Query(default=0),
    customer: dict[str, Any] = Depends(get_current_customer),
    logs: LogService = Depends(get_log_service),
):
    clamped = max(-840, min(840, tz_offset_minutes))
    stats = await logs.today_stats(
        customer_id=customer["id"],
        tz_offset_minutes=clamped,
    )
    scanned = int(stats.get("scanned", 0))
    blocked = int(stats.get("blocked", 0))
    return TodayStatsResponse(
        scanned=scanned,
        blocked=blocked,
        allowed=int(stats.get("allowed", 0)),
        block_rate=round(blocked / scanned, 4) if scanned else 0.0,
        top_rules=[
            TopRuleStat(label=r["label"], triggers=int(r["triggers"]))
            for r in stats.get("top_rules", [])
        ],
    )
