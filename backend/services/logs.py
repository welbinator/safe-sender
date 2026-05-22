"""Scan-log read service — paginated, filtered search."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Optional

from repositories import ScanLogRepository


@dataclass
class LogPage:
    total: int
    page: int
    page_size: int
    results: list[dict[str, Any]]


class LogService:
    __slots__ = ("scan_logs",)

    def __init__(self, scan_logs: ScanLogRepository) -> None:
        self.scan_logs = scan_logs

    async def search(
        self,
        *,
        customer_id: Any,
        page: int,
        page_size: int,
        outcome: Optional[str] = None,
        sender: Optional[str] = None,
        date_from: Optional[datetime] = None,
        date_to: Optional[datetime] = None,
    ) -> LogPage:
        offset = (page - 1) * page_size
        total, rows = await self.scan_logs.search(
            customer_id=customer_id,
            outcome=outcome,
            sender=sender,
            date_from=date_from,
            date_to=date_to,
            limit=page_size,
            offset=offset,
        )
        return LogPage(total=total, page=page, page_size=page_size, results=rows)

    async def today_stats(
        self,
        *,
        customer_id: Any,
        tz_offset_minutes: int = 0,
    ) -> dict[str, Any]:
        """F-39: server-side aggregation for the Overview card."""
        return await self.scan_logs.today_stats(
            customer_id=customer_id,
            tz_offset_minutes=tz_offset_minutes,
        )
