"""Mailgun bounce/complaint webhook service.

Owns:
  - parsing Mailgun webhook event payloads
  - mapping event type → suppression rows via helpers in `_webhook_helpers.py`
  - upserting suppressions via SuppressionRepository

Does NOT own:
  - HMAC signature verification (router calls mailgun_validator before us)
  - HTTP request parsing (router layer)
  - tag extraction / event→email mapping (see services/_webhook_helpers.py)
"""
from __future__ import annotations

import logging
from typing import Any, Optional

from pydantic import BaseModel

from repositories import SuppressionRepository
from services._webhook_helpers import emails_and_reason, extract_customer_id_tag

logger = logging.getLogger(__name__)


class ProcessResult(BaseModel):
    """What the router should return to Mailgun.

    status: "ok" | "ignored" | "error"
    suppressed: number of addresses suppressed
    detail: human-readable extra info (e.g. ignored event type)
    """
    status: str
    suppressed: int = 0
    detail: Optional[str] = None


class MailgunWebhookService:
    __slots__ = ("suppressions",)

    def __init__(self, suppressions: SuppressionRepository) -> None:
        self.suppressions = suppressions

    async def process_event(self, event_data: dict[str, Any]) -> ProcessResult:
        """Handle an already-signature-verified Mailgun event data object.

        Returns ProcessResult describing what was done so the router can shape
        the JSON response.
        """
        emails, reason, detail, recognized = emails_and_reason(event_data)
        if not recognized:
            return ProcessResult(
                status="ignored",
                detail=event_data.get("event", ""),
            )
        if not emails:
            return ProcessResult(status="ok", suppressed=0)

        customer_id_tag = extract_customer_id_tag(event_data)

        suppressed = 0
        for email in emails:
            try:
                if customer_id_tag:
                    await self.suppressions.upsert_for_customer(
                        email=email,
                        reason=reason,
                        detail=detail,
                        customer_id=customer_id_tag,
                    )
                else:
                    await self.suppressions.upsert_global(
                        email=email, reason=reason, detail=detail,
                    )
                suppressed += 1
                logger.info(
                    "Address suppressed",
                    extra={
                        "email": email,
                        "reason": reason,
                        "detail": detail,
                        "customer_id": customer_id_tag,
                    },
                )
            except Exception as exc:
                logger.error(
                    "Failed to suppress address",
                    extra={"email": email, "error": str(exc)},
                )
        return ProcessResult(status="ok", suppressed=suppressed)
