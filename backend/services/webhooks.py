"""SES bounce/complaint webhook service.

Owns:
  - parsing SNS Notification / SubscriptionConfirmation envelopes
  - mapping notificationType → suppression rows via the helpers in
    `_webhook_helpers.py`
  - upserting suppressions via SuppressionRepository

Does NOT own:
  - SNS signature verification (router calls sns_validator before us)
  - SubscribeURL fetch (router schedules it; HTTP call is router-level concern)
  - SES tag extraction / type→email mapping (see services/_webhook_helpers.py)
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any, Optional

from repositories import SuppressionRepository
from services._webhook_helpers import emails_and_reason, extract_customer_id_tag

logger = logging.getLogger(__name__)


@dataclass
class ProcessResult:
    """What the router should return to SNS."""
    status: str
    suppressed: int = 0
    detail: Optional[str] = None  # human-readable extra (e.g. ignored type)


class SesWebhookService:
    __slots__ = ("suppressions",)

    def __init__(self, suppressions: SuppressionRepository) -> None:
        self.suppressions = suppressions

    async def process_notification(self, outer: dict[str, Any]) -> ProcessResult:
        """Handle an already-signature-verified SNS Notification envelope.

        Returns ProcessResult describing what was done so the router can shape
        the JSON response. Raises ValueError when the inner Message is not
        valid JSON — the router maps that to 400.
        """
        try:
            inner = json.loads(outer.get("Message", "{}"))
        except json.JSONDecodeError as exc:
            raise ValueError("Invalid inner message JSON") from exc

        emails, reason, detail, recognized = emails_and_reason(inner)
        if not recognized:
            return ProcessResult(
                status="ignored",
                detail=inner.get("notificationType", ""),
            )
        if not emails:
            return ProcessResult(status="ok", suppressed=0)

        customer_id_tag = extract_customer_id_tag(inner.get("mail", {}))

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
