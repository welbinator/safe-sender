"""SES bounce/complaint webhook service.

Owns:
  - parsing SNS Notification / SubscriptionConfirmation envelopes
  - extracting + validating the customer_id tag SES echoes back
  - mapping notificationType → (emails, reason, detail)
  - upserting suppressions via SuppressionRepository

Does NOT own:
  - SNS signature verification (router calls sns_validator before us)
  - SubscribeURL fetch (router schedules it; HTTP call is router-level concern)
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from typing import Any, Optional

from repositories import SuppressionRepository

logger = logging.getLogger(__name__)

_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)


@dataclass
class ProcessResult:
    """What the router should return to SNS."""
    status: str
    suppressed: int = 0
    detail: Optional[str] = None  # human-readable extra (e.g. ignored type)


def _extract_customer_id_tag(mail: dict[str, Any]) -> Optional[str]:
    """SES echoes message tags back under `mail.tags.<TagName>` as a list.
    Returns the UUID string iff the tag is present and well-formed; else None.
    Malformed tags are logged but downgraded to None so we still write a
    legacy (NULL customer_id) suppression row rather than dropping it."""
    tags = (mail or {}).get("tags", {}) or {}
    raw_tag = tags.get("customer_id") or tags.get("customerId") or []
    if isinstance(raw_tag, list) and raw_tag:
        candidate = str(raw_tag[0]).strip() or None
    elif isinstance(raw_tag, str):
        candidate = raw_tag.strip() or None
    else:
        candidate = None
    if candidate and not _UUID_RE.match(candidate.lower()):
        logger.warning(
            "SES notification carried malformed customer_id tag",
            extra={"customer_id_tag": candidate},
        )
        return None
    return candidate


def _emails_and_reason(
    inner: dict[str, Any],
) -> tuple[list[str], str, str, bool]:
    """Return (emails, reason, detail, is_recognized_type)."""
    notification_type = inner.get("notificationType", "")
    if notification_type == "Bounce":
        bounce = inner.get("bounce", {}) or {}
        bounce_type = bounce.get("bounceType", "")
        bounce_subtype = bounce.get("bounceSubType", "")
        detail = f"{bounce_type}/{bounce_subtype}"
        emails: list[str] = []
        # Only suppress on permanent (hard) bounces — soft bounces retry.
        if bounce_type == "Permanent":
            for r in bounce.get("bouncedRecipients", []) or []:
                addr = (r or {}).get("emailAddress", "")
                if addr:
                    emails.append(addr.lower())
        return emails, "bounce", detail, True

    if notification_type == "Complaint":
        complaint = inner.get("complaint", {}) or {}
        detail = complaint.get("complaintFeedbackType", "abuse")
        emails = []
        for r in complaint.get("complainedRecipients", []) or []:
            addr = (r or {}).get("emailAddress", "")
            if addr:
                emails.append(addr.lower())
        return emails, "complaint", detail, True

    return [], "", "", False


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

        emails, reason, detail, recognized = _emails_and_reason(inner)
        if not recognized:
            return ProcessResult(
                status="ignored",
                detail=inner.get("notificationType", ""),
            )
        if not emails:
            return ProcessResult(status="ok", suppressed=0)

        customer_id_tag = _extract_customer_id_tag(inner.get("mail", {}))

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
