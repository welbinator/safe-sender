"""Pure helpers for MailgunWebhookService — maps Mailgun event payloads to
(emails, reason, detail, recognized) tuples and extracts customer_id tags.

Mailgun event schema reference:
  - Bounce:    event="failed", severity="permanent"
  - Complaint: event="complained"
  - Tags:      user-variables object keyed by tag name (set via X-Mailgun-Tag header)

UUID regex used for customer_id validation (same as SNS era).
"""
from __future__ import annotations

import logging
import re
from typing import Any, Optional

logger = logging.getLogger(__name__)

_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)


def extract_customer_id_tag(event_data: dict[str, Any]) -> Optional[str]:
    """Extract customer_id from Mailgun user-variables.

    Mailgun echoes X-Mailgun-Tag as the key in the top-level
    `user-variables` dict of the event data object.

    Returns the UUID string iff present and well-formed; else None.
    Malformed tags are logged but downgraded to None so we still write a
    legacy (NULL customer_id) suppression row rather than dropping it.
    """
    user_vars = (event_data or {}).get("user-variables") or {}
    candidate = user_vars.get("customer_id") or user_vars.get("customerId")
    if not candidate:
        return None
    candidate = str(candidate).strip() or None
    if candidate and not _UUID_RE.match(candidate.lower()):
        logger.warning(
            "Mailgun event carried malformed customer_id tag",
            extra={"customer_id_tag": candidate},
        )
        return None
    return candidate


def emails_and_reason(
    event_data: dict[str, Any],
) -> tuple[list[str], str, str, bool]:
    """Map a Mailgun event data object to (emails, reason, detail, recognized).

    `recognized` is False for event types we don't act on (e.g. delivered,
    opened), so the caller can return an 'ignored' response.

    Mailgun event types we handle:
      - "failed" + severity "permanent"  → hard bounce → suppress
      - "complained"                      → spam complaint → suppress
    """
    event_type = (event_data or {}).get("event", "")

    if event_type == "failed":
        severity = (event_data or {}).get("severity", "")
        if severity != "permanent":
            # Temporary failures — don't suppress, just ignore
            return [], "", f"failed/{severity}", False
        recipient = (event_data or {}).get("recipient", "")
        delivery_status = (event_data or {}).get("delivery-status") or {}
        detail = delivery_status.get("description") or delivery_status.get("message") or "permanent"
        emails = [recipient.lower()] if recipient else []
        return emails, "bounce", detail, True

    if event_type == "complained":
        recipient = (event_data or {}).get("recipient", "")
        emails = [recipient.lower()] if recipient else []
        return emails, "complaint", "abuse", True

    return [], "", "", False
