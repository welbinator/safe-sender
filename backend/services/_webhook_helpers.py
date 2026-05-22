"""Pure helpers for SesWebhookService — kept out of the service module so the
class file stays focused on orchestration and the helpers are independently
testable.
"""
from __future__ import annotations

import logging
import re
from typing import Any, Optional

logger = logging.getLogger(__name__)

_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)


def extract_customer_id_tag(mail: dict[str, Any]) -> Optional[str]:
    """SES echoes message tags back under `mail.tags.<TagName>` as a list.

    Returns the UUID string iff the tag is present and well-formed; else None.
    Malformed tags are logged but downgraded to None so we still write a
    legacy (NULL customer_id) suppression row rather than dropping it.
    """
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


def emails_and_reason(
    inner: dict[str, Any],
) -> tuple[list[str], str, str, bool]:
    """Map an SES notification body to (emails, reason, detail, recognized).

    `recognized` is False for notification types we don't act on (e.g.
    Delivery), so the caller can return an 'ignored' response instead of
    silently treating it as a no-op success.
    """
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
