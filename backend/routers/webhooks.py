"""
SES bounce/complaint webhook handler — Sprint 6.

AWS SES sends notifications via SNS to POST /webhooks/ses.
We handle:
  - SubscriptionConfirmation: validate URL host + signature, then auto-confirm
  - Notification: validate signature + TopicArn, parse bounce/complaint, suppress

Security (Sprint A):
  - SNS signature verified via x509 cert from sns.*.amazonaws.com (HTTPS only).
  - TopicArn must be in SNS_ALLOWED_TOPIC_ARNS env (comma-separated).
  - SubscribeURL must be https and host must match the SNS allowlist regex.
"""

import json
import logging
import os

import aiohttp
from fastapi import APIRouter, HTTPException, Request

from main import get_pool  # reuse pool from main
from sns_validator import (
    SNSValidationError,
    validate_subscribe_url,
    verify_sns_message,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/webhooks", tags=["webhooks"])

# Operator must list the SNS TopicArns we accept. Empty = reject everything,
# which is the safe default; misconfiguration is loud, not silent.
_ALLOWED_TOPIC_ARNS = [
    t.strip() for t in os.environ.get("SNS_ALLOWED_TOPIC_ARNS", "").split(",") if t.strip()
]


async def _confirm_subscription(subscribe_url: str) -> None:
    """GET the SubscribeURL to confirm the SNS subscription (host pre-validated)."""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(subscribe_url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                logger.info(
                    "SNS subscription confirmed",
                    extra={"status": resp.status, "host": subscribe_url.split("/")[2]},
                )
    except Exception as exc:
        logger.error("SNS subscription confirm failed", extra={"error": str(exc)})


@router.post("/ses")
async def ses_webhook(request: Request):
    """Receive SES bounce/complaint notifications from SNS."""
    body_bytes = await request.body()
    try:
        outer = json.loads(body_bytes)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    msg_type = outer.get("Type", "")

    # --- Signature + TopicArn check (applies to all real SNS messages) -------
    try:
        verify_sns_message(outer, _ALLOWED_TOPIC_ARNS)
    except SNSValidationError as exc:
        logger.warning(
            "SNS message rejected",
            extra={"reason": str(exc), "type": msg_type, "topic_arn": outer.get("TopicArn", "")},
        )
        raise HTTPException(status_code=403, detail="SNS validation failed")

    # --- Auto-confirm SNS subscription ---
    if msg_type == "SubscriptionConfirmation":
        subscribe_url = outer.get("SubscribeURL", "")
        try:
            validate_subscribe_url(subscribe_url)
        except SNSValidationError as exc:
            logger.warning("SubscribeURL rejected", extra={"reason": str(exc)})
            raise HTTPException(status_code=403, detail="SubscribeURL invalid")
        import asyncio
        asyncio.create_task(_confirm_subscription(subscribe_url))
        return {"status": "confirming"}

    if msg_type != "Notification":
        return {"status": "ignored"}

    # --- Parse the inner SES notification ---
    try:
        inner = json.loads(outer.get("Message", "{}"))
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid inner message JSON")

    notification_type = inner.get("notificationType", "")

    emails: list[str] = []
    reason = "bounce"
    detail = ""

    # Sprint B C16: pull the customer_id tag we attach in smtp/main.py when
    # calling SES SendRawEmail. SES echoes tags back on bounce/complaint
    # notifications under `mail.tags.<TagName>` as a list of strings.
    mail = inner.get("mail", {}) or {}
    tags = mail.get("tags", {}) or {}
    raw_tag = tags.get("customer_id") or tags.get("customerId") or []
    if isinstance(raw_tag, list) and raw_tag:
        customer_id_tag = str(raw_tag[0]).strip() or None
    elif isinstance(raw_tag, str):
        customer_id_tag = raw_tag.strip() or None
    else:
        customer_id_tag = None

    # Validate it actually looks like a UUID before we hand it to asyncpg.
    # A malformed tag should not poison the suppression table — fall through
    # to a legacy (NULL customer_id) row and alert in logs.
    import re as _re_uuid
    _UUID_RE = _re_uuid.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
    if customer_id_tag and not _UUID_RE.match(customer_id_tag.lower()):
        logger.warning(
            "SES notification carried malformed customer_id tag",
            extra={"customer_id_tag": customer_id_tag},
        )
        customer_id_tag = None

    if notification_type == "Bounce":
        bounce = inner.get("bounce", {})
        bounce_type = bounce.get("bounceType", "")
        bounce_subtype = bounce.get("bounceSubType", "")
        detail = f"{bounce_type}/{bounce_subtype}"
        # Only suppress on permanent (hard) bounces
        if bounce_type == "Permanent":
            for r in bounce.get("bouncedRecipients", []):
                addr = r.get("emailAddress", "")
                if addr:
                    emails.append(addr.lower())
        reason = "bounce"

    elif notification_type == "Complaint":
        complaint = inner.get("complaint", {})
        detail = complaint.get("complaintFeedbackType", "abuse")
        for r in complaint.get("complainedRecipients", []):
            addr = r.get("emailAddress", "")
            if addr:
                emails.append(addr.lower())
        reason = "complaint"

    else:
        return {"status": "ignored", "type": notification_type}

    if not emails:
        return {"status": "ok", "suppressed": 0}

    # --- Write to suppressed_addresses (scoped per-customer when tag present) ---
    # We can't use a single ON CONFLICT here because the unique constraint
    # is split between two partial indexes (per-customer vs legacy NULL).
    # Do an explicit upsert keyed on (customer_id, email).
    pool = get_pool()
    suppressed = 0
    async with pool.acquire() as conn:
        for email in emails:
            try:
                if customer_id_tag:
                    await conn.execute(
                        """
                        INSERT INTO suppressed_addresses (email, reason, detail, customer_id)
                        VALUES ($1, $2, $3, $4::uuid)
                        ON CONFLICT (customer_id, email) WHERE customer_id IS NOT NULL
                        DO UPDATE SET reason = EXCLUDED.reason,
                                      detail = EXCLUDED.detail,
                                      suppressed_at = NOW()
                        """,
                        email,
                        reason,
                        detail,
                        customer_id_tag,
                    )
                else:
                    # Legacy / untagged path — global suppression row.
                    await conn.execute(
                        """
                        INSERT INTO suppressed_addresses (email, reason, detail, customer_id)
                        VALUES ($1, $2, $3, NULL)
                        ON CONFLICT (email) WHERE customer_id IS NULL
                        DO UPDATE SET reason = EXCLUDED.reason,
                                      detail = EXCLUDED.detail,
                                      suppressed_at = NOW()
                        """,
                        email,
                        reason,
                        detail,
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

    return {"status": "ok", "suppressed": suppressed}
