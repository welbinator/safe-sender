"""
SES bounce/complaint webhook handler — Sprint 6.

AWS SES sends notifications via SNS to POST /webhooks/ses.
We handle:
  - SubscriptionConfirmation: auto-confirm the SNS subscription
  - Notification: parse bounce/complaint, add to suppressed_addresses

Setup:
  1. Create SNS topic in AWS console
  2. Add subscription: HTTPS → https://app.sendersafety.com/api/webhooks/ses
  3. In SES → Configuration sets (or identity notifications): point bounce + complaint
     notifications to that SNS topic
  4. AWS will POST SubscriptionConfirmation first — this handler auto-confirms it
"""

import json
import logging

import aiohttp
from fastapi import APIRouter, HTTPException, Request

from main import get_pool  # reuse pool from main

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/webhooks", tags=["webhooks"])


async def _confirm_subscription(subscribe_url: str) -> None:
    """GET the SubscribeURL to confirm the SNS subscription."""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(subscribe_url) as resp:
                logger.info(
                    "SNS subscription confirmed",
                    extra={"status": resp.status, "url": subscribe_url[:80]},
                )
    except Exception as exc:
        logger.error("SNS subscription confirm failed", extra={"error": str(exc)})


@router.post("/ses")
async def ses_webhook(request: Request):
    """
    Receive SES bounce/complaint notifications from SNS.
    """
    body_bytes = await request.body()
    try:
        outer = json.loads(body_bytes)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    msg_type = outer.get("Type", "")

    # --- Auto-confirm SNS subscription ---
    if msg_type == "SubscriptionConfirmation":
        subscribe_url = outer.get("SubscribeURL", "")
        if subscribe_url:
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

    # --- Write to suppressed_addresses ---
    pool = get_pool()
    suppressed = 0
    async with pool.acquire() as conn:
        for email in emails:
            try:
                await conn.execute(
                    """
                    INSERT INTO suppressed_addresses (email, reason, detail)
                    VALUES ($1, $2, $3)
                    ON CONFLICT (email) DO UPDATE SET reason = EXCLUDED.reason,
                        detail = EXCLUDED.detail, suppressed_at = NOW()
                    """,
                    email,
                    reason,
                    detail,
                )
                suppressed += 1
                logger.info(
                    "Address suppressed",
                    extra={"email": email, "reason": reason, "detail": detail},
                )
            except Exception as exc:
                logger.error(
                    "Failed to suppress address",
                    extra={"email": email, "error": str(exc)},
                )

    return {"status": "ok", "suppressed": suppressed}
