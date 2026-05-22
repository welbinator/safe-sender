"""
SES bounce/complaint webhook handler — Sprint 6.

AWS SES sends notifications via SNS to POST /webhooks/ses.
We handle:
  - SubscriptionConfirmation: validate URL host + signature, then auto-confirm
  - Notification: validate signature + TopicArn, hand off to SesWebhookService

Security (Sprint A):
  - SNS signature verified via x509 cert from sns.*.amazonaws.com (HTTPS only).
  - TopicArn must be in SNS_ALLOWED_TOPIC_ARNS env (comma-separated).
  - SubscribeURL must be https and host must match the SNS allowlist regex.

Sprint C1 t7: notification parsing + suppression upsert moved to
SesWebhookService. Router keeps the SNS protocol/security layer.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os

import aiohttp
from fastapi import APIRouter, Depends, HTTPException, Request

from deps import get_webhook_service
from services.webhooks import SesWebhookService
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
            async with session.get(
                subscribe_url, timeout=aiohttp.ClientTimeout(total=10)
            ) as resp:
                logger.info(
                    "SNS subscription confirmed",
                    extra={"status": resp.status, "host": subscribe_url.split("/")[2]},
                )
    except Exception as exc:
        logger.error("SNS subscription confirm failed", extra={"error": str(exc)})


@router.post("/ses")
async def ses_webhook(
    request: Request,
    webhook: SesWebhookService = Depends(get_webhook_service),
):
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
            extra={
                "reason": str(exc),
                "type": msg_type,
                "topic_arn": outer.get("TopicArn", ""),
            },
        )
        raise HTTPException(status_code=403, detail="SNS validation failed")

    # --- Auto-confirm SNS subscription ---------------------------------------
    if msg_type == "SubscriptionConfirmation":
        subscribe_url = outer.get("SubscribeURL", "")
        try:
            validate_subscribe_url(subscribe_url)
        except SNSValidationError as exc:
            logger.warning("SubscribeURL rejected", extra={"reason": str(exc)})
            raise HTTPException(status_code=403, detail="SubscribeURL invalid")
        asyncio.create_task(_confirm_subscription(subscribe_url))
        return {"status": "confirming"}

    if msg_type != "Notification":
        return {"status": "ignored"}

    # --- Hand off to the service ---------------------------------------------
    try:
        result = await webhook.process_notification(outer)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    payload: dict = {"status": result.status}
    if result.status == "ok":
        payload["suppressed"] = result.suppressed
    elif result.status == "ignored" and result.detail is not None:
        payload["type"] = result.detail
    return payload
