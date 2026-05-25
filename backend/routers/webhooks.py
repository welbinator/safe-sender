"""
Mailgun bounce/complaint webhook handler.

Mailgun POSTs to /webhooks/mailgun for:
  - failed (permanent) → hard bounce → suppress recipient
  - complained         → spam complaint → suppress recipient

Security:
  - HMAC-SHA256 signature verified via mailgun_validator.
  - Timestamp freshness + token replay protection enforced.
  - MAILGUN_WEBHOOK_SIGNING_KEY must be set in env.

Mailgun webhook payload structure:
  {
    "signature": {"timestamp": "...", "token": "...", "signature": "..."},
    "event-data": { "event": "failed"|"complained", "recipient": "...", ... }
  }
"""
from __future__ import annotations

import logging
import os

from fastapi import APIRouter, Depends, HTTPException, Request

from deps import get_webhook_service
from mailgun_validator import MailgunValidationError, verify_mailgun_webhook
from services.webhooks import MailgunWebhookService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/webhooks", tags=["webhooks"])

_SIGNING_KEY = os.environ.get("MAILGUN_WEBHOOK_SIGNING_KEY", "")


@router.post("/mailgun")
async def mailgun_webhook(
    request: Request,
    webhook: MailgunWebhookService = Depends(get_webhook_service),
):
    """Receive Mailgun bounce/complaint event notifications."""
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    sig = body.get("signature") or {}
    timestamp = sig.get("timestamp", "")
    token = sig.get("token", "")
    signature = sig.get("signature", "")

    try:
        verify_mailgun_webhook(
            timestamp=timestamp,
            token=token,
            signature=signature,
            signing_key=_SIGNING_KEY,
        )
    except MailgunValidationError as exc:
        logger.warning(
            "Mailgun webhook rejected",
            extra={"reason": str(exc)},
        )
        raise HTTPException(status_code=403, detail="Mailgun validation failed")

    event_data = body.get("event-data") or {}
    if not event_data:
        return {"status": "ignored", "detail": "no event-data"}

    result = await webhook.process_event(event_data)

    payload: dict = {"status": result.status}
    if result.status == "ok":
        payload["suppressed"] = result.suppressed
    elif result.status == "ignored" and result.detail is not None:
        payload["event"] = result.detail
    return payload
