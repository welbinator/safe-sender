"""
Email-dispatch service (Sprint C3 F-27, Mailgun rewrite).

Owns the *transport* concern for outbound emails: Mailgun HTTP API client,
retry config, structured logging, error swallowing. Templates live in
`services.email_templates`; this module just sends.

Previously used boto3/SES. AWS SES sandbox exit was rejected; all delivery
now goes through Mailgun HTTP API (api.mailgun.net/v3/{domain}/messages).
"""
from __future__ import annotations

import asyncio
import logging
import os

import httpx

from services.email_templates import render_welcome_email

logger = logging.getLogger(__name__)

MAILGUN_API_KEY = os.environ.get("MAILGUN_API_KEY", "")
MAILGUN_DOMAIN = os.environ.get("MAILGUN_DOMAIN", "mg.sendersafety.com")
FROM_EMAIL = os.environ.get("FROM_EMAIL", "noreply@sendersafety.com")

_MAILGUN_API_URL = f"https://api.mailgun.net/v3/{MAILGUN_DOMAIN}/messages"


def _send_email_sync(
    *,
    to_email: str,
    subject: str,
    body_text: str,
    body_html: str,
) -> None:
    """Blocking Mailgun send. Errors are logged with traceback and swallowed —
    callers schedule this off the request path so the user response is not
    coupled to Mailgun availability."""
    if not MAILGUN_API_KEY:
        logger.error(
            "email_send_skipped",
            extra={"reason": "MAILGUN_API_KEY not configured", "to_email": to_email},
        )
        return
    try:
        resp = httpx.post(
            _MAILGUN_API_URL,
            auth=("api", MAILGUN_API_KEY),
            data={
                "from": FROM_EMAIL,
                "to": to_email,
                "subject": subject,
                "text": body_text,
                "html": body_html,
            },
            timeout=15,
        )
        resp.raise_for_status()
        logger.info(
            "email_sent",
            extra={"to_email": to_email, "subject": subject, "status": resp.status_code},
        )
    except Exception as exc:  # noqa: BLE001
        # F-29: log full traceback so background failures aren't invisible.
        logger.exception(
            "email_send_failed",
            extra={"to_email": to_email, "subject": subject, "error": str(exc)},
        )


async def send_welcome_email(to_email: str, name: str, domain: str) -> None:
    """Async wrapper used as a FastAPI BackgroundTask."""
    subject, body_text, body_html = render_welcome_email(name=name, domain=domain)
    await asyncio.to_thread(
        _send_email_sync,
        to_email=to_email,
        subject=subject,
        body_text=body_text,
        body_html=body_html,
    )
